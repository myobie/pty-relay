import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  CLI_ENTRY,
  Session,
  createTestContext,
  destroyTestContext,
  extractTokenUrl,
  track,
  getPort,
  type TestContext,
} from "./helpers/index.ts";
import { getSession } from "@myobie/pty/client";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

let ctx: TestContext;
let originalSessionDir: string | undefined;
let originalHome: string | undefined;

beforeEach(() => {
  ctx = createTestContext();
  originalSessionDir = process.env.PTY_SESSION_DIR;
  originalHome = process.env.HOME;
  process.env.PTY_SESSION_DIR = ctx.stateDir;
});

afterEach(async () => {
  await destroyTestContext(ctx);
  if (originalSessionDir !== undefined) {
    process.env.PTY_SESSION_DIR = originalSessionDir;
  } else {
    delete process.env.PTY_SESSION_DIR;
  }
  if (originalHome !== undefined) {
    process.env.HOME = originalHome;
  } else {
    delete process.env.HOME;
  }
});

async function startServerWithSpawn(
  relayConfigDir: string,
  port: number,
  extraEnv: Record<string, string> = {}
): Promise<{ server: Session; baseToken: string }> {
  const server = track(
    ctx,
    Session.spawn(
      "node",
      [
        CLI_ENTRY,
        "serve",
        String(port),
        "--config-dir",
        relayConfigDir,
        "--allow-new-sessions",
        "--skip-allow-new-sessions-confirmation",
        "--auto-approve",
      ],
      {
        rows: 24,
        cols: 200,
        env: { PTY_SESSION_DIR: ctx.stateDir, ...extraEnv },
      }
    )
  );
  await server.waitForText("Token URL", 15000);
  const baseToken = extractTokenUrl(server.screenshot());
  return { server, baseToken };
}

describe("--isolate-env is passed to pty run on remote spawn", () => {
  it("spawned remote session does not see a secret from the operator's env", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    // Inject a sentinel secret into the daemon's environment. Without
    // --isolate-env on the pty run argv, this would propagate down to the
    // spawned shell and be visible to the remote client.
    const SECRET = "S3CRET-" + Math.random().toString(36).slice(2);
    const { baseToken } = await startServerWithSpawn(relayConfigDir, port, {
      PTY_RELAY_AUDIT_SECRET: SECRET,
    });

    const sessionName = `iso-${Date.now()}`;
    const client = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "connect",
          baseToken,
          "--config-dir",
          relayConfigDir,
          "--spawn",
          sessionName,
        ],
        { rows: 24, cols: 80, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await client.waitForText("$", 30000);
    // A distinctive sentinel in the OUTPUT (not in the command we typed)
    // lets us find the result line even though xterm echoes stdin back.
    client.sendKeys(`echo "RESULT[${SECRET.length}]:${"$"}PTY_RELAY_AUDIT_SECRET:END"\n`);
    await client.waitForText("RESULT[", 8000);
    // Wait for the :END so we know the full line was rendered.
    await client.waitForText(":END", 3000);

    const screen = client.screenshot();
    const joined = screen.lines.join("\n");
    // The sentinel must NOT have been inherited into the remote shell.
    expect(joined).not.toContain(SECRET);
    // On the output line, the variable expanded to empty → "RESULT[N]::END"
    // (two colons, nothing in between). Scan all lines for one that matches
    // this shape — the command-echo line contains `"$PTY_RELAY_AUDIT_SECRET"`
    // which won't match this pattern.
    const outputLine = screen.lines.find((l) => /RESULT\[\d+\]::END/.test(l));
    expect(outputLine, `no RESULT[N]::END line in:\n${joined}`).toBeDefined();
  }, 60000);
});

describe("remote spawn default shape", () => {
  // Matches pty's new TUI default: Enter creates a bare shell with no
  // displayName, using the remote's $SHELL in the remote's HOME. No
  // --cwd or command from the client.
  it("spawns with no displayName and the daemon's $SHELL in $HOME", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    // Pin HOME + SHELL on the server side so we can assert on what the
    // daemon chose; in real usage these come from the operator's env.
    const fakeHome = fs.mkdtempSync(path.join("/tmp", "home-spawn-"));
    const { baseToken } = await startServerWithSpawn(relayConfigDir, port, {
      HOME: fakeHome,
      SHELL: "/bin/bash",
    });

    const sessionName = `bare-${Date.now()}`;
    const client = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "connect",
          baseToken,
          "--config-dir", relayConfigDir,
          "--spawn", sessionName,
          // Deliberately NO --cwd and NO command — the client just hits Enter.
        ],
        { rows: 24, cols: 80, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await client.waitForText("$", 30000);

    const info = await getSession(sessionName);
    expect(info).not.toBeNull();
    // --no-display-name was propagated — the session has no displayName.
    expect(info!.metadata?.displayName).toBeUndefined();
    // Remote's SHELL was used.
    expect(info!.metadata?.command).toBe("/bin/bash");
    // Remote's HOME was used (realpath because macOS maps /tmp → /private/tmp).
    const resolvedHome = fs.realpathSync(fakeHome);
    expect(info!.metadata?.cwd).toBe(resolvedHome);

    fs.rmSync(fakeHome, { recursive: true, force: true });
  }, 60000);
});

describe("reserved tag keys are dropped on remote spawn", () => {
  it("drops strategy / ptyfile / supervisor.status tags from remote input", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const { baseToken } = await startServerWithSpawn(relayConfigDir, port);

    const sessionName = `reserved-tags-${Date.now()}`;
    const client = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "connect",
          baseToken,
          "--config-dir",
          relayConfigDir,
          "--spawn",
          sessionName,
          "--tag", "strategy=permanent",
          "--tag", "supervisor.status=managed",
          "--tag", "ptyfile=/tmp/malicious.toml",
          "--tag", "ptyfile.session=victim",
          "--tag", "project=fine",
        ],
        { rows: 24, cols: 80, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await client.waitForText("$", 30000);

    const info = await getSession(sessionName);
    expect(info).not.toBeNull();
    const tags = info!.metadata?.tags ?? {};
    // Reserved keys must be absent — the relay stripped them before invoking pty run.
    expect(tags).not.toHaveProperty("strategy");
    expect(tags).not.toHaveProperty("supervisor.status");
    expect(tags).not.toHaveProperty("ptyfile");
    expect(tags).not.toHaveProperty("ptyfile.session");
    // Non-reserved user tags still flow through.
    expect(tags.project).toBe("fine");
  }, 60000);
});

describe("spawn cwd containment to $HOME", () => {
  it("rejects a cwd that resolves outside HOME", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");

    // Put HOME somewhere specific so /etc is unambiguously outside it.
    const fakeHome = fs.mkdtempSync(path.join("/tmp", "home-"));
    const { baseToken } = await startServerWithSpawn(relayConfigDir, port, {
      HOME: fakeHome,
    });

    const sessionName = `outside-home-${Date.now()}`;
    const client = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "connect",
          baseToken,
          "--config-dir",
          relayConfigDir,
          "--spawn",
          sessionName,
          "--cwd",
          "/etc",
        ],
        { rows: 24, cols: 80, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    // The daemon's error message should appear before any shell prompt.
    await client.waitForText("cwd must be inside", 15000);

    // And no session should have been created.
    const info = await getSession(sessionName);
    expect(info).toBeNull();

    fs.rmSync(fakeHome, { recursive: true, force: true });
  }, 60000);

  it("accepts a cwd that is a subdirectory of HOME", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");

    const fakeHome = fs.mkdtempSync(path.join("/tmp", "home-ok-"));
    const subDir = path.join(fakeHome, "work");
    fs.mkdirSync(subDir);
    const { baseToken } = await startServerWithSpawn(relayConfigDir, port, {
      HOME: fakeHome,
    });

    const sessionName = `inside-home-${Date.now()}`;
    const client = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "connect",
          baseToken,
          "--config-dir",
          relayConfigDir,
          "--spawn",
          sessionName,
          "--cwd",
          subDir,
        ],
        { rows: 24, cols: 80, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await client.waitForText("$", 30000);
    client.sendKeys("pwd\n");
    // realpath normalizes /tmp → /private/tmp on macOS, so match the leaf name.
    await client.waitForText("work", 5000);

    fs.rmSync(fakeHome, { recursive: true, force: true });
  }, 60000);
});

// NOTE: an end-to-end integration test for the findTokenByExactId fix was
// attempted here but was flaky due to daemon-startup timing in non-auto-approve
// mode ("no daemon available" races). The fix is covered by:
//   • the findTokenByExactId unit test in test/security-fixes.test.ts, which
//     pins the "prefix does not match" behavior directly;
//   • grep of src/commands/serve.ts confirms every network-facing call site
//     uses findTokenByExactId and the prefix-matching findTokenById only
//     appears in the operator CLI (commands/clients.ts, tui/clients-tui.ts).
