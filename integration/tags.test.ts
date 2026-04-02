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
import { getSession, setDisplayName, updateTags } from "@myobie/pty/client";
import { saveKnownHost } from "../src/relay/known-hosts.ts";
import { openSecretStore } from "../src/storage/bootstrap.ts";
import { parseToken } from "../src/crypto/token.ts";
import { spawnSync } from "node:child_process";
import * as path from "node:path";

let ctx: TestContext;
let originalSessionDir: string | undefined;

beforeEach(() => {
  ctx = createTestContext();
  originalSessionDir = process.env.PTY_SESSION_DIR;
  process.env.PTY_SESSION_DIR = ctx.stateDir;
});

afterEach(async () => {
  await destroyTestContext(ctx);
  if (originalSessionDir !== undefined) {
    process.env.PTY_SESSION_DIR = originalSessionDir;
  } else {
    delete process.env.PTY_SESSION_DIR;
  }
});

async function startRelayAndRegisterHost(
  relayConfigDir: string,
  port: number,
  extraServeArgs: string[] = [],
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
        "--auto-approve",
        ...extraServeArgs,
      ],
      { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
    )
  );

  await server.waitForText("Token URL", 15000);
  const baseToken = extractTokenUrl(server.screenshot());

  // Pre-populate the known-host store so `pty-relay ls` has a host to query.
  // The connect flow does this automatically; for a pure `ls` test we skip
  // connect and seed it directly.
  const { store } = await openSecretStore(relayConfigDir, { interactive: false });
  const parsed = parseToken(baseToken);
  await saveKnownHost(parsed.host, baseToken, store);

  return { server, baseToken };
}

function runLs(relayConfigDir: string, extraArgs: string[] = []): {
  stdout: string;
  stderr: string;
  exitCode: number;
} {
  const result = spawnSync(
    "node",
    [
      CLI_ENTRY,
      "ls",
      "--json",
      "--config-dir",
      relayConfigDir,
      ...extraArgs,
    ],
    {
      encoding: "utf-8",
      timeout: 20000,
      env: {
        ...process.env,
        PTY_SESSION_DIR: ctx.stateDir,
      },
    }
  );
  return {
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    exitCode: result.status ?? 1,
  };
}

describe("displayName in pty-relay ls", () => {
  it("--json propagates displayName when set on the session", async () => {
    const port = getPort();
    const ptySession = await Session.server("bash", [], { rows: 24, cols: 80 });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);
    setDisplayName(ptySession.name, "my-scratch-shell");

    const relayConfigDir = path.join(ctx.stateDir, "relay");
    await startRelayAndRegisterHost(relayConfigDir, port);

    const { stdout, exitCode } = runLs(relayConfigDir);
    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout);
    const matched = parsed[0].sessions.find(
      (s: { name: string }) => s.name === ptySession.name
    );
    expect(matched.displayName).toBe("my-scratch-shell");
  }, 60000);

  it("--json omits displayName for sessions without one (like --no-display-name remote spawns)", async () => {
    const port = getPort();
    const ptySession = await Session.server("bash", [], { rows: 24, cols: 80 });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);
    // Do NOT call setDisplayName — Session.server auto-generates one by
    // default, so we have to clear it explicitly to simulate the remote
    // --no-display-name path.
    setDisplayName(ptySession.name, null);

    const relayConfigDir = path.join(ctx.stateDir, "relay");
    await startRelayAndRegisterHost(relayConfigDir, port);

    const { stdout, exitCode } = runLs(relayConfigDir);
    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout);
    const matched = parsed[0].sessions.find(
      (s: { name: string }) => s.name === ptySession.name
    );
    expect(matched.displayName).toBeUndefined();
  }, 60000);

  it("non-JSON output leads with displayName and shows (name) dimmed", async () => {
    const port = getPort();
    const ptySession = await Session.server("bash", [], { rows: 24, cols: 80 });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);
    setDisplayName(ptySession.name, "pretty-name");

    const relayConfigDir = path.join(ctx.stateDir, "relay");
    await startRelayAndRegisterHost(relayConfigDir, port);

    // Run ls without --json and strip ANSI for content assertions.
    const raw = spawnSync(
      "node",
      ["--experimental-strip-types", "--no-warnings", CLI_ENTRY, "ls", "--config-dir", relayConfigDir],
      { encoding: "utf-8", timeout: 20000, env: { ...process.env, PTY_SESSION_DIR: ctx.stateDir } }
    );
    expect(raw.status).toBe(0);
    // eslint-disable-next-line no-control-regex
    const plain = (raw.stdout || "").replace(/\x1b\[[0-9;]*m/g, "");
    // `<displayName> (<name>)` appears on the same line.
    expect(plain).toMatch(new RegExp(`pretty-name\\s+\\(${ptySession.name}\\)`));
  }, 60000);
});

describe("tags in pty-relay ls --json", () => {
  it("includes tags from tagged pty sessions in the JSON output", async () => {
    const port = getPort();

    const ptySession = await Session.server("bash", [], { rows: 24, cols: 80 });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    updateTags(ptySession.name, { project: "boom", role: "agent" });

    const relayConfigDir = path.join(ctx.stateDir, "relay");
    await startRelayAndRegisterHost(relayConfigDir, port);

    const { stdout, exitCode } = runLs(relayConfigDir);
    expect(exitCode).toBe(0);

    const parsed = JSON.parse(stdout);
    expect(parsed).toHaveLength(1);
    const sessions = parsed[0].sessions;
    const matched = sessions.find((s: { name: string }) => s.name === ptySession.name);
    expect(matched).toBeDefined();
    expect(matched.tags).toEqual({ project: "boom", role: "agent" });
  }, 60000);

  it("omits the tags field entirely for sessions without tags", async () => {
    const port = getPort();

    const ptySession = await Session.server("bash", [], { rows: 24, cols: 80 });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    const relayConfigDir = path.join(ctx.stateDir, "relay");
    await startRelayAndRegisterHost(relayConfigDir, port);

    const { stdout, exitCode } = runLs(relayConfigDir);
    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout);
    const matched = parsed[0].sessions.find(
      (s: { name: string }) => s.name === ptySession.name
    );
    expect(matched).toBeDefined();
    expect(matched.tags).toBeUndefined();
  }, 60000);
});

describe("--filter-tag", () => {
  it("returns only sessions that match all filter pairs", async () => {
    const port = getPort();

    const agent = await Session.server("bash", [], { rows: 24, cols: 80 });
    track(ctx, agent);
    await agent.attach();
    await agent.waitForText("$", 5000);
    updateTags(agent.name, { role: "agent", project: "boom" });

    const server = await Session.server("bash", [], { rows: 24, cols: 80 });
    track(ctx, server);
    await server.attach();
    await server.waitForText("$", 5000);
    updateTags(server.name, { role: "server", project: "boom" });

    const untagged = await Session.server("bash", [], { rows: 24, cols: 80 });
    track(ctx, untagged);
    await untagged.attach();
    await untagged.waitForText("$", 5000);

    const relayConfigDir = path.join(ctx.stateDir, "relay");
    await startRelayAndRegisterHost(relayConfigDir, port);

    const { stdout, exitCode } = runLs(relayConfigDir, [
      "--filter-tag",
      "role=agent",
    ]);
    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout);
    const names = parsed[0].sessions.map((s: { name: string }) => s.name);
    expect(names).toContain(agent.name);
    expect(names).not.toContain(server.name);
    expect(names).not.toContain(untagged.name);
  }, 60000);

  it("returns nothing when filter is repeated and sessions match only one pair", async () => {
    const port = getPort();

    const onlyRole = await Session.server("bash", [], { rows: 24, cols: 80 });
    track(ctx, onlyRole);
    await onlyRole.attach();
    await onlyRole.waitForText("$", 5000);
    updateTags(onlyRole.name, { role: "agent" });

    const relayConfigDir = path.join(ctx.stateDir, "relay");
    await startRelayAndRegisterHost(relayConfigDir, port);

    const { stdout, exitCode } = runLs(relayConfigDir, [
      "--filter-tag",
      "role=agent",
      "--filter-tag",
      "project=boom",
    ]);
    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout);
    const names = parsed[0].sessions.map((s: { name: string }) => s.name);
    expect(names).not.toContain(onlyRole.name);
  }, 60000);
});

describe("connect --spawn --tag", () => {
  it("tags the spawned remote session with every --tag pair", async () => {
    const port = getPort();

    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const { baseToken } = await startRelayAndRegisterHost(relayConfigDir, port, [
      "--allow-new-sessions",
      "--skip-allow-new-sessions-confirmation",
    ]);

    const sessionName = `spawn-tags-${Date.now()}`;
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
          "--tag",
          "project=boom",
          "--tag",
          "role=agent",
        ],
        { rows: 24, cols: 80, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    // Wait for the shell prompt so we know the spawn completed and the
    // daemon has written session metadata to disk.
    await client.waitForText("$", 30000);

    const info = await getSession(sessionName);
    expect(info).not.toBeNull();
    expect(info!.metadata?.tags).toMatchObject({
      project: "boom",
      role: "agent",
    });
  }, 60000);
});
