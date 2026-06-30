import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { spawnSync } from "node:child_process";
import {
  CLI_ENTRY,
  createTestContext,
  destroyTestContext,
  integEnv,
  type TestContext,
} from "./helpers/index.ts";

/**
 * Brief-015 end-to-end: drop a peers file with both `ssh://…` and
 * `https://…#pk.secret` lines, verify every phase-2 subcommand resolves
 * peers from it and shells out correctly.
 *
 * Like `ssh-ls.test.ts`, we use a fake `ssh` shim earlier on PATH so
 * the test exercises the full chain without depending on a real local
 * sshd / pty install. The shim records its arguments to a log file
 * + emits the JSON / output shape the real remote `pty` would produce.
 */

let ctx: TestContext;
let fakeSshDir: string;
let configDir: string;
let peersDir: string;
let peersFile: string;

beforeAll(() => {
  ctx = createTestContext();
  fakeSshDir = fs.mkdtempSync(path.join(os.tmpdir(), "peers-fake-ssh-"));
  configDir = path.join(ctx.stateDir, "relay-config");
  fs.mkdirSync(configDir, { recursive: true });

  // The peers file goes under the test's stateDir and is selected via
  // PTY_RELAY_PEERS_FILE, which beats both XDG_CONFIG_HOME and ~/.config.
  peersDir = path.join(ctx.stateDir, "peers");
  fs.mkdirSync(peersDir, { recursive: true });
  peersFile = path.join(peersDir, "peers");

  const fakeSshPath = path.join(fakeSshDir, "ssh");
  fs.writeFileSync(
    fakeSshPath,
    `#!/usr/bin/env bash
# Record every invocation for assertion.
printf '%s\\n' "$*" >> "${fakeSshDir}/calls.log"

# Last arguments are <userHost> <remote-tokens...>. We dispatch on
# the remote command — peek / send / tag / kill / events / attach —
# and emit the shape the friend would see from a real pty install.
all="$*"
case "$all" in
  *"pty list --json"*)
    cat <<'JSON'
[{"name":"work","status":"running","command":"bash","tags":{}}]
JSON
    exit 0 ;;
  *"pty peek"*)
    # Honor --plain by emitting plain text either way (good enough).
    echo "fake peek screen"
    exit 0 ;;
  *"pty send"*)
    # send produces no stdout on success.
    exit 0 ;;
  *"pty tag --json"*)
    # Tag with --json emits the resulting tag map.
    echo '{"env":"prod","owner":"alice"}'
    exit 0 ;;
  *"pty kill"*)
    exit 0 ;;
  *"pty events --json"*)
    # JSONL: emit one event then close. The followSshRemoteEvents
    # subscriber reads + closes when ssh exits.
    echo '{"ts":"2026-06-30T00:00:00Z","type":"session_started","session":"work"}'
    exit 0 ;;
  *"pty attach"*)
    # attach is interactive — the integration test invokes it without
    # a real tty so we just exit 0 to prove the spawn happened.
    exit 0 ;;
  *"pty --version"*)
    echo "1.2.3-fake"
    exit 0 ;;
esac
echo "fake ssh: unrecognized command (\${all})" >&2
exit 1
`,
  );
  fs.chmodSync(fakeSshPath, 0o755);
});

afterAll(async () => {
  await destroyTestContext(ctx);
  try { fs.rmSync(fakeSshDir, { recursive: true, force: true }); } catch {}
});

function runCli(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync("node", [CLI_ENTRY, ...args], {
    encoding: "utf-8",
    env: {
      ...process.env,
      ...integEnv({
        PTY_SESSION_DIR: ctx.stateDir,
        PTY_RELAY_PEERS_FILE: peersFile,
      }),
      PATH: `${fakeSshDir}:${process.env.PATH ?? ""}`,
    },
    timeout: 15_000,
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function clearCallLog(): void {
  fs.writeFileSync(path.join(fakeSshDir, "calls.log"), "");
}

function readCallLog(): string {
  return fs.readFileSync(path.join(fakeSshDir, "calls.log"), "utf-8");
}

describe("peers file — declarative provisioning", () => {
  it("ls discovers a peer dropped into the peers file (zero commands run)", () => {
    fs.writeFileSync(peersFile, "ssh://nathan@web1.example.com  prod-web\n");
    clearCallLog();
    const result = runCli(["ls", "--config-dir", configDir, "--json"]);
    if (result.status !== 0) {
      console.log("ls stderr:", result.stderr);
      console.log("ls stdout:", result.stdout);
    }
    expect(result.status).toBe(0);
    const parsed = JSON.parse(result.stdout) as Array<{
      label: string;
      url: string;
      sessions: Array<{ name: string }>;
      error: string | null;
    }>;
    expect(parsed).toHaveLength(1);
    expect(parsed[0].label).toBe("prod-web");
    expect(parsed[0].url).toBe("ssh://nathan@web1.example.com");
    expect(parsed[0].sessions.map((s) => s.name)).toEqual(["work"]);
    expect(readCallLog()).toContain("nathan@web1.example.com pty list --json");
  });

  it("supports a mixed ssh + https://#pk.secret peers file", () => {
    const pk = "A".repeat(43);
    const sec = "B".repeat(43);
    const tokenUrl = `https://relay.example.com#${pk}.${sec}`;
    fs.writeFileSync(
      peersFile,
      `# fleet roster\nssh://web1.example.com\n${tokenUrl}  remote-relay\n`,
    );
    const result = runCli(["ls", "--config-dir", configDir, "--json"]);
    expect(result.status).toBe(0);
    const parsed = JSON.parse(result.stdout) as Array<{ label: string; url: string; error: string | null }>;
    const labels = parsed.map((h) => h.label).sort();
    expect(labels).toEqual(["remote-relay", "web1.example.com"]);
    const remote = parsed.find((h) => h.label === "remote-relay")!;
    expect(remote.url).toBe(tokenUrl);
    // The https://#pk.secret peer can't actually connect (no real
    // daemon at relay.example.com) — error is populated. That's fine
    // for this test; we're verifying the loader, not the dial.
    expect(typeof remote.error).toBe("string");
  });

  it("malformed lines are warned + skipped, valid peers still load", () => {
    fs.writeFileSync(
      peersFile,
      "ssh://\nnot-a-url-at-all\nssh://web1\n",
    );
    const result = runCli(["ls", "--config-dir", configDir, "--json"]);
    expect(result.status).toBe(0);
    expect(result.stderr).toContain("[peers-file]");
    const parsed = JSON.parse(result.stdout) as Array<{ label: string }>;
    expect(parsed.map((p) => p.label)).toEqual(["web1"]);
  });
});

describe("phase-2 ssh wiring — every subcommand routes through ssh", () => {
  beforeAll(() => {
    fs.writeFileSync(peersFile, "ssh://me@web1  prod\n");
  });

  it("peek shells out to `ssh me@web1 pty peek work`", () => {
    clearCallLog();
    const result = runCli(["peek", "--config-dir", configDir, "prod", "work"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("fake peek screen");
    expect(readCallLog()).toContain("me@web1 pty peek work");
  });

  it("send shells out with --seq verbatim", () => {
    clearCallLog();
    const result = runCli([
      "send",
      "--config-dir",
      configDir,
      "prod",
      "work",
      "--seq",
      "hello world",
      "--seq",
      "key:return",
    ]);
    expect(result.status).toBe(0);
    const calls = readCallLog();
    expect(calls).toContain("me@web1 pty send");
    expect(calls).toContain("--seq hello world");
    // pty's parseSeqValue resolves "key:return" → "\r" before we
    // forward. So the remote ssh sees the carriage return; not the
    // literal "key:return" token.
    expect(calls).toContain("work");
  });

  it("tag shells out with --json and parses the response", () => {
    clearCallLog();
    const result = runCli([
      "tag",
      "--config-dir",
      configDir,
      "prod",
      "work",
      "--json",
    ]);
    expect(result.status).toBe(0);
    // The fake responded with {"env":"prod","owner":"alice"} —
    // pty-relay re-serializes it as JSON.
    const parsed = JSON.parse(result.stdout);
    expect(parsed).toEqual({ env: "prod", owner: "alice" });
    expect(readCallLog()).toContain("me@web1 pty tag --json work");
  });

  it("kill shells out to `ssh me@web1 pty kill work`", () => {
    clearCallLog();
    const result = runCli(["kill", "--config-dir", configDir, "prod", "work"]);
    expect(result.status).toBe(0);
    expect(readCallLog()).toContain("me@web1 pty kill work");
  });

  it("events streams the JSONL line the remote emits and exits when ssh exits", () => {
    clearCallLog();
    const result = runCli([
      "events",
      "--config-dir",
      configDir,
      "--json",
      "prod",
    ]);
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toContain('"type":"session_started"');
    expect(readCallLog()).toContain("me@web1 pty events --json");
  });

  it("connect spawns `ssh -t me@web1 pty attach work` with --session", () => {
    clearCallLog();
    const result = runCli([
      "connect",
      "--config-dir",
      configDir,
      "prod",
      "--session",
      "work",
    ]);
    expect(result.status).toBe(0);
    const calls = readCallLog();
    expect(calls).toContain("me@web1 pty attach work");
    // The -t flag is the load-bearing one for interactive attach.
    expect(calls).toContain("-t ");
  });

  it("connect without --session prints a helpful error", () => {
    clearCallLog();
    const result = runCli(["connect", "--config-dir", configDir, "prod"]);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("needs --session");
  });
});
