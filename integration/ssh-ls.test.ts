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
import { openSecretStore } from "../src/storage/bootstrap.ts";
import { saveSshKnownHost } from "../src/relay/known-hosts.ts";

/**
 * Brief-010 phase 1: end-to-end check that `pty-relay ls <label>`
 * with an ssh:// host shells out to `ssh <userHost> pty list --json`
 * and renders the result alongside relay-hosted entries.
 *
 * We don't depend on a real local sshd. Instead we drop a fake `ssh`
 * script earlier on PATH that records its arguments + emits the
 * `pty list --json` shape we'd expect from a real peer. That tests
 * everything from CLI dispatch → host-resolve → transport-ssh.ts →
 * ls.ts rendering without the real sshd / host-key / firewall mess.
 */

let ctx: TestContext;
let fakeSshDir: string;

beforeAll(() => {
  ctx = createTestContext();
  fakeSshDir = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-ls-fake-"));

  // The fake `ssh` script accepts the same positional + -o args ssh
  // would, looks at argv to decide what to emit, and writes a marker
  // to a log file so the test can assert call shape. Bash because
  // it's universal on macOS + Linux CI.
  const fakeSshPath = path.join(fakeSshDir, "ssh");
  fs.writeFileSync(fakeSshPath, `#!/usr/bin/env bash
echo "$@" >> "${fakeSshDir}/calls.log"
# The last two args are <userHost> <remote-command-tokens...>
# We respond to "pty --version" and "pty list --json" specifically.
last_cmd="$*"
case "$last_cmd" in
  *"pty --version"*)
    echo "1.2.3-fake"
    exit 0
    ;;
  *"pty list --json"*)
    cat <<'JSON'
[
  {
    "name": "fake-session-1",
    "status": "running",
    "command": "bash",
    "tags": {}
  },
  {
    "name": "fake-session-2",
    "status": "running",
    "command": "/usr/bin/htop",
    "tags": {"role":"monitor"}
  }
]
JSON
    exit 0
    ;;
esac
echo "fake ssh: unrecognized command" >&2
exit 1
`);
  fs.chmodSync(fakeSshPath, 0o755);
});

afterAll(async () => {
  await destroyTestContext(ctx);
  try { fs.rmSync(fakeSshDir, { recursive: true, force: true }); } catch {}
});

describe("ssh:// transport — pty-relay ls", () => {
  it("ls renders ssh peer sessions returned by `pty list --json`", async () => {
    const configDir = path.join(ctx.stateDir, "ssh-ls-relay");
    fs.mkdirSync(configDir, { recursive: true });

    // Seed a known-host entry. The label is what we'll resolve via the
    // CLI; the sshUrl is what gets shell-outed.
    const { store } = await openSecretStore(configDir, {
      interactive: false,
      passphraseFile: undefined,
    });
    await saveSshKnownHost(
      { label: "fakebox", sshUrl: "ssh://me@fakebox" },
      store,
    );

    const result = spawnSync(
      "node",
      [CLI_ENTRY, "ls", "--config-dir", configDir, "--json"],
      {
        encoding: "utf-8",
        env: {
          ...process.env,
          ...integEnv({ PTY_SESSION_DIR: ctx.stateDir }),
          // Prepend the fake-ssh directory to PATH so our script wins
          // over the real ssh.
          PATH: `${fakeSshDir}:${process.env.PATH ?? ""}`,
        },
        timeout: 15_000,
      },
    );
    if (result.status !== 0) {
      console.log("ls stderr:", result.stderr);
      console.log("ls stdout:", result.stdout);
    }
    expect(result.status).toBe(0);
    const parsed = JSON.parse(result.stdout) as Array<{
      label: string;
      url: string;
      sessions: Array<{ name: string; command: string; tags?: Record<string, string> }>;
      error: string | null;
    }>;
    expect(parsed.length).toBe(1);
    expect(parsed[0].label).toBe("fakebox");
    expect(parsed[0].url).toBe("ssh://me@fakebox");
    expect(parsed[0].error).toBeNull();
    expect(parsed[0].sessions.map((s) => s.name)).toEqual([
      "fake-session-1",
      "fake-session-2",
    ]);
    expect(parsed[0].sessions[1].tags).toEqual({ role: "monitor" });

    // Assert the fake ssh was called with the right shape.
    const calls = fs.readFileSync(path.join(fakeSshDir, "calls.log"), "utf-8");
    expect(calls).toContain("me@fakebox pty list --json");
    // BatchMode=yes is the headless-friendly default.
    expect(calls).toContain("-o BatchMode=yes");
  }, 30_000);

  it("`pty-relay add ssh://…` probes via `pty --version` before saving", async () => {
    const configDir = path.join(ctx.stateDir, "ssh-add-relay");
    fs.mkdirSync(configDir, { recursive: true });

    // Clear the call log to keep this case isolated.
    fs.writeFileSync(path.join(fakeSshDir, "calls.log"), "");

    const result = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "add",
        "ssh://nathan@beta",
        "--label",
        "beta",
        "--config-dir",
        configDir,
      ],
      {
        encoding: "utf-8",
        env: {
          ...process.env,
          ...integEnv({ PTY_SESSION_DIR: ctx.stateDir }),
          PATH: `${fakeSshDir}:${process.env.PATH ?? ""}`,
        },
        timeout: 15_000,
      },
    );
    if (result.status !== 0) {
      console.log("add stderr:", result.stderr);
      console.log("add stdout:", result.stdout);
    }
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Added beta → ssh://nathan@beta");
    expect(result.stdout).toContain("ok (pty 1.2.3-fake)");

    // The probe used `pty --version`, not `pty list --json`.
    const calls = fs.readFileSync(path.join(fakeSshDir, "calls.log"), "utf-8");
    expect(calls).toContain("nathan@beta pty --version");

    // Now reading back via ls should see the new entry. We need the
    // fake to keep responding to `list --json` for the second
    // invocation, which it does.
    const ls = spawnSync(
      "node",
      [CLI_ENTRY, "ls", "--config-dir", configDir, "--json"],
      {
        encoding: "utf-8",
        env: {
          ...process.env,
          ...integEnv({ PTY_SESSION_DIR: ctx.stateDir }),
          PATH: `${fakeSshDir}:${process.env.PATH ?? ""}`,
        },
        timeout: 15_000,
      },
    );
    expect(ls.status).toBe(0);
    const parsed = JSON.parse(ls.stdout);
    expect(parsed[0].label).toBe("beta");
    expect(parsed[0].url).toBe("ssh://nathan@beta");
  }, 30_000);
});
