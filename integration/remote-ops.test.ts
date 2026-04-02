import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  CLI_ENTRY,
  createTestContext,
  destroyTestContext,
  getPort,
  type TestContext,
} from "./helpers/index.ts";
import { getSession, updateTags } from "@myobie/pty/client";
import { saveKnownHost } from "../src/relay/known-hosts.ts";
import { openSecretStore } from "../src/storage/bootstrap.ts";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import * as path from "node:path";

// Tests in this file spawn pty sessions via the external `pty` CLI rather
// than Session.server from @myobie/pty/testing. Session.server runs a pty
// server in-process, which interacts in subtle ways with a pty-relay daemon
// that tries to peek into it via Unix socket — a situation that never
// arises in production, since the pty daemon is always a separate process.
// Using `pty run -d` keeps the test topology identical to real use.

let ctx: TestContext;
let originalSessionDir: string | undefined;
let runningServers: ChildProcess[] = [];
let spawnedSessions: string[] = [];

beforeEach(() => {
  ctx = createTestContext();
  originalSessionDir = process.env.PTY_SESSION_DIR;
  process.env.PTY_SESSION_DIR = ctx.stateDir;
  runningServers = [];
  spawnedSessions = [];
});

afterEach(async () => {
  for (const name of spawnedSessions) {
    spawnSync("pty", ["kill", name], {
      env: { ...process.env, PTY_SESSION_DIR: ctx.stateDir },
    });
  }
  spawnedSessions = [];
  for (const srv of runningServers) {
    srv.kill("SIGTERM");
  }
  runningServers = [];
  await destroyTestContext(ctx);
  if (originalSessionDir !== undefined) {
    process.env.PTY_SESSION_DIR = originalSessionDir;
  } else {
    delete process.env.PTY_SESSION_DIR;
  }
});

async function startRelayAndSeedHost(
  relayConfigDir: string,
  port: number,
  hostLabel: string
): Promise<{ server: ChildProcess; baseToken: string }> {
  let buffer = "";
  const server = spawn(
    "node",
    [
      CLI_ENTRY,
      "serve",
      String(port),
      "--config-dir",
      relayConfigDir,
      "--auto-approve",
    ],
    {
      env: { ...process.env, PTY_SESSION_DIR: ctx.stateDir },
      stdio: ["ignore", "pipe", "pipe"],
    }
  );
  runningServers.push(server);
  server.stdout!.setEncoding("utf-8");
  server.stderr!.setEncoding("utf-8");
  server.stdout!.on("data", (d: string) => { buffer += d; });
  server.stderr!.on("data", (d: string) => { buffer += d; });

  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (buffer.includes("Primary control connection established.")) break;
    await new Promise((r) => setTimeout(r, 50));
  }
  if (!buffer.includes("Primary control connection established.")) {
    throw new Error(`Relay did not become ready in 20s. Log:\n${buffer}`);
  }
  const tokenMatch = buffer.match(/Token URL:\s*(\S+)/);
  if (!tokenMatch) throw new Error(`No Token URL line in:\n${buffer}`);
  const baseToken = tokenMatch[1];

  const { store } = await openSecretStore(relayConfigDir, { interactive: false });
  await saveKnownHost(hostLabel, baseToken, store);

  return { server, baseToken };
}

/** Spawn a real pty session via `pty run -d` and track for cleanup. */
function spawnPtySession(name: string): void {
  const result = spawnSync(
    "pty",
    ["run", "-d", "--name", name, "--", "bash"],
    { encoding: "utf-8", env: { ...process.env, PTY_SESSION_DIR: ctx.stateDir } }
  );
  if (result.status !== 0) {
    throw new Error(`pty run failed: ${result.stderr}`);
  }
  spawnedSessions.push(name);
}

/** Run `pty send` on a session so its screen has something to peek at. */
function driveSession(name: string, line: string): void {
  spawnSync(
    "pty",
    ["send", name, line],
    { env: { ...process.env, PTY_SESSION_DIR: ctx.stateDir } }
  );
  spawnSync(
    "pty",
    ["send", name, "--seq", "key:return"],
    { env: { ...process.env, PTY_SESSION_DIR: ctx.stateDir } }
  );
}

function runCli(args: string[]): {
  stdout: string;
  stderr: string;
  exitCode: number;
} {
  const result = spawnSync("node", [CLI_ENTRY, ...args], {
    encoding: "utf-8",
    timeout: 30000,
    env: { ...process.env, PTY_SESSION_DIR: ctx.stateDir },
  });
  return {
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    exitCode: result.status ?? 1,
  };
}

describe("peek", () => {
  it("returns the current screen of a remote session", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    await startRelayAndSeedHost(relayConfigDir, port, host);

    const sessionName = `peek-${Date.now()}`;
    spawnPtySession(sessionName);
    driveSession(sessionName, "echo peek-marker-alpha");
    await new Promise((r) => setTimeout(r, 400));

    const { stdout, exitCode, stderr } = runCli([
      "peek", "--plain",
      "--config-dir", relayConfigDir,
      host, sessionName,
    ]);
    expect(exitCode, `stderr: ${stderr}`).toBe(0);
    expect(stdout).toContain("peek-marker-alpha");
  }, 60000);

  it("--wait polls until the pattern appears", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    await startRelayAndSeedHost(relayConfigDir, port, host);

    const sessionName = `peek-wait-${Date.now()}`;
    spawnPtySession(sessionName);

    // Schedule a delayed send IN A CHILD PROCESS. The test process is about
    // to block in spawnSync(peek), so any setTimeout in-process would never
    // fire. A background shell runs in parallel and drives the session after
    // the peek command has had time to start polling.
    const driver = spawn(
      "sh",
      [
        "-c",
        `sleep 0.8 && pty send ${sessionName} 'echo DELAYED-MARKER' && pty send ${sessionName} --seq key:return`,
      ],
      {
        env: { ...process.env, PTY_SESSION_DIR: ctx.stateDir },
        stdio: "ignore",
      }
    );
    runningServers.push(driver);

    const { stdout, exitCode, stderr } = runCli([
      "peek", "--plain",
      "--wait", "DELAYED-MARKER",
      "-t", "10",
      "--config-dir", relayConfigDir,
      host, sessionName,
    ]);
    expect(exitCode, `stderr: ${stderr}`).toBe(0);
    expect(stdout).toContain("DELAYED-MARKER");
  }, 60000);

  it("--wait exits non-zero with a timeout error", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    await startRelayAndSeedHost(relayConfigDir, port, host);

    const sessionName = `peek-timeout-${Date.now()}`;
    spawnPtySession(sessionName);

    const { stderr, exitCode } = runCli([
      "peek", "--plain",
      "--wait", "never-going-to-appear",
      "-t", "1",
      "--config-dir", relayConfigDir,
      host, sessionName,
    ]);
    expect(exitCode).not.toBe(0);
    expect(stderr.toLowerCase()).toContain("timed out");
  }, 60000);
});

describe("send", () => {
  it("delivers text to a remote session", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    await startRelayAndSeedHost(relayConfigDir, port, host);

    const sessionName = `send-${Date.now()}`;
    spawnPtySession(sessionName);

    // `--seq text` + `--seq key:return` mirrors what a user types to make
    // the shell actually execute a line.
    const { exitCode, stderr } = runCli([
      "send",
      "--config-dir", relayConfigDir,
      host, sessionName,
      "--seq", "echo hello-from-send",
      "--seq", "key:return",
    ]);
    expect(exitCode, `stderr: ${stderr}`).toBe(0);

    // Give the shell time to render, then peek to verify the text arrived.
    await new Promise((r) => setTimeout(r, 500));
    const peek = runCli([
      "peek", "--plain",
      "--config-dir", relayConfigDir,
      host, sessionName,
    ]);
    expect(peek.stdout).toContain("hello-from-send");
  }, 60000);
});

describe("tag", () => {
  it("shows tags on a remote session", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    await startRelayAndSeedHost(relayConfigDir, port, host);

    const sessionName = `tag-show-${Date.now()}`;
    spawnPtySession(sessionName);
    updateTags(sessionName, { role: "agent", project: "boom" });

    const { stdout, exitCode } = runCli([
      "tag",
      "--config-dir", relayConfigDir,
      host, sessionName,
    ]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("#role=agent");
    expect(stdout).toContain("#project=boom");
  }, 60000);

  it("sets tags and echoes the resulting tag set", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    await startRelayAndSeedHost(relayConfigDir, port, host);

    const sessionName = `tag-set-${Date.now()}`;
    spawnPtySession(sessionName);

    const { stdout, exitCode } = runCli([
      "tag",
      "--config-dir", relayConfigDir,
      host, sessionName,
      "owner=me",
      "status=alive",
    ]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("#owner=me");
    expect(stdout).toContain("#status=alive");

    const info = await getSession(sessionName);
    expect(info!.metadata?.tags).toMatchObject({ owner: "me", status: "alive" });
  }, 60000);

  it("--rm removes a tag", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    await startRelayAndSeedHost(relayConfigDir, port, host);

    const sessionName = `tag-rm-${Date.now()}`;
    spawnPtySession(sessionName);
    updateTags(sessionName, { role: "agent", temp: "yes" });

    const { exitCode } = runCli([
      "tag",
      "--config-dir", relayConfigDir,
      host, sessionName,
      "--rm", "temp",
    ]);
    expect(exitCode).toBe(0);
    const info = await getSession(sessionName);
    expect(info!.metadata?.tags).toMatchObject({ role: "agent" });
    expect(info!.metadata?.tags).not.toHaveProperty("temp");
  }, 60000);

  it("refuses to let a remote tag() set reserved keys", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    await startRelayAndSeedHost(relayConfigDir, port, host);

    const sessionName = `tag-reserved-${Date.now()}`;
    spawnPtySession(sessionName);

    const { stdout, exitCode } = runCli([
      "tag",
      "--config-dir", relayConfigDir,
      host, sessionName,
      // Reserved: pty's supervisor reads these and a remote must not be
      // able to promote a session into a supervisor-managed persistent one.
      "strategy=permanent",
      "ptyfile=/tmp/malicious.toml",
      "project=legit",
    ]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("#project=legit");
    expect(stdout).not.toContain("strategy=");
    expect(stdout).not.toContain("ptyfile=");

    const info = await getSession(sessionName);
    expect(info!.metadata?.tags).not.toHaveProperty("strategy");
    expect(info!.metadata?.tags).not.toHaveProperty("ptyfile");
    expect(info!.metadata?.tags?.project).toBe("legit");
  }, 60000);

  it("--json outputs tags as JSON", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    await startRelayAndSeedHost(relayConfigDir, port, host);

    const sessionName = `tag-json-${Date.now()}`;
    spawnPtySession(sessionName);
    updateTags(sessionName, { a: "1", b: "two" });

    const { stdout, exitCode } = runCli([
      "tag", "--json",
      "--config-dir", relayConfigDir,
      host, sessionName,
    ]);
    expect(exitCode).toBe(0);
    const parsed = JSON.parse(stdout);
    expect(parsed).toEqual({ a: "1", b: "two" });
  }, 60000);
});
