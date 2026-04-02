import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  CLI_ENTRY,
  createTestContext,
  destroyTestContext,
  getPort,
  type TestContext,
} from "./helpers/index.ts";
import { saveKnownHost } from "../src/relay/known-hosts.ts";
import { openSecretStore } from "../src/storage/bootstrap.ts";
import { subscribeRemoteEvents } from "../src/relay/events-client.ts";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import * as path from "node:path";

// These tests cover the pty-relay side of the events subscription end-to-end:
// WS connect, Noise handshake, snapshot delivery, stream teardown, and CLI
// wiring. The two earlier upstream flakes (watchFile-at-EOF race on new files,
// and session_exit lost on daemon shutdown) were fixed in pty and the
// session_start / session_exit tests below are reliable again.

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

async function startRelay(
  relayConfigDir: string,
  port: number,
  hostLabel: string
): Promise<{ baseToken: string }> {
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
    throw new Error(`Relay not ready in 20s:\n${buffer}`);
  }
  const tokenMatch = buffer.match(/Token URL:\s*(\S+)/);
  if (!tokenMatch) throw new Error(`No Token URL line in:\n${buffer}`);
  const baseToken = tokenMatch[1];

  const { store } = await openSecretStore(relayConfigDir, { interactive: false });
  await saveKnownHost(hostLabel, baseToken, store);

  return { baseToken };
}

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

function killPtySession(name: string): void {
  spawnSync("pty", ["kill", name], {
    env: { ...process.env, PTY_SESSION_DIR: ctx.stateDir },
  });
  spawnedSessions = spawnedSessions.filter((s) => s !== name);
}

async function waitFor(
  predicate: () => boolean,
  timeoutMs: number,
  label: string
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`timed out after ${timeoutMs}ms waiting for ${label}`);
}

describe("events subscription", () => {
  it("receives a snapshot of currently-running sessions on subscribe", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    const { baseToken } = await startRelay(relayConfigDir, port, host);

    spawnPtySession(`snap-a-${port}`);
    spawnPtySession(`snap-b-${port}`);

    let snapshot: { name: string }[] | null = null;
    const sub = subscribeRemoteEvents(baseToken, {
      onSnapshot: (sessions) => { snapshot = sessions; },
      onEvent: () => {},
    });
    try {
      await waitFor(() => snapshot !== null, 10000, "initial snapshot");
    } finally {
      sub.close();
    }

    const names = snapshot!.map((s) => s.name).sort();
    expect(names).toContain(`snap-a-${port}`);
    expect(names).toContain(`snap-b-${port}`);
  }, 60000);

  it("snapshot reflects tags from each session's metadata", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    const { baseToken } = await startRelay(relayConfigDir, port, host);

    const name = `tagged-${port}`;
    spawnPtySession(name);
    // Set tags AFTER spawn so the snapshot-read has the latest metadata.
    const { updateTags } = await import("@myobie/pty/client");
    updateTags(name, { role: "agent", project: "boom" });

    let snapshot: { name: string; tags?: Record<string, string> }[] | null = null;
    const sub = subscribeRemoteEvents(baseToken, {
      onSnapshot: (sessions) => { snapshot = sessions; },
      onEvent: () => {},
    });
    try {
      await waitFor(() => snapshot !== null, 10000, "snapshot");
    } finally {
      sub.close();
    }

    const row = snapshot!.find((s) => s.name === name);
    expect(row).toBeDefined();
    expect(row!.tags).toMatchObject({ role: "agent", project: "boom" });
  }, 60000);

  it("emits session_start for a session spawned after subscribe", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    const { baseToken } = await startRelay(relayConfigDir, port, host);

    let snapshotSeen = false;
    const starts: string[] = [];
    const sub = subscribeRemoteEvents(baseToken, {
      onSnapshot: () => { snapshotSeen = true; },
      onEvent: (evt) => {
        if (evt.type === "session_start") starts.push(evt.session);
      },
    });
    try {
      // Wait for snapshot so we know the follower is actually running.
      await waitFor(() => snapshotSeen, 10000, "initial snapshot");

      const name = `start-${port}`;
      spawnPtySession(name);

      await waitFor(() => starts.includes(name), 10000, `session_start for ${name}`);
    } finally {
      sub.close();
    }
  }, 60000);

  it("emits session_exit when a running session is killed", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    const { baseToken } = await startRelay(relayConfigDir, port, host);

    const name = `exit-${port}`;
    spawnPtySession(name);

    let snapshotSeen = false;
    const exits: string[] = [];
    const sub = subscribeRemoteEvents(baseToken, {
      onSnapshot: () => { snapshotSeen = true; },
      onEvent: (evt) => {
        if (evt.type === "session_exit") exits.push(evt.session);
      },
    });
    try {
      await waitFor(() => snapshotSeen, 10000, "initial snapshot");
      killPtySession(name);
      await waitFor(() => exits.includes(name), 10000, `session_exit for ${name}`);
    } finally {
      sub.close();
    }
  }, 60000);

  it("close() prevents further callbacks even when events arrive later", async () => {
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    const { baseToken } = await startRelay(relayConfigDir, port, host);

    let snapshotSeen = false;
    let closed = false;
    let callsAfterClose = 0;
    const sub = subscribeRemoteEvents(baseToken, {
      onSnapshot: () => { snapshotSeen = true; },
      onEvent: () => { if (closed) callsAfterClose++; },
    });

    await waitFor(() => snapshotSeen, 10000, "initial snapshot");
    sub.close();
    closed = true;

    // Nudge activity on the host — regardless of whether the follower would
    // have delivered, a closed subscription must swallow everything.
    spawnPtySession(`post-close-${port}`);
    await new Promise((r) => setTimeout(r, 400));
    expect(callsAfterClose).toBe(0);
  }, 60000);

  it("a closed subscription has a no-op close()", async () => {
    // Idempotency matters because UI consumers often call close() on
    // unmount regardless of the sub's state.
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    const { baseToken } = await startRelay(relayConfigDir, port, host);

    const sub = subscribeRemoteEvents(baseToken, {
      onSnapshot: () => {},
      onEvent: () => {},
    });
    sub.close();
    expect(() => sub.close()).not.toThrow();
  }, 60000);
});

describe("pty-relay events CLI", () => {
  it("connects and stays alive until Ctrl+C, then exits cleanly", async () => {
    // We can't easily send Ctrl+C to a spawned subprocess portably; instead
    // SIGTERM it and confirm it had connected (something went to stderr from
    // the reconnect path, or the process was otherwise live).
    const port = getPort();
    const relayConfigDir = path.join(ctx.stateDir, "relay");
    const host = `host-${port}`;
    await startRelay(relayConfigDir, port, host);

    const cli = spawn(
      "node",
      [CLI_ENTRY, "events", "--json", "--config-dir", relayConfigDir, host],
      {
        env: { ...process.env, PTY_SESSION_DIR: ctx.stateDir },
        stdio: ["ignore", "pipe", "pipe"],
      }
    );
    runningServers.push(cli);

    // Give the CLI time to complete handshake + subscribe. If it crashed it
    // would exit before this window; the `cli.exitCode` would be non-null.
    await new Promise((r) => setTimeout(r, 1500));
    expect(cli.exitCode).toBeNull();

    cli.kill("SIGTERM");
    const exitCode = await new Promise<number | null>((resolve) => {
      cli.once("exit", (code) => resolve(code));
    });
    // Either a clean 0 exit (SIGINT handler) or the default SIGTERM 143.
    expect([0, 143, null]).toContain(exitCode);
  }, 60000);
});
