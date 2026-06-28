import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as net from "node:net";
import { probeDaemon } from "../src/commands/local/status.ts";

/**
 * Unit tests for `probeDaemon`'s dual-signal (PID alive + TCP port
 * listening). The full CLI shape of `pty-relay local status` is
 * exercised by the integration suite; here we just pin the probe's
 * logic since it's the load-bearing fix for Nathan's "stale pid
 * 12839 (process not found)" reading-it-wrong bug.
 */

let dir: string;
let listenServer: net.Server | null = null;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "local-status-probe-"));
});

afterEach(async () => {
  if (listenServer) {
    await new Promise<void>((r) => listenServer!.close(() => r()));
    listenServer = null;
  }
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
});

/** Bind a TCP server on a free port. Returns the port. */
async function bindLoopback(): Promise<number> {
  listenServer = net.createServer();
  await new Promise<void>((resolve, reject) => {
    listenServer!.once("error", reject);
    listenServer!.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = listenServer!.address();
  if (!addr || typeof addr === "string") throw new Error("no address");
  return addr.port;
}

/** Pick an unused port — bind, read the port, then close. */
async function pickUnusedPort(): Promise<number> {
  const tmp = net.createServer();
  await new Promise<void>((r) => tmp.listen(0, "127.0.0.1", () => r()));
  const addr = tmp.address();
  if (!addr || typeof addr === "string") throw new Error("no address");
  const port = addr.port;
  await new Promise<void>((r) => tmp.close(() => r()));
  return port;
}

describe("probeDaemon", () => {
  it("running:true, portListening:true when the pid is alive AND the port is bound", async () => {
    const port = await bindLoopback();
    fs.writeFileSync(path.join(dir, "daemon.pid"), String(process.pid));
    const probe = await probeDaemon(dir, port);
    expect(probe).toEqual({
      pid: process.pid,
      running: true,
      portListening: true,
    });
  });

  it("running:false, portListening:true on a stale pid file with the port still bound (supervisor respawn case)", async () => {
    const port = await bindLoopback();
    // Pid 2**30 - 1 ≈ 1 billion — high enough that it's never a real
    // process on any sane system.
    const stalePid = 2 ** 30 - 1;
    fs.writeFileSync(path.join(dir, "daemon.pid"), String(stalePid));
    const probe = await probeDaemon(dir, port);
    expect(probe.pid).toBe(stalePid);
    expect(probe.running).toBe(false);
    expect(probe.portListening).toBe(true);
  });

  it("running:false, portListening:false when nothing's around (Nathan's clean-shutdown case)", async () => {
    const port = await pickUnusedPort();
    const probe = await probeDaemon(dir, port);
    expect(probe).toEqual({
      pid: null,
      running: false,
      portListening: false,
    });
  });

  it("pid file present but port not bound — surfaces as pid:N, running:?, portListening:false", async () => {
    const port = await pickUnusedPort();
    fs.writeFileSync(path.join(dir, "daemon.pid"), String(process.pid));
    const probe = await probeDaemon(dir, port);
    expect(probe.pid).toBe(process.pid);
    expect(probe.running).toBe(true); // this process IS alive
    expect(probe.portListening).toBe(false);
  });

  it("missing daemon.pid + port bound — running:false, portListening:true (this is the daemon-up-but-no-pid-file case)", async () => {
    const port = await bindLoopback();
    const probe = await probeDaemon(dir, port);
    expect(probe.pid).toBeNull();
    expect(probe.running).toBe(false);
    expect(probe.portListening).toBe(true);
  });

  it("garbage daemon.pid (non-numeric) — same as missing", async () => {
    const port = await pickUnusedPort();
    fs.writeFileSync(path.join(dir, "daemon.pid"), "not a number");
    const probe = await probeDaemon(dir, port);
    expect(probe.pid).toBeNull();
    expect(probe.running).toBe(false);
    expect(probe.portListening).toBe(false);
  });

  it("the TCP probe times out fast (under ~1s) when the port is firewalled / unreachable", async () => {
    // 0.0.0.0:1 is reserved + typically firewalled. Connecting to it
    // either errors immediately or times out — our 500ms cap means
    // this resolves quickly either way. We don't assert a specific
    // result (depends on platform), just that it doesn't hang.
    const start = Date.now();
    const probe = await probeDaemon(dir, 1);
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(1500);
    expect(typeof probe.portListening).toBe("boolean");
  });
});
