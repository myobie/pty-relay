import { describe, it, expect } from "vitest";
import * as net from "node:net";
import * as os from "node:os";
import { createRelayServer } from "../src/serve/server.ts";

/**
 * Issue #1 — verify that the `host` parameter on `createRelayServer`
 * actually scopes the listen socket. The unit-level resolver tests
 * (test/bind-host.test.ts) just check what value the CLI computes;
 * this file boots a real server and probes both loopback and a
 * non-loopback interface to confirm the kernel sees the right scope.
 */

/** First non-loopback IPv4 on this machine, or null if none. CI runners
 *  in some sandboxes have only `lo`, so the cross-interface test must
 *  skip cleanly there. */
function firstNonLoopbackIPv4(): string | null {
  const ifs = os.networkInterfaces();
  for (const addrs of Object.values(ifs)) {
    if (!addrs) continue;
    for (const a of addrs) {
      if (a.family === "IPv4" && !a.internal) return a.address;
    }
  }
  return null;
}

/** Try to open a TCP connection. Resolves to "ok" / "refused" /
 *  the error code. Times out at 1.5s so a silently-blackholed dial
 *  doesn't hang the suite forever. */
function probeTcp(host: string, port: number): Promise<string> {
  return new Promise((resolve) => {
    const sock = net.createConnection({ host, port });
    let settled = false;
    const finish = (result: string) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch {}
      resolve(result);
    };
    const timer = setTimeout(() => finish("timeout"), 1500);
    sock.once("connect", () => { clearTimeout(timer); finish("ok"); });
    sock.once("error", (err: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      finish(err.code ?? err.message);
    });
  });
}

/** Pick a high random port and try createRelayServer there. Retries
 *  a few times on EADDRINUSE, otherwise rethrows. Returns the port
 *  the server is actually listening on. */
async function bootOnRandomPort(host?: string): Promise<{ port: number; stop: () => Promise<void> }> {
  for (let i = 0; i < 5; i++) {
    const port = 40000 + Math.floor(Math.random() * 20000);
    const server = createRelayServer(port, undefined, host);
    try {
      await server.start();
      return { port, stop: () => server.stop() };
    } catch (err: any) {
      if (err?.code !== "EADDRINUSE") throw err;
    }
  }
  throw new Error("could not find free port after 5 tries");
}

describe("createRelayServer host binding", () => {
  it("--bind 127.0.0.1 accepts loopback connections and refuses non-loopback", async () => {
    const nonLoop = firstNonLoopbackIPv4();
    if (!nonLoop) {
      // No external interface (locked-down CI). The "refuse non-loopback"
      // half of this assertion has nothing to probe; skip with an
      // explanatory message rather than failing.
      console.warn("skipping: no non-loopback IPv4 on this host");
      return;
    }
    const { port, stop } = await bootOnRandomPort("127.0.0.1");
    try {
      const loop = await probeTcp("127.0.0.1", port);
      expect(loop).toBe("ok");

      // The kernel returns ECONNREFUSED for a port that's listening on
      // a different interface, because no socket on the dialed
      // interface accepts it. (If the listener were on 0.0.0.0 we'd
      // get "ok" here too — that's the regression we're guarding.)
      const lan = await probeTcp(nonLoop, port);
      expect(lan).toBe("ECONNREFUSED");
    } finally {
      await stop();
    }
  });

  it("no host argument binds to all interfaces (historical default)", async () => {
    const nonLoop = firstNonLoopbackIPv4();
    if (!nonLoop) {
      console.warn("skipping: no non-loopback IPv4 on this host");
      return;
    }
    // host=undefined → start.ts hits the no-host listen() branch, which
    // is Node's all-interfaces default. Both loopback and non-loopback
    // dials should succeed.
    const { port, stop } = await bootOnRandomPort(undefined);
    try {
      const loop = await probeTcp("127.0.0.1", port);
      expect(loop).toBe("ok");
      const lan = await probeTcp(nonLoop, port);
      expect(lan).toBe("ok");
    } finally {
      await stop();
    }
  });
});
