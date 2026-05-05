import { describe, it, expect } from "vitest";
import * as path from "node:path";
import { createRelayServer } from "../src/serve/server.ts";

/**
 * The daemon serves index.html with a `<meta name="pty-relay-config">`
 * tag whose JSON content is read by the browser to decide which
 * opt-in features to wire up (latency telemetry, mosh-style predictive
 * echo, etc). This file verifies that the CLI flags the daemon was
 * started with actually land in that meta — i.e., the *only* gate
 * between the operator and the corresponding browser feature.
 *
 * These are smoke-level integration tests: they boot the real HTTP
 * server, fetch /, and inspect the served HTML.
 */

const HTML_PATH = path.resolve(import.meta.dirname, "../browser/dist/index.html");

async function bootOnRandomPort(opts: { mosh?: boolean; latencyStats?: boolean }): Promise<{
  port: number;
  stop: () => Promise<void>;
}> {
  for (let i = 0; i < 5; i++) {
    const port = 40000 + Math.floor(Math.random() * 20000);
    const server = createRelayServer(port, HTML_PATH, "127.0.0.1", {
      mosh: opts.mosh,
      latencyStats: opts.latencyStats,
    });
    try {
      await server.start();
      return { port, stop: () => server.stop() };
    } catch (err: any) {
      if (err?.code !== "EADDRINUSE") throw err;
    }
  }
  throw new Error("could not find free port after 5 tries");
}

async function fetchIndex(port: number): Promise<string> {
  const res = await fetch(`http://127.0.0.1:${port}/`);
  expect(res.status).toBe(200);
  return await res.text();
}

/** Extract the parsed JSON content of <meta name="pty-relay-config">.
 *  Throws if the meta is missing — that's a regression in itself. */
function parseConfigMeta(html: string): Record<string, unknown> {
  const match = html.match(
    /<meta\s+name="pty-relay-config"\s+content='([^']+)'\s*\/?>/
  );
  if (!match) throw new Error("pty-relay-config meta tag not found in index.html");
  return JSON.parse(match[1]);
}

describe("served runtime config meta", () => {
  it("--mosh flag injects mosh:true into the runtime config", async () => {
    const { port, stop } = await bootOnRandomPort({ mosh: true });
    try {
      const html = await fetchIndex(port);
      const config = parseConfigMeta(html);
      expect(config.mosh).toBe(true);
    } finally {
      await stop();
    }
  });

  it("default (no --mosh) leaves mosh:false", async () => {
    const { port, stop } = await bootOnRandomPort({});
    try {
      const html = await fetchIndex(port);
      const config = parseConfigMeta(html);
      expect(config.mosh).toBe(false);
    } finally {
      await stop();
    }
  });

  it("--mosh and --latency-stats are independent and both reach the browser", async () => {
    // Belt-and-suspenders against a regression where adding the second
    // boolean stomps the first (e.g. accidental object reuse).
    const { port, stop } = await bootOnRandomPort({ mosh: true, latencyStats: true });
    try {
      const html = await fetchIndex(port);
      const config = parseConfigMeta(html);
      expect(config.mosh).toBe(true);
      expect(config.latencyStats).toBe(true);
    } finally {
      await stop();
    }
  });

  it("the bundled main.js is served and references runtimeConfig.mosh", async () => {
    // The runtime gate ('if (!runtimeConfig.mosh) return') is what
    // makes the meta tag actually load-bearing. If a future build
    // accidentally drops that branch, the meta tag would still be
    // served but mosh would be on for everyone — catch that here.
    const { port, stop } = await bootOnRandomPort({});
    try {
      const res = await fetch(`http://127.0.0.1:${port}/main.js`);
      expect(res.status).toBe(200);
      const js = await res.text();
      expect(js).toContain("runtimeConfig");
      expect(js).toContain("mosh");
    } finally {
      await stop();
    }
  });
});
