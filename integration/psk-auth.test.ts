import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  CLI_ENTRY,
  Session,
  createTestContext,
  destroyTestContext,
  extractTokenUrl,
  tokenWithSession,
  track,
  getPort,
  type TestContext,
} from "./helpers/index.ts";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";

/**
 * Phase-5 PSK e2e: prove the three matrix cells of
 * `Noise_NKpsk2` auth — match, server-only, client-only — produce
 * the expected outcomes end-to-end (not just at the framing layer).
 *
 * Each case spawns a real self-hosted relay + a real connect client,
 * with --psk-file pointing at temp files. The `psk-gen` subcommand is
 * exercised once at the top to produce a PSK in the documented format.
 */

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

function writePskFile(name: string, contents: string): string {
  const p = path.join(ctx.stateDir, name);
  fs.writeFileSync(p, contents, { mode: 0o600 });
  return p;
}

function generatePskViaCli(): string {
  // Exercise the actual subcommand so a regression in its plumbing
  // surfaces here, not just in the unit test.
  const result = spawnSync(
    "node",
    [CLI_ENTRY, "psk-gen"],
    { encoding: "utf-8" },
  );
  if (result.status !== 0) {
    throw new Error(
      `psk-gen failed: status=${result.status}, stderr=${result.stderr}`,
    );
  }
  const psk = result.stdout.trim();
  if (psk.length !== 43) {
    throw new Error(`Expected 43-char PSK from psk-gen, got ${psk.length}: ${psk}`);
  }
  return psk;
}

describe("PSK auth — server-required, client-supplied (Noise_NKpsk2)", () => {
  it("happy path: matching PSK on both sides → echo round-trip", async () => {
    const port = getPort();
    const psk = generatePskViaCli();
    const pskFile = writePskFile("psk", psk);

    // Start a pty session so the client has something to attach to.
    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--psk-file",
          pskFile,
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } },
      ),
    );

    // The startup banner confirms the responder is in PSK mode — the
    // assertion catches an upstream regression where --psk-file gets
    // silently dropped through cli.ts → start.ts before the per-client
    // RelayConnection sees it.
    await server.waitForText("PSK authentication enabled", 15000);
    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);
    const token = tokenWithSession(baseToken, ptySession.name);

    const client = track(
      ctx,
      Session.spawn(
        "node",
        [CLI_ENTRY, "connect", token, "--psk-file", pskFile],
        { rows: 24, cols: 80, env: { PTY_SESSION_DIR: ctx.stateDir } },
      ),
    );

    await client.waitForText("$", 15000);
    client.sendKeys("echo psk-handshake-ok\n");
    await client.waitForText("psk-handshake-ok", 5000);
  }, 60000);

  it("server has PSK, client doesn't → server REJECTS non-PSK pairing", async () => {
    const port = getPort();
    const psk = generatePskViaCli();
    const pskFile = writePskFile("psk", psk);

    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--psk-file",
          pskFile,
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } },
      ),
    );

    await server.waitForText("PSK authentication enabled", 15000);
    await server.waitForText("Token URL", 15000);
    const baseToken = extractTokenUrl(server.screenshot());
    const token = tokenWithSession(baseToken, ptySession.name);

    // Connect WITHOUT --psk-file. The client picks plain NK; the
    // server should refuse via `daemon has PSK configured` because
    // it has a PSK loaded.
    const client = track(
      ctx,
      Session.spawn(
        "node",
        [CLI_ENTRY, "connect", token],
        { rows: 24, cols: 80, env: { PTY_SESSION_DIR: ctx.stateDir } },
      ),
    );

    // The structured audit log line on the responder + the warn() to
    // the daemon's stdout are what we assert on — the client sees a
    // generic disconnect, but the daemon's screen shows the reason.
    await server.waitForText("REJECTED", 15000);
    await server.waitForText("daemon has PSK configured", 15000);
  }, 60000);

  it("client has PSK, server doesn't → server REJECTS NKpsk2 request", async () => {
    const port = getPort();
    const psk = generatePskViaCli();
    const pskFile = writePskFile("psk", psk);

    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    // Server WITHOUT --psk-file.
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } },
      ),
    );

    await server.waitForText("Token URL", 15000);
    const baseToken = extractTokenUrl(server.screenshot());
    const token = tokenWithSession(baseToken, ptySession.name);

    // Client signals psk_required=1 via --psk-file, but the daemon
    // has none. Construction-time error in beginHandshake. Note: the
    // audit warn line is only attached when the responder ALSO has a
    // PSK loaded — in this asymmetric case the failure surfaces via
    // RelayConnection's normal onError → `Client <id> error:` line.
    const client = track(
      ctx,
      Session.spawn(
        "node",
        [CLI_ENTRY, "connect", token, "--psk-file", pskFile],
        { rows: 24, cols: 80, env: { PTY_SESSION_DIR: ctx.stateDir } },
      ),
    );

    await server.waitForText("client requested NKpsk2", 15000);
    await server.waitForText("no PSK configured", 15000);
  }, 60000);
});
