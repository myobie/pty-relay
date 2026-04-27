import * as os from "node:os";
import sodium from "libsodium-wrappers-sumo";
import { ready, KK, Transport } from "../crypto/index.ts";
import { ClientRelayConnection } from "../terminal/client-connection.ts";
import { Terminal } from "../terminal/terminal.ts";
import type { SecretStore } from "../storage/secret-store.ts";
import { openSecretStore } from "../storage/bootstrap.ts";
import { resolveHost } from "../relay/host-resolve.ts";
import type { PublicTarget } from "../relay/relay-client.ts";
import { listPublicRemoteSessions } from "../relay/relay-client.ts";
import { buildPublicClientPairUrl } from "../relay/public-server-url.ts";
import {
  ed25519PkToCurve25519,
  ed25519SkToCurve25519,
} from "../crypto/key-conversion.ts";
import type { ConnectResult } from "./connect.ts";
import { reconnectDelay } from "./connect.ts";
import { spawnSync } from "node:child_process";
import { log } from "../log.ts";

/**
 * Public-relay variant of the `connect` flow. Mirrors the self-hosted
 * `connect` command in spirit — list sessions, let the user pick, attach
 * with reconnect-on-lost — but over a signed `role=client_pair` WS
 * against a public-relay target daemon (Ed25519-authenticated, no
 * #pk.secret fragment, no operator approval step).
 *
 * Kept in a separate module so the self-hosted reconnect/detach logic
 * in connect.ts doesn't have to branch on transport at every step.
 */

const RECONNECT_INITIAL_MS = 1000;
const MAX_RECONNECT_ATTEMPTS = 20;

export async function connectPublic(
  hostLabel: string,
  options: {
    session?: string;
    configDir?: string;
    passphraseFile?: string;
  } = {}
): Promise<void> {
  await ready();
  log("cli", "connect-public begin", { hostLabel, session: options.session });

  const { store } = await openSecretStore(options.configDir, {
    interactive: true,
    passphraseFile: options.passphraseFile,
  });

  const resolved = await resolveHost(hostLabel, store);
  if (resolved.kind !== "public") {
    // Shouldn't happen — the caller already checked — but guard anyway.
    throw new Error(`Host "${hostLabel}" is not a public-relay host`);
  }

  let session: string | undefined = options.session;
  if (!session) {
    const picked = await listAndPickPublic(resolved.target, hostLabel);
    if (!picked) return; // no sessions, or re-exec'd through listAndPick
    session = picked;
  }

  await connectPublicWithReconnect(resolved.target, session);
}

async function listAndPickPublic(
  target: PublicTarget,
  hostLabel: string
): Promise<string | null> {
  const { sessions } = await listPublicRemoteSessions(target, 15_000);
  if (sessions.length === 0) {
    console.log(`No running sessions on "${hostLabel}".`);
    return null;
  }
  if (sessions.length === 1) return sessions[0].name;

  console.log("\nAvailable sessions:\n");
  sessions.forEach((s, i) => {
    const cmd = s.command ? `  ${s.command}` : "";
    const disp = s.displayName ? `${s.displayName} (${s.name})` : s.name;
    console.log(`  ${i + 1}) ${disp}${cmd}`);
  });
  console.log();

  const answer = await prompt("Select session: ");
  const idx = parseInt(answer.trim(), 10) - 1;
  if (idx < 0 || idx >= sessions.length) {
    console.error("Invalid selection.");
    process.exit(1);
  }

  // Re-exec ourselves with the chosen session so we get a clean stdin
  // for raw-mode terminal handling (same trick as self-hosted connect).
  const result = spawnSync(
    process.argv[0],
    [process.argv[1], "connect", hostLabel, "--session", sessions[idx].name],
    { stdio: "inherit" }
  );
  process.exit(result.status ?? 0);
}

async function connectPublicWithReconnect(
  target: PublicTarget,
  session: string
): Promise<void> {
  let attempt = 0;
  let isReconnect = false;

  while (true) {
    const reason = await attemptConnectPublic(target, session, isReconnect);

    log("bridge", "public attempt ended", {
      session,
      attempt,
      isReconnect,
      reason: reason.kind,
      ...(reason.kind === "error" ? { message: reason.message } : {}),
      ...(reason.kind === "lost" ? { wasAttached: reason.wasAttached } : {}),
    });

    if (reason.kind === "detached") return;
    if (reason.kind === "exited") return;
    if (reason.kind === "error") {
      console.error(`Fatal: ${reason.message}`);
      process.exit(1);
    }

    // "lost": bounded retries, reset the counter on a connection that
    // actually attached (so sleep/wake doesn't burn through the budget).
    if (reason.wasAttached) attempt = 0;
    if (attempt >= MAX_RECONNECT_ATTEMPTS) {
      log("bridge", "public gave up reconnecting", { attempts: attempt });
      console.error(`\n[gave up reconnecting after ${attempt} attempts]`);
      return;
    }
    const delay = reconnectDelay(attempt);
    log("bridge", "public scheduling reconnect", { attempt, delayMs: delay });
    console.error(
      `\n[disconnected — reconnecting in ${Math.round(delay / 1000)}s...]`
    );
    await sleep(delay);
    attempt++;
    isReconnect = true;
  }
}

type PublicDisconnectReason =
  | { kind: "detached" }
  | { kind: "exited" }
  | { kind: "error"; message: string }
  | { kind: "lost"; wasAttached: boolean };

async function attemptConnectPublic(
  target: PublicTarget,
  session: string,
  isReconnect: boolean
): Promise<PublicDisconnectReason> {
  const cols = process.stdout.columns || 80;
  const rows = process.stdout.rows || 24;

  // Fresh signed URL per attempt — Ed25519 payloads expire after 60s.
  const wsUrl = buildPublicClientPairUrl(
    target.relayUrl,
    target.accountKeys,
    target.targetPublicKeyB64
  );
  const targetEdBytes = sodium.from_base64(
    target.targetPublicKeyB64,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );
  const targetCurvePk = await ed25519PkToCurve25519(targetEdBytes);
  // Convert our own Ed25519 account keypair to Curve25519 for KK.
  // KK requires both parties' statics; the relay tells the daemon ours
  // via client_public_key in the paired frame.
  const clientStaticKeys = {
    publicKey: await ed25519PkToCurve25519(target.accountKeys.public),
    privateKey: await ed25519SkToCurve25519(target.accountKeys.secret),
  };

  return new Promise<PublicDisconnectReason>((resolve) => {
    let settled = false;
    let terminal: Terminal | null = null;
    let intentionalClose = false;

    function done(reason: PublicDisconnectReason) {
      if (settled) return;
      settled = true;
      resolve(reason);
    }

    const connection = new ClientRelayConnection(wsUrl, {
      pattern: KK,
      daemonPublicKey: targetCurvePk,
      clientStaticKeys,
    }, {
      onReady: () => {
        if (!process.env.PTY_RELAY_CLIENT_ANON) {
          connection.send(
            new TextEncoder().encode(
              JSON.stringify({
                type: "hello",
                client: "cli",
                os: process.platform,
                label: os.hostname(),
              })
            )
          );
        }
        terminal = new Terminal({
          connection,
          session,
          cols,
          rows,
          onDetach: () => {
            intentionalClose = true;
            try { connection.close(); } catch {}
            done({ kind: "detached" });
          },
          onExit: () => {
            intentionalClose = true;
            try { connection.close(); } catch {}
            done({ kind: "exited" });
          },
          onError: (msg: string) => {
            intentionalClose = true;
            try { connection.close(); } catch {}
            done({ kind: "error", message: msg });
          },
        });
        terminal.start(cols, rows);
      },

      onEncryptedMessage: (plaintext: Uint8Array) => {
        if (terminal) terminal.handleMessage(plaintext);
      },

      // Public-mode never waits for approval — Ed25519 is the gate.
      onWaitingForApproval: () => {},

      onPeerDisconnected: () => {
        const attached = terminal !== null;
        terminal?.cleanup();
        terminal = null;
        if (!intentionalClose) {
          done({ kind: "lost", wasAttached: attached });
        }
      },

      onError: (err: Error) => {
        const msg = err.message.toLowerCase();
        if (msg.includes("not registered") || msg.includes("revoked")) {
          terminal?.cleanup();
          terminal = null;
          intentionalClose = true;
          try { connection.close(); } catch {}
          done({ kind: "error", message: err.message });
          return;
        }
        if (!terminal && !isReconnect) {
          console.error(`Error: ${err.message}`);
        }
      },

      onClose: () => {
        const attached = terminal !== null;
        terminal?.cleanup();
        terminal = null;
        if (!intentionalClose) {
          done({ kind: "lost", wasAttached: attached });
        }
      },
    });

    connection.connect();
  });
}

function prompt(question: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(question);
    process.stdin.ref();
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    process.stdin.once("data", (data: string) => {
      process.stdin.pause();
      process.stdin.unref();
      resolve(data);
    });
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
