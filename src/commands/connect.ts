import * as os from "node:os";
import { spawnSync } from "node:child_process";
import {
  ready,
  parseToken,
  computeSecretHash,
  getWebSocketUrl,
  createToken,
  NK,
} from "../crypto/index.ts";
import type { ParsedToken } from "../crypto/index.ts";
import { ClientRelayConnection } from "../terminal/client-connection.ts";
import { Terminal } from "../terminal/terminal.ts";
import { saveKnownHost } from "../relay/known-hosts.ts";
import type { SecretStore } from "../storage/secret-store.ts";
import { openSecretStore } from "../storage/bootstrap.ts";
import { log } from "../log.ts";

// Reconnect constants
const RECONNECT_INITIAL_MS = 1000;
const RECONNECT_MAX_MS = 15000;
const RECONNECT_BACKOFF = 2;
const MAX_RECONNECT_ATTEMPTS = 20;

export async function connect(
  tokenUrlOrLabel: string,
  options?: {
    spawn?: string;
    cwd?: string;
    tags?: Record<string, string>;
    session?: string;
    configDir?: string;
    passphraseFile?: string;
  }
): Promise<void> {
  await ready();
  log("cli", "connect begin", {
    target: looksLikeTokenUrl(tokenUrlOrLabel) ? "token-url" : tokenUrlOrLabel,
    spawn: options?.spawn,
    cwd: options?.cwd,
    session: options?.session,
    hasTags: !!(options?.tags && Object.keys(options.tags).length > 0),
  });

  // Dispatch: a raw http(s):// URL is a self-hosted token URL and goes
  // through the existing flow. Anything else is treated as a known-hosts
  // label — we look it up and, if public-mode, hand off to the public
  // attach path. Labels are a recent addition for public-relay; the
  // self-hosted UX still keys on paste-in token URLs.
  if (!looksLikeTokenUrl(tokenUrlOrLabel)) {
    const { store, passphrase } = await openSecretStore(options?.configDir, {
      interactive: true,
      passphraseFile: options?.passphraseFile,
    });
    if (passphrase && !process.env.PTY_RELAY_PASSPHRASE) {
      process.env.PTY_RELAY_PASSPHRASE = passphrase;
    }
    const { resolveHost } = await import("../relay/host-resolve.ts");
    const resolved = await resolveHost(tokenUrlOrLabel, store);
    if (resolved.kind === "public") {
      const { connectPublic } = await import("./connect-public.ts");
      await connectPublic(tokenUrlOrLabel, {
        session: options?.session,
        configDir: options?.configDir,
        passphraseFile: options?.passphraseFile,
      });
      return;
    }
    // Self-hosted label → look up the stored URL and fall through.
    tokenUrlOrLabel = resolved.url;
  }

  const tokenUrl = tokenUrlOrLabel;
  const parsed = parseToken(tokenUrl);
  const secretHash = computeSecretHash(parsed.secret);
  const wsUrl = getWebSocketUrl(parsed.host, "client", secretHash, undefined, parsed.clientToken ?? undefined);

  const { store, passphrase } = await openSecretStore(options?.configDir, {
    interactive: true,
    passphraseFile: options?.passphraseFile,
  });

  // If we prompted interactively for a passphrase, propagate it via env var
  // so re-exec'd children (listAndPick) don't re-prompt.
  if (passphrase && !process.env.PTY_RELAY_PASSPHRASE) {
    process.env.PTY_RELAY_PASSPHRASE = passphrase;
  }

  // Save this host for the interactive TUI (strip session from URL)
  const baseUrl = createToken(parsed.host, parsed.publicKey, parsed.secret, undefined, parsed.clientToken ?? undefined);
  await saveKnownHost(parsed.host, baseUrl, store);

  // If no session and no spawn, list sessions and re-exec with the chosen one
  if (!parsed.session && !options?.spawn) {
    await listAndPick(wsUrl, parsed, tokenUrl, store);
    return;
  }

  attachSession(wsUrl, parsed, store, options);
}

function looksLikeTokenUrl(s: string): boolean {
  return s.startsWith("http://") || s.startsWith("https://");
}

/**
 * Connect, list sessions, let user pick, then re-exec with the session in the URL.
 * Re-exec gives the new process clean stdin for raw mode.
 */
async function listAndPick(
  wsUrl: string,
  parsed: ReturnType<typeof parseToken>,
  tokenUrl: string,
  store: SecretStore,
): Promise<void> {
  const sessions = await fetchSessions(wsUrl, parsed, store);

  if (sessions.length === 0) {
    console.log("No running sessions.");
    process.exit(0);
  }

  let chosen: string;

  if (sessions.length === 1) {
    chosen = sessions[0].name;
  } else {
    console.log("\nAvailable sessions:\n");
    for (let i = 0; i < sessions.length; i++) {
      const s = sessions[i];
      const cmd = s.command ? `  ${s.command}` : "";
      console.log(`  ${i + 1}) ${s.name}${cmd}`);
    }
    console.log();

    const answer = await prompt("Select session: ");
    const idx = parseInt(answer.trim(), 10) - 1;
    if (idx < 0 || idx >= sessions.length) {
      console.error("Invalid selection.");
      process.exit(1);
    }
    chosen = sessions[idx].name;
  }

  // Build the URL with the session name and re-exec (preserve clientToken)
  const sessionUrl = createToken(parsed.host, parsed.publicKey, parsed.secret, chosen, parsed.clientToken ?? undefined);

  // Re-exec ourselves with the session in the URL — clean process, clean stdin
  const result = spawnSync(process.argv[0], [process.argv[1], "connect", sessionUrl], {
    stdio: "inherit",
  });
  process.exit(result.status ?? 0);
}

function fetchSessions(
  wsUrl: string,
  parsed: ReturnType<typeof parseToken>,
  store: SecretStore,
): Promise<Array<{ name: string; command?: string }>> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      connection.close();
      reject(new Error("Timed out waiting for session list"));
    }, 15000);

    const connection = new ClientRelayConnection(wsUrl, {
      pattern: NK,
      daemonPublicKey: parsed.publicKey,
    }, {
      onReady: () => {
        if (!process.env.PTY_RELAY_CLIENT_ANON) {
          connection.send(new TextEncoder().encode(JSON.stringify({
            type: "hello",
            client: "cli",
            os: process.platform,
            label: os.hostname(),
          })));
        }
        connection.send(new TextEncoder().encode(JSON.stringify({ type: "list" })));
      },
      onEncryptedMessage: (plaintext: Uint8Array) => {
        if (plaintext.length > 0 && plaintext[0] === 0x7b) {
          try {
            const msg = JSON.parse(new TextDecoder().decode(plaintext));
            if (msg.type === "sessions") {
              clearTimeout(timeout);
              connection.close();
              resolve(msg.sessions);
            } else if (msg.type === "approved" && msg.client_token) {
              // Save the approved token for future reconnections AND
              // update parsed so the re-exec URL includes the token.
              parsed.clientToken = msg.client_token;
              const newUrl = createToken(parsed.host, parsed.publicKey, parsed.secret, undefined, msg.client_token);
              saveKnownHost(parsed.host, newUrl, store).catch(() => {});
            } else if (msg.type === "error") {
              connection.close();
              reject(new Error(msg.message));
            }
          } catch {}
        }
      },
      onWaitingForApproval: () => {
        console.log("Waiting for operator approval...");
      },
      onPeerDisconnected: () => { reject(new Error("Daemon disconnected")); },
      onError: (err: Error) => { reject(err); },
      onClose: () => {},
    });
    connection.connect();
  });
}

function prompt(question: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(question);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    process.stdin.once("data", (data: string) => {
      process.stdin.pause();
      resolve(data);
    });
  });
}

export type ConnectResult =
  | "detached"
  | "disconnected"
  | "exited"
  | { error: string };

/**
 * Reason for a single connection ending. Used internally to decide
 * whether the reconnect loop should retry or give up.
 */
type DisconnectReason =
  | { kind: "detached" }   // user pressed Ctrl+\ — intentional
  | { kind: "exited" }     // session EXIT packet
  | { kind: "error"; message: string }  // non-retriable error (token revoked, etc.)
  | { kind: "lost"; wasAttached: boolean };  // connection lost — should reconnect

/**
 * Attempt a single connection. Resolves when the connection ends for any
 * reason: intentional detach, session exit, error, or lost connection.
 */
function attemptConnect(
  wsUrl: string,
  parsed: ParsedToken,
  store: SecretStore,
  session: string,
  options: {
    spawn?: string;
    cwd?: string;
    tags?: Record<string, string>;
    isReconnect: boolean;
    onStatus: (msg: string) => void;
  },
): Promise<DisconnectReason> {
  const cols = process.stdout.columns || 80;
  const rows = process.stdout.rows || 24;

  return new Promise<DisconnectReason>((resolve) => {
    let resolved = false;
    let terminal: Terminal | null = null;
    let approvalTimeout: ReturnType<typeof setTimeout> | null = null;
    // Track whether disconnect was caused by us (intentional close)
    let intentionalClose = false;

    function done(reason: DisconnectReason): void {
      if (resolved) return;
      resolved = true;
      if (approvalTimeout) {
        clearTimeout(approvalTimeout);
        approvalTimeout = null;
      }
      resolve(reason);
    }

    const connection = new ClientRelayConnection(wsUrl, {
      pattern: NK,
      daemonPublicKey: parsed.publicKey,
    }, {
      onReady: () => {
        if (!process.env.PTY_RELAY_CLIENT_ANON) {
          connection.send(new TextEncoder().encode(JSON.stringify({
            type: "hello",
            client: "cli",
            os: process.platform,
            label: os.hostname(),
          })));
        }

        if (options.spawn && !options.isReconnect) {
          // Only spawn on first connect — on reconnect we always attach
          connection.send(new TextEncoder().encode(JSON.stringify({
            type: "spawn",
            name: options.spawn,
            cols,
            rows,
            ...(options.cwd ? { cwd: options.cwd } : {}),
            ...(options.tags && Object.keys(options.tags).length > 0 ? { tags: options.tags } : {}),
          })));
          terminal = new Terminal({
            connection,
            session,
            cols,
            rows,
            skipAttach: true,
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
            onError: (msg) => {
              intentionalClose = true;
              try { connection.close(); } catch {}
              done({ kind: "error", message: msg });
            },
          });
          terminal.start(cols, rows);
        } else {
          // Attach to existing session (also used on reconnect)
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
            onError: (msg) => {
              intentionalClose = true;
              try { connection.close(); } catch {}
              done({ kind: "error", message: msg });
            },
          });
          terminal.start(cols, rows);
        }
      },

      onEncryptedMessage: (plaintext: Uint8Array) => {
        // Check for control messages before passing to terminal
        if (plaintext.length > 0 && plaintext[0] === 0x7b) {
          try {
            const msg = JSON.parse(new TextDecoder().decode(plaintext));
            if (msg.type === "approved" && msg.client_token) {
              // Save the approved token for future reconnections
              const newUrl = createToken(parsed.host, parsed.publicKey, parsed.secret, undefined, msg.client_token);
              saveKnownHost(parsed.host, newUrl, store).catch(() => {});
              return; // Don't pass to terminal
            }
          } catch {}
        }
        if (terminal) terminal.handleMessage(plaintext);
      },

      onWaitingForApproval: () => {
        if (!options.isReconnect) {
          options.onStatus("Waiting for operator approval...");
          approvalTimeout = setTimeout(() => {
            if (!terminal) {
              intentionalClose = true;
              connection.close();
              done({ kind: "error", message: "Approval timed out" });
            }
          }, 5 * 60 * 1000);
        }
      },

      onPeerDisconnected: () => {
        const attached = terminal !== null;
        terminal?.cleanup();
        terminal = null;
        if (!intentionalClose) {
          done({ kind: "lost", wasAttached: attached });
        }
      },

      onError: (error: Error) => {
        // Check for non-retriable errors
        const msg = error.message.toLowerCase();
        if (msg.includes("token revoked") || msg.includes("not authorized")) {
          terminal?.cleanup();
          terminal = null;
          intentionalClose = true;
          try { connection.close(); } catch {}
          done({ kind: "error", message: error.message });
          return;
        }
        // Non-fatal errors during approval/handshake — log but don't resolve
        if (!terminal && !options.isReconnect) {
          options.onStatus(`Error: ${error.message}`);
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

/**
 * Compute the backoff delay for a reconnect attempt.
 */
export function reconnectDelay(attempt: number): number {
  const delay = RECONNECT_INITIAL_MS * Math.pow(RECONNECT_BACKOFF, attempt);
  return Math.min(delay, RECONNECT_MAX_MS);
}

/**
 * Sleep for the given number of milliseconds.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const CTRL_BACKSLASH = 0x1c;
const KITTY_CTRL_BACKSLASH = Buffer.from("\x1b[92;5u");

/**
 * Sleep for `ms` but return early if the user presses Ctrl+\.
 * Returns true if interrupted (user wants to detach), false if the
 * sleep completed normally.
 */
function interruptibleSleep(ms: number): Promise<boolean> {
  return new Promise((resolve) => {
    let done = false;

    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      cleanup();
      resolve(false);
    }, ms);

    const onData = (data: Buffer | string) => {
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
      if (
        (buf.length === 1 && buf[0] === CTRL_BACKSLASH) ||
        buf.equals(KITTY_CTRL_BACKSLASH)
      ) {
        if (done) return;
        done = true;
        clearTimeout(timer);
        cleanup();
        resolve(true);
      }
    };

    function cleanup() {
      process.stdin.removeListener("data", onData);
      if (process.stdin.isTTY) {
        try { process.stdin.setRawMode(false); } catch {}
      }
      process.stdin.pause();
    }

    // Enter raw mode to capture Ctrl+\
    if (process.stdin.isTTY) {
      try { process.stdin.setRawMode(true); } catch {}
    }
    process.stdin.resume();
    process.stdin.on("data", onData);
  });
}

/**
 * Connect with automatic reconnection on connection loss.
 * Used by both connectEmbedded and attachSession.
 */
async function connectWithReconnect(
  wsUrl: string,
  parsed: ParsedToken,
  store: SecretStore,
  session: string,
  options: {
    spawn?: string;
    cwd?: string;
    tags?: Record<string, string>;
    onStatus: (msg: string) => void;
    onResolve: (result: ConnectResult) => void;
  },
): Promise<ConnectResult> {
  let attempt = 0;
  let isReconnect = false;
  // Give up after this many consecutive failed attempts. With exponential
  // backoff (1s, 2s, 4s, 8s, 15s, 15s, ...) this is roughly 20 attempts
  // With exponential backoff (1s, 2s, 4s, 8s, 15s, 15s, ...) this is
  // roughly ~4 minutes of active retrying. System sleep does NOT count —
  // we only count actual attempts, and reset on successful connections.

  while (true) {
    const reason = await attemptConnect(wsUrl, parsed, store, session, {
      spawn: options.spawn,
      cwd: options.cwd,
      tags: options.tags,
      isReconnect,
      onStatus: options.onStatus,
    });

    log("bridge", "attempt ended", {
      session,
      attempt,
      isReconnect,
      reason: reason.kind,
      ...(reason.kind === "error" ? { message: reason.message } : {}),
      ...(reason.kind === "lost" ? { wasAttached: reason.wasAttached } : {}),
    });

    switch (reason.kind) {
      case "detached":
        return "detached";

      case "exited":
        return "exited";

      case "error":
        return { error: reason.message };

      case "lost": {
        // If we were attached (handshake succeeded, terminal was active),
        // reset the attempt counter. This means: sleep for 8 hours, wake
        // up, reconnect immediately — you get fresh retries because the
        // previous connection was working.
        if (reason.wasAttached) {
          attempt = 0;
        }

        if (attempt >= MAX_RECONNECT_ATTEMPTS) {
          log("bridge", "gave up reconnecting", { attempts: attempt });
          options.onStatus(`[gave up reconnecting after ${attempt} attempts]`);
          return "disconnected";
        }

        const delay = reconnectDelay(attempt);
        const delaySec = Math.round(delay / 1000);
        log("bridge", "scheduling reconnect", { attempt, delayMs: delay });
        options.onStatus(
          `[disconnected — reconnecting in ${delaySec}s... ctrl+\\ to detach]`
        );

        // Wait for the backoff delay, but allow Ctrl+\ to interrupt
        const interrupted = await interruptibleSleep(delay);
        if (interrupted) {
          return "detached";
        }

        attempt++;
        isReconnect = true;
        // Loop continues — will create a fresh connection + handshake
        break;
      }
    }
  }
}

/**
 * Embedded connect — returns a Promise that resolves when the session ends.
 * Unlike the standalone `connect()`, this does NOT call `process.exit`.
 * Designed for use inside the interactive TUI's pause/resume loop.
 *
 * Automatically reconnects on connection loss with exponential backoff.
 * Gives up after 5 minutes of failed retries.
 */
export async function connectEmbedded(
  tokenUrl: string,
  options: { spawn?: string; cwd?: string; store: SecretStore }
): Promise<ConnectResult> {
  await ready();
  log("cli", "connect embedded begin", { spawn: options.spawn, cwd: options.cwd });

  const parsed = parseToken(tokenUrl);
  const secretHash = computeSecretHash(parsed.secret);
  const wsUrl = getWebSocketUrl(parsed.host, "client", secretHash, undefined, parsed.clientToken ?? undefined);

  // Save this host for the interactive TUI
  const baseUrl = createToken(parsed.host, parsed.publicKey, parsed.secret, undefined, parsed.clientToken ?? undefined);
  await saveKnownHost(parsed.host, baseUrl, options.store);

  const session = options.spawn || parsed.session!;

  // Scoped SIGINT handler — detach immediately without reconnect
  let sigintResolve: ((result: ConnectResult) => void) | null = null;
  function sigintHandler(): void {
    process.stdout.write("\r\n[detached]\r\n");
    if (sigintResolve) sigintResolve("detached");
  }
  process.on("SIGINT", sigintHandler);

  const result = await connectWithReconnect(wsUrl, parsed, options.store, session, {
    spawn: options.spawn,
    cwd: options.cwd,
    onStatus: (msg: string) => {
      process.stdout.write(`\r\n${msg}\r\n`);
    },
    onResolve: () => {},
  });

  process.removeListener("SIGINT", sigintHandler);
  return result;
}

/**
 * Direct attach — session is known, stdin is clean.
 * Automatically reconnects on connection loss with exponential backoff.
 * Gives up after 5 minutes of failed retries.
 */
function attachSession(
  wsUrl: string,
  parsed: ReturnType<typeof parseToken>,
  store: SecretStore,
  options?: { spawn?: string; cwd?: string; tags?: Record<string, string>; configDir?: string },
): void {
  const session = options?.spawn || parsed.session!;

  process.on("SIGINT", () => {
    process.stdout.write("\r\n[detached]\r\n");
    process.exit(0);
  });

  connectWithReconnect(wsUrl, parsed, store, session, {
    spawn: options?.spawn,
    cwd: options?.cwd,
    tags: options?.tags,
    onStatus: (msg: string) => {
      process.stdout.write(`\r\n${msg}\r\n`);
    },
    onResolve: () => {},
  }).then((result) => {
    switch (result) {
      case "detached":
        process.exit(0);
        break;
      case "exited":
        process.exit(0);
        break;
      case "disconnected":
        process.stderr.write("\nFailed to reconnect after 5 minutes.\n");
        process.exit(1);
        break;
      default:
        // error case: result is { error: string }
        if (typeof result === "object" && result.error) {
          process.stderr.write(`\nError: ${result.error}\n`);
        }
        process.exit(1);
        break;
    }
  });
}
