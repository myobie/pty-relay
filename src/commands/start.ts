import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs";
import { defaultConfigDir } from "../storage/bootstrap.ts";
import { createRelayServer } from "../serve/server.ts";
import { loadDaemonConfig, getTokenUrl, loadLabel } from "../relay/config.ts";
import { PrimaryRelayConnection } from "../relay/primary-connection.ts";
import { RelayConnection } from "../relay/relay-connection.ts";
import { SessionBridge } from "../relay/session-bridge.ts";
import { ClientTracker } from "../relay/client-tracker.ts";
import { EventFollower } from "@myobie/pty/client";
import { execFileSync, execSync, spawn as childSpawn } from "node:child_process";
import type { Config } from "../crypto/index.ts";
import {
  loadClients,
  updateClients,
  findTokenByExactId,
  generateTokenId,
  saveDaemonPid,
  type ClientsData,
} from "../relay/clients.ts";
import { sanitizeRemoteString } from "../sanitize.ts";
import { handleSessionControlMessage } from "./start-shared.ts";
import { log } from "../log.ts";

const MAX_CLIENTS = 10;
/** Cap on simultaneously-pending approvals. Without this, a scripted
 *  connect-disconnect loop from someone with the base token can bloat
 *  the encrypted clients.json file and flood the operator's TUI until
 *  each entry individually times out at PENDING_TIMEOUT_MS. */
const MAX_PENDING_CLIENTS = 20;
const PENDING_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

interface ClientSession {
  connection: RelayConnection;
  bridge: SessionBridge | null;
  tracker: ClientTracker;
  tokenId: string | null;
  /** Per-client resources created during the session (events subscriptions,
   *  etc.) that must be torn down when the client disconnects. */
  eventsFollower?: EventFollower;
  eventsHeartbeat?: ReturnType<typeof setInterval>;
}

/** Heartbeat cadence for event subscriptions. Idle ticks keep the
 *  tunnel alive and let the client notice a half-open connection
 *  without waiting for TCP keepalives. */
const EVENTS_HEARTBEAT_MS = 30_000;

interface PendingClient {
  clientId: string;
  tokenId: string;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * Self-hosted relay: runs the relay server and daemon in one process.
 * No auth, no database, no email. For local networks.
 */
export async function start(
  port: number,
  configDir?: string,
  options?: {
    allowNewSessions?: boolean;
    tailscale?: boolean;
    autoApprove?: boolean;
    passphraseFile?: string;
    bind?: string;
  }
): Promise<void> {
  log("cli", "local start begin", {
    port,
    configDir,
    tailscale: !!options?.tailscale,
    autoApprove: !!options?.autoApprove,
    allowNewSessions: !!options?.allowNewSessions,
    bind: options?.bind,
  });
  const relay = `localhost:${port}`;
  const { config, secretHash, store } = await loadDaemonConfig(
    relay,
    configDir,
    { interactive: true, passphraseFile: options?.passphraseFile }
  );
  const label = (await loadLabel(store)) || os.hostname();
  const autoApprove = options?.autoApprove ?? false;

  // Start the relay server, serving the web UI from the bundled browser client
  const htmlPath = path.resolve(import.meta.dirname, "../../browser/dist/index.html");
  const server = createRelayServer(port, htmlPath, options?.bind);
  await server.start();

  const tokenUrl = getTokenUrl(relay, config);

  if (options?.allowNewSessions) {
    console.warn("WARNING: --allow-new-sessions is enabled. Remote clients can start new sessions on this machine.");
  }

  if (!autoApprove) {
    console.log("Client approval enabled. Use --auto-approve to skip.");
  }

  const boundHost = options?.bind ?? "0.0.0.0";
  console.log(`Self-hosted relay running on ${boundHost}:${port}`);
  console.log(`Token URL: ${tokenUrl}`);

  // Tailscale HTTPS support
  if (options?.tailscale) {
    const tsUrl = await setupTailscale(port, config);
    if (tsUrl) {
      console.log(`Tailscale: ${tsUrl}`);
      printQrCode(tsUrl);
    }
  }

  // Write the PID file in every mode, not just approval mode. The
  // approval TUI uses it to signal the daemon, and `local status`
  // uses it to detect whether the daemon is running — both need it
  // regardless of --auto-approve.
  const cleanupPid: (() => void) | null = saveDaemonPid(configDir);

  if (!autoApprove) {
    // Clear stale pending entries on startup (their client_ids are from old connections)
    await updateClients(store, (startupData) => {
      for (const token of startupData.tokens) {
        if (token.status === "pending") {
          token.status = "revoked";
          token.revoked_at = new Date().toISOString();
          token.client_id = null;
        }
      }
    });
  }

  // Per-client session map
  const clients = new Map<string, ClientSession>();
  // Pending clients waiting for approval
  const pendingClients = new Map<string, PendingClient>();

  function makeControlMessageHandler(
    clientId: string,
    getClientSession: () => ClientSession | undefined
  ): (plaintext: Uint8Array) => boolean {
    return function handleControlMessage(plaintext: Uint8Array): boolean {
      if (plaintext.length === 0 || plaintext[0] !== 0x7b) return false;

      const cs = getClientSession();
      if (!cs) return false;

      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(new TextDecoder().decode(plaintext));
      } catch {
        return false;
      }

      // Latency reports from the web UI's tracker. The browser sends
      // a structured payload every 30s with keystroke samples + WS
      // frame stats. We append one JSONL line per report to
      // <configDir>/latency.jsonl so an operator can `tail -f` the
      // file or post-process it offline. Best-effort: a failed write
      // never breaks the session.
      //
      // Rotation: when latency.jsonl crosses LATENCY_LOG_MAX_BYTES,
      // rename it to latency.jsonl.old (overwriting any prior .old)
      // and start fresh. Caps disk use at ~2x that limit. Heavy
      // typing = ~500KB/hr; 10MB ≈ 20 hours of active data, plenty
      // for a debugging session.
      if (msg.type === "latency_report") {
        const dir = configDir ?? defaultConfigDir();
        const file = path.join(dir, "latency.jsonl");
        const line = JSON.stringify({
          ts: new Date().toISOString(),
          clientId,
          ...msg,
        }) + "\n";
        appendLatencyLine(file, line);
        return true;
      }

      // Self-hosted-specific: hello's side effect is backfilling the
      // operator-approval token's label in clients.json so the TUI can
      // show "iPhone (web)" instead of a truncated id next time the
      // operator opens `pty-relay clients`.
      if (msg.type === "hello") {
        cs.tracker.setClient(msg);
        const meta = cs.tracker.getClient();
        if (meta) console.log(`Client ${clientId}: ${meta.client} on ${meta.os}`);
        if (cs.tokenId) {
          const capturedTokenId = cs.tokenId;
          (async () => {
            try {
              await updateClients(store, (data) => {
                const token = data.tokens.find((t) => t.id === capturedTokenId);
                if (token && token.label === null) {
                  // Strip C0/C1/DEL from remote-supplied strings so a
                  // malicious label can't forge text or escape sequences
                  // when the operator opens `pty-relay clients` later.
                  const helloLabel = sanitizeRemoteString(String(msg.label ?? ""), 64) || "unknown";
                  const kind = sanitizeRemoteString(String(msg.client ?? ""), 32) || "client";
                  token.label = `${helloLabel} (${kind})`;
                }
              });
            } catch {
              // Best-effort; don't break the connection if we can't save.
            }
          })();
        }
        return true;
      }

      // Shared session vocabulary — everything else the self-hosted serve
      // handles. Mutates cs.bridge / cs.eventsFollower / cs.eventsHeartbeat.
      return handleSessionControlMessage(msg, cs, clientId, {
        allowNewSessions: options?.allowNewSessions,
        log: (m) => console.log(m),
      });
    };
  }

  function teardownClient(clientId: string): void {
    const cs = clients.get(clientId);
    if (!cs) return;
    if (cs.bridge) { cs.bridge.close(); cs.bridge = null; }
    // Stop any event-subscription fixtures: otherwise inotify/FSWatchers
    // and the heartbeat interval leak for every disconnected subscriber.
    if (cs.eventsHeartbeat) { clearInterval(cs.eventsHeartbeat); cs.eventsHeartbeat = undefined; }
    if (cs.eventsFollower) { cs.eventsFollower.stop(); cs.eventsFollower = undefined; }
    cs.connection.close();
    clients.delete(clientId);
    console.log(`Client ${clientId} disconnected. (${clients.size} active)`);
  }

  function teardownAllClients(): void {
    for (const [clientId] of clients) {
      teardownClient(clientId);
    }
  }

  /** Open a per-client connection and start the Noise handshake. */
  function openClientConnection(clientId: string, tokenId?: string): void {
    const perClientUrl = `ws://localhost:${port}/ws?role=daemon&secret_hash=${secretHash}&client_id=${clientId}`;

    const tracker = new ClientTracker();
    const handleControl = makeControlMessageHandler(
      clientId,
      () => clients.get(clientId)
    );

    const connection = new RelayConnection(perClientUrl, config, {
      onConnected: () => {},

      onPaired: (_meta) => {
        console.log(`Client ${clientId} paired.`);
      },

      onHandshakeComplete: () => {
        // If the client was approved with a token, send it inside the encrypted tunnel
        const cs = clients.get(clientId);
        if (cs?.tokenId) {
          cs.connection.send(new TextEncoder().encode(
            JSON.stringify({ type: "approved", client_token: cs.tokenId })
          ));
        }
      },

      onEncryptedMessage: (plaintext: Uint8Array) => {
        if (handleControl(plaintext)) return;
        const cs = clients.get(clientId);
        if (cs?.bridge?.isConnected()) {
          cs.bridge.handleRelayData(plaintext);
        }
      },

      onPeerDisconnected: () => {
        teardownClient(clientId);
      },

      onError: (err: Error) => {
        console.error(`Client ${clientId} error:`, err.message);
      },

      onClose: () => {
        teardownClient(clientId);
      },
    });

    clients.set(clientId, { connection, bridge: null, tracker, tokenId: tokenId ?? null });
    connection.connect();
  }

  /** Approve a pending client: clear timeout, open connection. */
  function approveClient(tokenId: string): void {
    // Find the pending entry by tokenId
    let pendingEntry: PendingClient | undefined;
    for (const [, p] of pendingClients) {
      if (p.tokenId === tokenId) {
        pendingEntry = p;
        break;
      }
    }
    if (!pendingEntry) return;

    clearTimeout(pendingEntry.timer);
    pendingClients.delete(pendingEntry.clientId);

    console.log(`Approved client ${pendingEntry.clientId} (token ${tokenId.slice(0, 8)})`);
    openClientConnection(pendingEntry.clientId, tokenId);
  }

  // SIGUSR1 handler: re-read clients.json and act on changes
  if (!autoApprove) {
    process.on("SIGUSR1", async () => {
      const data = await loadClients(store);

      // Check pending clients that became active (collect first to avoid mutation during iteration)
      const toApprove: string[] = [];
      for (const [clientId, pending] of pendingClients) {
        const token = findTokenByExactId(data, pending.tokenId);
        if (token && token.status === "active") {
          toApprove.push(pending.tokenId);
        }
      }
      for (const tokenId of toApprove) {
        approveClient(tokenId);
      }

      // Check connected clients whose tokens were revoked (collect first)
      const toRevoke: string[] = [];
      for (const [clientId, cs] of clients) {
        if (cs.tokenId) {
          const token = findTokenByExactId(data, cs.tokenId);
          if (token && token.status === "revoked") {
            toRevoke.push(clientId);
          }
        }
      }
      for (const clientId of toRevoke) {
        const cs = clients.get(clientId);
        if (cs) {
          console.log(`Token ${cs.tokenId?.slice(0, 8)} revoked, disconnecting client ${clientId}`);
          teardownClient(clientId);
        }
      }
    });
  }

  // Clean up PID file on exit
  process.on("exit", () => {
    if (cleanupPid) cleanupPid();
  });
  process.on("SIGINT", () => {
    if (cleanupPid) cleanupPid();
    process.exit(0);
  });

  // Primary daemon URL (no client_id, no auth for self-hosted)
  const primaryWsUrl = `ws://localhost:${port}/ws?role=daemon&secret_hash=${secretHash}&label=${encodeURIComponent(label)}`;

  const primary = new PrimaryRelayConnection(primaryWsUrl, {
    onConnected: () => {
      console.log("Primary control connection established.");
    },

    onClientWaiting: async (
      clientId: string,
      clientToken?: string,
      meta?: { remote_addr?: string | null; user_agent?: string | null; origin?: string | null }
    ) => {
      if (clients.size >= MAX_CLIENTS) {
        console.warn(`Rejecting client ${clientId}: max ${MAX_CLIENTS} reached`);
        primary.sendText(JSON.stringify({ type: "reject_client", client_id: clientId, reason: "max clients reached" }));
        return;
      }

      if (!autoApprove && pendingClients.size >= MAX_PENDING_CLIENTS) {
        console.warn(`Rejecting client ${clientId}: max ${MAX_PENDING_CLIENTS} pending approvals reached`);
        primary.sendText(JSON.stringify({ type: "reject_client", client_id: clientId, reason: "too many pending approvals" }));
        return;
      }

      // Auto-approve: skip all approval logic
      if (autoApprove) {
        console.log(`Client ${clientId} waiting, opening per-client connection...`);
        openClientConnection(clientId);
        return;
      }

      // Check if client has a pre-auth token
      if (clientToken) {
        const data = await loadClients(store);
        const token = findTokenByExactId(data, clientToken);
        if (token) {
          if (token.status === "active") {
            console.log(`Client ${clientId} authenticated with token ${clientToken.slice(0, 8)}`);
            openClientConnection(clientId, token.id);
            return;
          } else if (token.status === "revoked") {
            console.log(`Rejecting client ${clientId}: token ${clientToken.slice(0, 8)} is revoked`);
            primary.sendText(JSON.stringify({ type: "reject_client", client_id: clientId, reason: "token revoked" }));
            return;
          }
          // pending or not found: fall through to approval queue
        }
      }

      // No valid token: queue for approval
      const tokenId = generateTokenId();
      await updateClients(store, (data) => {
        data.tokens.push({
          id: tokenId,
          label: null,
          status: "pending",
          client_id: clientId,
          created: new Date().toISOString(),
          revoked_at: null,
          pending_meta: meta
            ? {
                // Sanitize before persisting: these strings are rendered
                // verbatim in the operator's approval TUI and log lines.
                remote_addr: meta.remote_addr ? sanitizeRemoteString(meta.remote_addr, 64) : null,
                user_agent: meta.user_agent ? sanitizeRemoteString(meta.user_agent, 256) : null,
                origin: meta.origin ? sanitizeRemoteString(meta.origin, 128) : null,
              }
            : undefined,
        });
      });

      // Tell the relay to hold the client (send waiting_for_approval)
      primary.sendText(JSON.stringify({ type: "hold_client", client_id: clientId }));

      // Set a 5-minute timeout
      const timer = setTimeout(async () => {
        pendingClients.delete(clientId);
        console.log(`Pending client ${clientId} timed out (token ${tokenId.slice(0, 8)})`);
        primary.sendText(JSON.stringify({ type: "reject_client", client_id: clientId, reason: "approval timed out" }));

        // Mark as revoked in clients.json
        await updateClients(store, (d) => {
          const t = findTokenByExactId(d, tokenId);
          if (t && t.status === "pending") {
            t.status = "revoked";
            t.revoked_at = new Date().toISOString();
            t.client_id = null;
          }
        });
      }, PENDING_TIMEOUT_MS);

      pendingClients.set(clientId, { clientId, tokenId, timer });

      const metaBits: string[] = [];
      if (meta?.remote_addr) metaBits.push(sanitizeRemoteString(meta.remote_addr, 64));
      if (meta?.user_agent) {
        // Truncate UA strings for the log line, and sanitize so a malicious
        // client can't smuggle terminal escape sequences into the operator's
        // console via the UA header.
        const safeUa = sanitizeRemoteString(meta.user_agent, 60);
        metaBits.push(safeUa);
      }
      const metaDesc = metaBits.length ? ` (${metaBits.join(", ")})` : "";
      console.log(
        `Client ${clientId} pending approval (token ${tokenId.slice(0, 8)})${metaDesc}`
      );
      console.log(`  Approve: pty-relay clients approve ${tokenId.slice(0, 8)}`);
    },

    onClientDisconnected: (clientId: string) => {
      // Clean up pending entry if the client disconnects before approval
      const pending = pendingClients.get(clientId);
      if (pending) {
        clearTimeout(pending.timer);
        pendingClients.delete(clientId);
      }
      teardownClient(clientId);
    },

    onError: (err: Error) => {
      console.error("Primary connection error:", err.message);
    },

    onClose: (code?: number) => {
      teardownAllClients();
      // Clear all pending timers
      for (const [, p] of pendingClients) {
        clearTimeout(p.timer);
      }
      pendingClients.clear();
      // Self-hosted: reconnect immediately to our own server
      setTimeout(() => primary.connect(), 500);
    },
  });

  primary.connect();
}

/**
 * Print a QR code for a URL via the `qrencode` CLI if it's installed.
 * Silently no-op if qrencode isn't available — the URL is still printed
 * right above, so the user always has a fallback.
 */
/** Cap on latency.jsonl size before rotation. Picked so an active
 *  debugging session (a few hours of typing) fits comfortably and
 *  the file never grows unbounded. ~500KB/hr of typing = ~20 hours
 *  of active data at this cap. The rotation is single-step (rename
 *  to .old, start fresh), so worst-case disk use is 2x. */
const LATENCY_LOG_MAX_BYTES = 10 * 1024 * 1024;

function appendLatencyLine(filePath: string, line: string): void {
  fs.stat(filePath, (statErr, stats) => {
    if (!statErr && stats && stats.size + line.length > LATENCY_LOG_MAX_BYTES) {
      // Rotate. fs.rename is atomic within the same dir; failures
      // (race with another rotator, missing old, etc.) are silent —
      // the worst case is the file briefly grows past the cap or
      // the next .old isn't written. Latency telemetry isn't
      // load-bearing.
      fs.rename(filePath, filePath + ".old", () => {
        fs.appendFile(filePath, line, () => {});
      });
      return;
    }
    fs.appendFile(filePath, line, () => {});
  });
}

function printQrCode(url: string): void {
  try {
    const result = execFileSync("qrencode", ["-t", "ANSIUTF8", "-m", "1", url], {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 2000,
    });
    if (result && result.length > 0) {
      process.stdout.write(result);
    }
  } catch {
    // qrencode not installed or failed — fine, the URL is already printed.
  }
}

function findTailscaleCli(): string | null {
  // Check PATH first (user may have an alias or symlink)
  try {
    execSync("tailscale version", { stdio: "ignore" });
    return "tailscale";
  } catch {}
  // macOS app location
  const macPath = "/Applications/Tailscale.app/Contents/MacOS/Tailscale";
  try {
    execSync(`"${macPath}" version`, { stdio: "ignore" });
    return macPath;
  } catch {}
  return null;
}

function getTailscaleDnsName(cli: string): string | null {
  try {
    const json = execSync(`"${cli}" status --self --json`, { encoding: "utf-8" });
    const data = JSON.parse(json);
    const dns = data?.Self?.DNSName;
    if (!dns) return null;
    // Remove trailing dot
    return dns.replace(/\.$/, "");
  } catch {
    return null;
  }
}

async function setupTailscale(port: number, config: Config): Promise<string | null> {
  const cli = findTailscaleCli();
  if (!cli) {
    console.error("Warning: --tailscale specified but tailscale CLI not found");
    return null;
  }

  const dnsName = getTailscaleDnsName(cli);
  if (!dnsName) {
    console.error("Warning: Could not get Tailscale DNS name. Is Tailscale running?");
    return null;
  }

  // Start tailscale serve in the foreground (as a child process)
  const tsServe = childSpawn(cli, ["serve", String(port)], {
    stdio: "ignore",
    detached: false,
  });

  tsServe.on("error", (err) => {
    console.error(`Tailscale serve error: ${err.message}`);
  });

  // Clean up on exit
  process.on("exit", () => {
    tsServe.kill();
    try { execSync(`"${cli}" serve reset`, { stdio: "ignore" }); } catch {}
  });
  process.on("SIGINT", () => {
    tsServe.kill();
    try { execSync(`"${cli}" serve reset`, { stdio: "ignore" }); } catch {}
    process.exit(0);
  });

  // Give it a moment to start
  await new Promise((r) => setTimeout(r, 1000));

  return getTokenUrl(dnsName, config);
}
