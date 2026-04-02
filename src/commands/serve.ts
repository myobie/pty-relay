import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs";
import { createRelayServer } from "../serve/server.ts";
import { loadDaemonConfig, getTokenUrl, loadLabel } from "../relay/config.ts";
import { PrimaryRelayConnection } from "../relay/primary-connection.ts";
import { RelayConnection } from "../relay/relay-connection.ts";
import { SessionBridge } from "../relay/session-bridge.ts";
import { ClientTracker } from "../relay/client-tracker.ts";
import {
  validateName,
  listSessions,
  getSession,
  peekScreen,
  sendData,
  updateTags,
  EventFollower,
} from "@myobie/pty/client";
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
export async function serve(
  port: number,
  configDir?: string,
  options?: {
    allowNewSessions?: boolean;
    tailscale?: boolean;
    autoApprove?: boolean;
    passphraseFile?: string;
  }
): Promise<void> {
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
  const server = createRelayServer(port, htmlPath);
  await server.start();

  const tokenUrl = getTokenUrl(relay, config);

  if (options?.allowNewSessions) {
    console.warn("WARNING: --allow-new-sessions is enabled. Remote clients can start new sessions on this machine.");
  }

  if (!autoApprove) {
    console.log("Client approval enabled. Use --auto-approve to skip.");
  }

  console.log(`Self-hosted relay running on port ${port}`);
  console.log(`Token URL: ${tokenUrl}`);

  // Tailscale HTTPS support
  if (options?.tailscale) {
    const tsUrl = await setupTailscale(port, config);
    if (tsUrl) {
      console.log(`Tailscale: ${tsUrl}`);
      printQrCode(tsUrl);
    }
  }

  // Write PID file for CLI signal communication
  let cleanupPid: (() => void) | null = null;
  if (!autoApprove) {
    cleanupPid = saveDaemonPid(configDir);

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

      try {
        const msg = JSON.parse(new TextDecoder().decode(plaintext));

        if (msg.type === "hello") {
          cs.tracker.setClient(msg);
          const meta = cs.tracker.getClient();
          if (meta) console.log(`Client ${clientId}: ${meta.client} on ${meta.os}`);

          // Backfill the label on the client's token in clients.json if
          // it's still unnamed. Uses the hello message's label with a
          // client-type suffix so an unnamed token becomes "iPhone (web)"
          // or "Silber.local (cli)" next time you run `pty-relay clients`.
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
                    const helloLabel = sanitizeRemoteString(msg.label, 64) || "unknown";
                    const kind = sanitizeRemoteString(msg.client, 32) || "client";
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

        if (msg.type === "list") {
          if (cs.bridge?.isConnected()) cs.bridge.close();
          listSessions().then((sessions) => {
            const response = JSON.stringify({
              type: "sessions",
              sessions: sessions
                .filter((s) => s.status === "running")
                .map((s) => ({
                  name: s.name,
                  status: s.status,
                  displayName: s.metadata?.displayName,
                  command: s.metadata?.displayCommand,
                  cwd: s.metadata?.cwd,
                  tags: s.metadata?.tags,
                })),
              spawn_enabled: !!options?.allowNewSessions,
            });
            cs.connection.send(new TextEncoder().encode(response));
          });
          return true;
        }

        if (msg.type === "attach" && msg.session) {
          const session = String(msg.session);
          try { validateName(session); } catch {
            cs.connection.send(new TextEncoder().encode(
              JSON.stringify({ type: "error", message: "invalid session name" })
            ));
            return true;
          }

          if (cs.bridge?.isConnected()) cs.bridge.close();
          cs.bridge = new SessionBridge(cs.connection);

          cs.bridge.attach(session, msg.cols || 80, msg.rows || 24)
            .then(() => {
              console.log(`Client ${clientId}: bridging session "${session}"`);
              cs.connection.send(new TextEncoder().encode(JSON.stringify({ type: "attached" })));
            })
            .catch((err: Error) => {
              cs.connection.send(new TextEncoder().encode(
                JSON.stringify({ type: "error", message: `Session "${session}" not found` })
              ));
            });
          return true;
        }

        // One-shot "peek": return the current screen contents of a session
        // as a single string. No bridge, no stdin — read-only snapshot.
        //
        // If `wait` is a non-empty array, poll the plain-text screen every
        // 200ms (mirroring pty's local `peek --wait`) and return the first
        // snapshot that matches ANY of the patterns. If `timeoutSec` is set
        // and elapses first, respond with an error. This matches pty local
        // behavior at pty/src/cli.ts:cmdPeekWait.
        if (msg.type === "peek" && msg.session) {
          const session = String(msg.session);
          try { validateName(session); } catch {
            cs.connection.send(new TextEncoder().encode(
              JSON.stringify({ type: "error", message: "invalid session name" })
            ));
            return true;
          }
          const plain = !!msg.plain;
          const full = !!msg.full;
          const waitPatterns: string[] = Array.isArray(msg.wait)
            ? msg.wait.filter((p: unknown): p is string => typeof p === "string" && p.length > 0)
            : [];
          const timeoutMs =
            typeof msg.timeoutSec === "number" && msg.timeoutSec > 0
              ? msg.timeoutSec * 1000
              : 0;

          // Send-helpers that no-op when the connection has already been
          // torn down. Otherwise a late-resolving peek would throw
          // "Not ready to send" into an unhandled rejection.
          const safeSend = (payload: Uint8Array) => {
            try { cs.connection.send(payload); } catch { /* client gone */ }
          };
          const sendPeek = (screen: string) => {
            safeSend(new TextEncoder().encode(
              JSON.stringify({ type: "peek_result", screen })
            ));
          };
          const sendPeekError = (message: string) => {
            safeSend(new TextEncoder().encode(
              JSON.stringify({ type: "error", message })
            ));
          };

          if (waitPatterns.length === 0) {
            peekScreen({ name: session, plain, full })
              .then(sendPeek)
              .catch((err: Error) => sendPeekError(err.message));
            return true;
          }

          // Polling wait loop. Runs at 200ms cadence like pty's local
          // `peek --wait`. Caps iterations by `timeoutMs` if provided.
          const start = Date.now();
          const matchesAny = (text: string) =>
            waitPatterns.some((p) => text.includes(p));

          const pollOnce = async () => {
            if (timeoutMs > 0 && Date.now() - start > timeoutMs) {
              sendPeekError(
                `timed out after ${(timeoutMs / 1000).toFixed(1)}s waiting for pattern`
              );
              return;
            }
            try {
              const plainScreen = await peekScreen({ name: session, plain: true, full });
              if (matchesAny(plainScreen)) {
                if (plain) {
                  sendPeek(plainScreen);
                } else {
                  const ansi = await peekScreen({ name: session, plain: false, full });
                  sendPeek(ansi);
                }
                return;
              }
            } catch (err: any) {
              // Session may have exited mid-poll; surface the error as-is.
              sendPeekError(err.message || "peek failed");
              return;
            }
            setTimeout(pollOnce, 200);
          };
          pollOnce();
          return true;
        }

        // One-shot "send": push an array of strings (optionally with a delay
        // between them) into a session's stdin. Mirrors `pty send <name>`.
        if (msg.type === "send" && msg.session) {
          const session = String(msg.session);
          try { validateName(session); } catch {
            cs.connection.send(new TextEncoder().encode(
              JSON.stringify({ type: "error", message: "invalid session name" })
            ));
            return true;
          }
          if (!Array.isArray(msg.data) || msg.data.some((d: unknown) => typeof d !== "string")) {
            cs.connection.send(new TextEncoder().encode(
              JSON.stringify({ type: "error", message: "send: data must be string[]" })
            ));
            return true;
          }
          const delayMs = typeof msg.delayMs === "number" && msg.delayMs >= 0 ? msg.delayMs : undefined;
          const paste = msg.paste === true;
          sendData({ name: session, data: msg.data, delayMs, paste })
            .then(() => {
              cs.connection.send(new TextEncoder().encode(
                JSON.stringify({ type: "send_ok" })
              ));
            })
            .catch((err: Error) => {
              cs.connection.send(new TextEncoder().encode(
                JSON.stringify({ type: "error", message: err.message })
              ));
            });
          return true;
        }

        // One-shot "tag": read or mutate a session's tags. Mirrors the
        // server-side spawn deny-list — remote clients must not be able to
        // set `strategy`, `supervisor.status`, or `ptyfile*` via tag writes
        // either, since those keys feed pty's supervisor and could convert
        // a normal session into a persistent foothold.
        if (msg.type === "tag" && msg.session) {
          const session = String(msg.session);
          try { validateName(session); } catch {
            cs.connection.send(new TextEncoder().encode(
              JSON.stringify({ type: "error", message: "invalid session name" })
            ));
            return true;
          }
          const RESERVED_TAG_KEYS = new Set([
            "strategy",
            "supervisor.status",
            "ptyfile",
            "ptyfile.session",
            "ptyfile.tags",
          ]);
          const updates: Record<string, string> = {};
          if (msg.set && typeof msg.set === "object") {
            for (const [k, v] of Object.entries(msg.set)) {
              if (typeof k !== "string" || typeof v !== "string") continue;
              if (RESERVED_TAG_KEYS.has(k)) {
                console.warn(`Dropping reserved tag key "${k}" from remote tag() by client ${clientId}`);
                continue;
              }
              updates[k] = v;
            }
          }
          const removals: string[] = [];
          if (Array.isArray(msg.remove)) {
            for (const k of msg.remove) {
              if (typeof k !== "string") continue;
              if (RESERVED_TAG_KEYS.has(k)) {
                console.warn(`Refusing to let remote client ${clientId} remove reserved tag key "${k}"`);
                continue;
              }
              removals.push(k);
            }
          }

          try {
            // updateTags is synchronous and throws if the session doesn't exist.
            // Skip the write if there's nothing to do (read-only tag()).
            if (Object.keys(updates).length > 0 || removals.length > 0) {
              updateTags(session, updates, removals);
            }
            getSession(session).then((info) => {
              cs.connection.send(new TextEncoder().encode(
                JSON.stringify({ type: "tag_result", tags: info?.metadata?.tags ?? {} })
              ));
            }).catch((err: Error) => {
              cs.connection.send(new TextEncoder().encode(
                JSON.stringify({ type: "error", message: err.message })
              ));
            });
          } catch (err: any) {
            cs.connection.send(new TextEncoder().encode(
              JSON.stringify({ type: "error", message: err.message || "tag failed" })
            ));
          }
          return true;
        }

        // Streaming "events_subscribe": snapshot the current session list,
        // then pipe every subsequent EventRecord over the encrypted tunnel
        // until the client disconnects. Mirrors pty's local EventFollower —
        // the consumer is expected to diff against the snapshot on each
        // (re)connect rather than rely on a monotonic cursor.
        if (msg.type === "events_subscribe") {
          // One subscription per client session. Silently replace any
          // previous one so a caller can resubscribe without a fresh WS.
          if (cs.eventsHeartbeat) clearInterval(cs.eventsHeartbeat);
          if (cs.eventsFollower) cs.eventsFollower.stop();

          const safeSend = (obj: unknown): boolean => {
            try {
              cs.connection.send(new TextEncoder().encode(JSON.stringify(obj)));
              return true;
            } catch {
              return false;
            }
          };

          (async () => {
            try {
              const all = await listSessions();
              const sessions = all
                .filter((s) => s.status === "running")
                .map((s) => ({
                  name: s.name,
                  status: s.status,
                  displayName: s.metadata?.displayName,
                  command: s.metadata?.displayCommand,
                  cwd: s.metadata?.cwd,
                  tags: s.metadata?.tags,
                }));
              if (!safeSend({ type: "events_snapshot", sessions })) return;

              const follower = new EventFollower({
                onEvent: (event) => {
                  if (!safeSend({ type: "event", event })) {
                    // Connection gone — stop this follower to avoid leaking
                    // FSWatchers on the host.
                    follower.stop();
                  }
                },
              });
              follower.start();
              cs.eventsFollower = follower;

              cs.eventsHeartbeat = setInterval(() => {
                if (!safeSend({ type: "event_ping" })) {
                  if (cs.eventsHeartbeat) clearInterval(cs.eventsHeartbeat);
                  cs.eventsHeartbeat = undefined;
                }
              }, EVENTS_HEARTBEAT_MS);

              console.log(`Client ${clientId}: subscribed to events (${sessions.length} running)`);
            } catch (err: any) {
              safeSend({ type: "error", message: err.message || "events subscribe failed" });
            }
          })();
          return true;
        }

        if (msg.type === "spawn" && options?.allowNewSessions) {
          const name = String(msg.name || `remote-${Date.now()}`);
          const cols = msg.cols || 80;
          const rows = msg.rows || 24;
          const shell = process.env.SHELL || "/bin/bash";

          try { validateName(name); } catch {
            cs.connection.send(new TextEncoder().encode(
              JSON.stringify({ type: "error", message: "invalid session name" })
            ));
            return true;
          }

          // Constrain remote-supplied cwd to the operator's HOME. Without this,
          // a client can request `cwd: "/etc"` / `/var/log` / someone else's
          // readable home, nudging the spawned shell toward sensitive files.
          // Not an escalation past "attach to a shell on this machine", but a
          // worthwhile narrowing of the remote-spawn surface.
          const home = process.env.HOME || os.homedir();
          let cwd: string;
          if (msg.cwd) {
            try {
              const resolved = fs.realpathSync(String(msg.cwd));
              const resolvedHome = fs.realpathSync(home);
              // Must be the home dir itself, or a path strictly inside it.
              const contained =
                resolved === resolvedHome ||
                resolved.startsWith(resolvedHome + path.sep);
              if (!contained) {
                cs.connection.send(new TextEncoder().encode(
                  JSON.stringify({ type: "error", message: `cwd must be inside ${home}` })
                ));
                return true;
              }
              cwd = resolved;
            } catch {
              cs.connection.send(new TextEncoder().encode(
                JSON.stringify({ type: "error", message: "cwd does not exist" })
              ));
              return true;
            }
          } else {
            cwd = home;
          }

          // Convert msg.tags (Record<string,string>) into repeated `--tag k=v` argv.
          // Reject any key containing `=` so the parser on the other side can't
          // be tricked into splitting at the wrong boundary.
          //
          // Also deny-list tag keys that pty treats as SUPERVISOR CONTROL rather
          // than user metadata. A remote client that sets these on a spawn could:
          //   • `strategy=permanent` → turn a one-shot remote session into a
          //     persistent foothold that pty's supervisor auto-restarts.
          //   • `ptyfile=/path` + `ptyfile.session=name` → on next restart,
          //     pty's supervisor re-reads that pty.toml and `/bin/sh -c`'s the
          //     `command` field — RCE if the attacker also controls any
          //     readable pty.toml on disk.
          // These keys MUST originate from the local machine (`pty up`, the
          // pty supervisor), never from an authenticated-but-untrusted remote.
          const RESERVED_TAG_KEYS = new Set([
            "strategy",
            "supervisor.status",
            "ptyfile",
            "ptyfile.session",
            "ptyfile.tags",
          ]);
          const tagArgs: string[] = [];
          if (msg.tags && typeof msg.tags === "object") {
            for (const [k, v] of Object.entries(msg.tags)) {
              if (typeof k !== "string" || typeof v !== "string" || k.includes("=")) continue;
              if (RESERVED_TAG_KEYS.has(k)) {
                console.warn(`Dropping reserved tag key "${k}" from remote spawn by client ${clientId}`);
                continue;
              }
              tagArgs.push("--tag", `${k}=${v}`);
            }
          }

          getSession(name).then(async (existing) => {
            if (existing && existing.status === "running") {
              cs.connection.send(new TextEncoder().encode(
                JSON.stringify({ type: "error", message: `Session "${name}" already exists` })
              ));
              return;
            }

            try {
              // `--isolate-env` scrubs the daemon's env down to a safe allow-list
              // before spawning the session child. Without it, whatever secrets
              // the operator's daemon process inherited (cloud tokens, SSH agent,
              // PTY_RELAY_PASSPHRASE, etc.) would leak into the remote shell.
              //
              // `--no-display-name` matches pty's new TUI default: the client
              // just hits Enter and gets a bare shell, then uses `pty rename` /
              // `pty exec` from inside to promote it into something richer.
              // Avoids the relay conjuring a cwd/command label the user never
              // asked for.
              execFileSync("pty", ["run", "-d", "--isolate-env", "--no-display-name", "--name", name, ...tagArgs, "--", shell], {
                timeout: 5000,
                cwd,
              });
              if (cs.bridge?.isConnected()) cs.bridge.close();
              cs.bridge = new SessionBridge(cs.connection);
              await cs.bridge.attach(name, cols, rows);
              console.log(`Spawned and bridging session "${name}" for client ${clientId}`);
              cs.connection.send(new TextEncoder().encode(
                JSON.stringify({ type: "spawned", session: name })
              ));
              cs.connection.send(new TextEncoder().encode(
                JSON.stringify({ type: "attached" })
              ));
            } catch (err: any) {
              cs.connection.send(new TextEncoder().encode(
                JSON.stringify({ type: "error", message: `Failed to spawn: ${err.message}` })
              ));
            }
          });
          return true;
        }

        if (msg.type === "spawn" && !options?.allowNewSessions) {
          cs.connection.send(new TextEncoder().encode(
            JSON.stringify({ type: "error", message: "Spawn not enabled. Run 'pty-relay serve --allow-new-sessions'." })
          ));
          return true;
        }

      } catch {}
      return false;
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

      onPaired: () => {
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
