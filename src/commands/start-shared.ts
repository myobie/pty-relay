import { SessionBridge } from "../relay/session-bridge.ts";
import {
  listSessions,
  getSession,
  peekScreen,
  sendData,
  updateTags,
  validateName,
  EventFollower,
} from "@myobie/pty/client";
import { execFileSync } from "node:child_process";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs";
import { log as vlog } from "../log.ts";

/**
 * Shared pty-session vocabulary for both the self-hosted and public-mode
 * `start` commands. Each daemon keeps its own transport/primary setup
 * and its own "hello" handler (the self-hosted one backfills approval-
 * token labels; public-mode doesn't need any of that). When a control
 * message comes in, each daemon dispatches its transport-specific cases
 * first, then hands the rest off here.
 *
 * Handled types: list, attach, peek, send, tag, events_subscribe, spawn
 * (when options.allowNewSessions). Returns true if the type was
 * handled; false if the caller should try something else.
 *
 * The handler mutates `cs.bridge`, `cs.eventsFollower`, and
 * `cs.eventsHeartbeat` in place. Callers must declare these fields
 * mutable on their ClientSession type.
 */

/** Tag keys that pty treats as SUPERVISOR CONTROL rather than metadata.
 *  Remote clients must not be able to set these via `tag` or `spawn` —
 *  see src/commands/start.ts for the threat model. */
const RESERVED_TAG_KEYS = new Set([
  "strategy",
  "supervisor.status",
  "ptyfile",
  "ptyfile.session",
  "ptyfile.tags",
]);

/** Heartbeat cadence for event subscriptions. */
const EVENTS_HEARTBEAT_MS = 30_000;

export interface SharedClientSession {
  connection: { send(bytes: Uint8Array): void; isReady?: () => boolean };
  bridge: SessionBridge | null;
  eventsFollower?: EventFollower;
  eventsHeartbeat?: ReturnType<typeof setInterval>;
}

export interface SharedHandlerOptions {
  allowNewSessions?: boolean;
  /** Optional log prefix used for operator-visible messages. Both daemons
   *  log "Client <id>: ..." in their own format; the shared handler
   *  only emits informative side-info via this callback. */
  log?: (msg: string) => void;
}

/** Dispatch a pre-parsed control message against the shared vocabulary.
 *  Returns true if the type was recognized and handled. */
export function handleSessionControlMessage(
  msg: Record<string, unknown>,
  cs: SharedClientSession,
  clientId: string,
  options: SharedHandlerOptions = {}
): boolean {
  const reply = (payload: Record<string, unknown>) => {
    try {
      cs.connection.send(new TextEncoder().encode(JSON.stringify(payload)));
    } catch {
      // Connection torn down mid-response; nothing to do. Specific late
      // callbacks (peek polling, events) call this from async paths so
      // the throw protection keeps unhandled rejections out of logs.
    }
  };
  const replyError = (message: string) => reply({ type: "error", message });
  const type = msg.type;
  vlog("serve", "control message", {
    clientId,
    type: typeof type === "string" ? type : typeof type,
    session: typeof msg.session === "string" ? msg.session : undefined,
    // attach/spawn carry cols+rows; logging them makes resize bugs
    // visible without browser-side instrumentation.
    cols: typeof msg.cols === "number" ? msg.cols : undefined,
    rows: typeof msg.rows === "number" ? msg.rows : undefined,
  });

  if (type === "list") {
    if (cs.bridge?.isConnected()) cs.bridge.close();
    listSessions().then((sessions) => {
      reply({
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
        spawn_enabled: !!options.allowNewSessions,
      });
    });
    return true;
  }

  if (type === "attach" && typeof msg.session === "string") {
    const session = msg.session;
    try {
      validateName(session);
    } catch {
      replyError("invalid session name");
      return true;
    }
    if (cs.bridge?.isConnected()) cs.bridge.close();
    // The SessionBridge constructor expects the real RelayConnection type.
    // SharedClientSession's `connection` is typed loosely here so both
    // daemons can plug in compatible objects; cast at construction time.
    cs.bridge = new SessionBridge(cs.connection as any);
    cs.bridge
      .attach(session, (msg.cols as number) || 80, (msg.rows as number) || 24)
      .then(() => {
        options.log?.(`Client ${clientId}: bridging session "${session}"`);
        reply({ type: "attached" });
      })
      .catch(() => replyError(`Session "${session}" not found`));
    return true;
  }

  if (type === "peek" && typeof msg.session === "string") {
    const session = msg.session;
    try {
      validateName(session);
    } catch {
      replyError("invalid session name");
      return true;
    }
    const plain = !!msg.plain;
    const full = !!msg.full;
    const waitPatterns: string[] = Array.isArray(msg.wait)
      ? (msg.wait as unknown[]).filter(
          (p): p is string => typeof p === "string" && p.length > 0
        )
      : [];
    const timeoutMs =
      typeof msg.timeoutSec === "number" && msg.timeoutSec > 0
        ? (msg.timeoutSec as number) * 1000
        : 0;

    if (waitPatterns.length === 0) {
      peekScreen({ name: session, plain, full })
        .then((screen) => reply({ type: "peek_result", screen }))
        .catch((err: Error) => replyError(err.message));
      return true;
    }

    // Polling wait loop — mirrors pty's local `peek --wait` at 200ms.
    const start = Date.now();
    const matchesAny = (text: string) => waitPatterns.some((p) => text.includes(p));
    const pollOnce = async () => {
      if (timeoutMs > 0 && Date.now() - start > timeoutMs) {
        replyError(
          `timed out after ${(timeoutMs / 1000).toFixed(1)}s waiting for pattern`
        );
        return;
      }
      try {
        const plainScreen = await peekScreen({ name: session, plain: true, full });
        if (matchesAny(plainScreen)) {
          if (plain) {
            reply({ type: "peek_result", screen: plainScreen });
          } else {
            const ansi = await peekScreen({ name: session, plain: false, full });
            reply({ type: "peek_result", screen: ansi });
          }
          return;
        }
      } catch (err: any) {
        replyError(err?.message || "peek failed");
        return;
      }
      setTimeout(pollOnce, 200);
    };
    pollOnce();
    return true;
  }

  if (type === "send" && typeof msg.session === "string" && Array.isArray(msg.data)) {
    const session = msg.session;
    try {
      validateName(session);
    } catch {
      replyError("invalid session name");
      return true;
    }
    const data = (msg.data as unknown[]).filter(
      (d): d is string => typeof d === "string"
    );
    const delayMs =
      typeof msg.delayMs === "number" && (msg.delayMs as number) >= 0
        ? (msg.delayMs as number)
        : undefined;
    const paste = msg.paste === true;
    sendData({ name: session, data, delayMs, paste })
      .then(() => reply({ type: "send_ok" }))
      .catch((err: Error) => replyError(err.message));
    return true;
  }

  if (type === "tag" && typeof msg.session === "string") {
    const session = msg.session;
    try {
      validateName(session);
    } catch {
      replyError("invalid session name");
      return true;
    }
    const updates: Record<string, string> = {};
    if (msg.set && typeof msg.set === "object") {
      for (const [k, v] of Object.entries(msg.set as Record<string, unknown>)) {
        if (typeof v === "string" && !RESERVED_TAG_KEYS.has(k)) updates[k] = v;
      }
    }
    const removals: string[] = [];
    if (Array.isArray(msg.remove)) {
      for (const k of msg.remove as unknown[]) {
        if (typeof k === "string" && !RESERVED_TAG_KEYS.has(k)) removals.push(k);
      }
    }
    try {
      if (Object.keys(updates).length > 0 || removals.length > 0) {
        updateTags(session, updates, removals);
      }
      getSession(session)
        .then((info) =>
          reply({ type: "tag_result", tags: info?.metadata?.tags ?? {} })
        )
        .catch((err: Error) => replyError(err.message));
    } catch (err: any) {
      replyError(err?.message ?? "tag failed");
    }
    return true;
  }

  if (type === "events_subscribe") {
    if (cs.eventsHeartbeat) clearInterval(cs.eventsHeartbeat);
    if (cs.eventsFollower) cs.eventsFollower.stop();

    (async () => {
      try {
        const all = await listSessions();
        reply({
          type: "events_snapshot",
          sessions: all
            .filter((s) => s.status === "running")
            .map((s) => ({
              name: s.name,
              status: s.status,
              displayName: s.metadata?.displayName,
              command: s.metadata?.displayCommand,
              cwd: s.metadata?.cwd,
              tags: s.metadata?.tags,
            })),
        });

        const follower = new EventFollower({
          onEvent: (event) => {
            try {
              reply({ type: "event", event });
            } catch {
              follower.stop();
            }
          },
        });
        follower.start();
        cs.eventsFollower = follower;
        cs.eventsHeartbeat = setInterval(() => {
          try {
            reply({ type: "event_ping" });
          } catch {
            if (cs.eventsHeartbeat) clearInterval(cs.eventsHeartbeat);
            cs.eventsHeartbeat = undefined;
          }
        }, EVENTS_HEARTBEAT_MS);
        options.log?.(
          `Client ${clientId}: subscribed to events (${all.length} running)`
        );
      } catch (err: any) {
        replyError(err?.message ?? "events subscribe failed");
      }
    })();
    return true;
  }

  if (type === "spawn" && options.allowNewSessions) {
    const name = String(msg.name || `remote-${Date.now()}`);
    const cols = (msg.cols as number) || 80;
    const rows = (msg.rows as number) || 24;
    const shell = process.env.SHELL || "/bin/bash";
    try {
      validateName(name);
    } catch {
      replyError("invalid session name");
      return true;
    }

    // Remote-proposed cwd must resolve to the operator's HOME or a
    // subdirectory of it. Matches self-hosted start.ts's original
    // containment check verbatim.
    const home = process.env.HOME || os.homedir();
    let cwd = home;
    if (msg.cwd) {
      try {
        const resolved = fs.realpathSync(String(msg.cwd));
        const resolvedHome = fs.realpathSync(home);
        const contained =
          resolved === resolvedHome ||
          resolved.startsWith(resolvedHome + path.sep);
        if (!contained) {
          replyError(`cwd must be inside ${home}`);
          return true;
        }
        cwd = resolved;
      } catch {
        replyError("cwd does not exist");
        return true;
      }
    }

    // --tag args, with the same reserved-key deny-list used for `tag` above.
    const tagArgs: string[] = [];
    if (msg.tags && typeof msg.tags === "object") {
      for (const [k, v] of Object.entries(msg.tags as Record<string, unknown>)) {
        if (typeof v !== "string" || k.includes("=")) continue;
        if (RESERVED_TAG_KEYS.has(k)) {
          options.log?.(
            `Dropping reserved tag key "${k}" from remote spawn by client ${clientId}`
          );
          continue;
        }
        tagArgs.push("--tag", `${k}=${v}`);
      }
    }

    getSession(name).then(async (existing) => {
      if (existing && existing.status === "running") {
        replyError(`Session "${name}" already exists`);
        return;
      }
      try {
        execFileSync(
          "pty",
          [
            "run",
            "-d",
            "--isolate-env",
            "--no-display-name",
            "--name",
            name,
            ...tagArgs,
            "--",
            shell,
          ],
          { timeout: 5000, cwd }
        );
        if (cs.bridge?.isConnected()) cs.bridge.close();
        cs.bridge = new SessionBridge(cs.connection as any);
        await cs.bridge.attach(name, cols, rows);
        options.log?.(
          `Spawned and bridging session "${name}" for client ${clientId}`
        );
        reply({ type: "spawned", session: name });
        reply({ type: "attached" });
      } catch (err: any) {
        replyError(`Failed to spawn: ${err?.message ?? err}`);
      }
    });
    return true;
  }

  if (type === "spawn" && !options.allowNewSessions) {
    replyError(
      "Spawn not enabled. Run start with `--allow-new-sessions`."
    );
    return true;
  }

  return false;
}

/** Teardown helper shared by both daemons. Closes the bridge, stops the
 *  events follower, and clears the heartbeat. Safe to call twice. */
export function teardownSharedClient(cs: SharedClientSession): void {
  vlog("serve", "teardown shared client", {
    hadBridge: !!cs.bridge,
    hadEventsFollower: !!cs.eventsFollower,
    hadHeartbeat: !!cs.eventsHeartbeat,
  });
  if (cs.bridge) {
    cs.bridge.close();
    cs.bridge = null;
  }
  if (cs.eventsHeartbeat) {
    clearInterval(cs.eventsHeartbeat);
    cs.eventsHeartbeat = undefined;
  }
  if (cs.eventsFollower) {
    cs.eventsFollower.stop();
    cs.eventsFollower = undefined;
  }
}
