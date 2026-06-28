/**
 * Daemon-side handler for `channel_open` / `channel_close` control
 * messages. Owned by both daemons (self-hosted + public-mode) so they
 * land on the same gate before the per-mode bridge construction.
 *
 * Today this is responsible for:
 *   - validating the `--allow-exec` daemon flag,
 *   - checking argv[0] against the compile-time allow-list,
 *   - constructing + registering an ExecBridge,
 *   - replying with `channel_open_ack` or `channel_open_error`,
 *   - tearing down on `channel_close`.
 *
 * It does NOT handle `mode:"pty"` here yet — the v1 attach RPC still
 * carries pty channel setup, and it lives on the implicit
 * DEFAULT_PTY_CHANNEL_ID. Migrating pty to channel_open is a follow-up.
 */

import type { ChannelConnection } from "./channel-connection.ts";
import {
  ExecBridge,
  realSpawn,
  type SpawnFn,
  type ExecChild,
} from "./exec-bridge.ts";
import { checkArgvAllowed } from "./exec-allow-list.ts";
import {
  ChannelOpenError,
  type ChannelHandler,
} from "./channel-registry.ts";
import type {
  ControlMessage,
  ChannelOpenExec,
} from "./channel-control.ts";
import { log } from "../log.ts";

export interface ChannelOpenOptions {
  /** Daemon flag controlling whether exec channels are accepted at
   *  all. Off by default. */
  allowExec: boolean;
  /** Override the real spawn fn (tests). Production callers omit and
   *  get `realSpawn` (wrapping `child_process.spawn`). */
  spawnFn?: SpawnFn;
}

/**
 * Route an incoming channel-lifecycle ControlMessage. Returns `true` if
 * the message was handled (so the dispatcher's `onControlMessage`
 * callback knows there's nothing more to do).
 *
 * Out of scope here:
 *   - channel_open_ack / channel_open_error — replies *from* the daemon,
 *     never arrive *at* the daemon.
 *   - channel_exit — daemon → client only.
 *   - keepalive — no-op (caller may want to extend lifetime tracking).
 */
export function handleChannelOpenControl(
  channel: ChannelConnection,
  msg: ControlMessage,
  opts: ChannelOpenOptions,
): boolean {
  switch (msg.type) {
    case "channel_open":
      handleChannelOpen(channel, msg, opts);
      return true;
    case "channel_close":
      channel.registry.close(msg.id, msg.reason);
      return true;
    case "keepalive":
      // Caller can layer their own keepalive tracking on top.
      return true;
    case "channel_open_ack":
    case "channel_open_error":
    case "channel_exit":
    case "error":
      // Daemon-bound side of these is meaningless in v1; ignore.
      return true;
  }
}

function handleChannelOpen(
  channel: ChannelConnection,
  msg: ControlMessage & { type: "channel_open" },
  opts: ChannelOpenOptions,
): void {
  if (msg.mode === "exec") {
    openExecChannel(channel, msg, opts);
    return;
  }

  // Pty mode via channel_open isn't wired yet — the v1 attach RPC
  // still owns DEFAULT_PTY_CHANNEL_ID. Reply with a structured error
  // so future-clients know to fall back.
  channel.sendApp({
    type: "channel_open_error",
    id: msg.id,
    code: "mode_not_enabled",
    message:
      "pty-mode channel_open isn't wired yet; use the v1 attach RPC on DEFAULT_PTY_CHANNEL_ID",
  });
}

function openExecChannel(
  channel: ChannelConnection,
  msg: ChannelOpenExec,
  opts: ChannelOpenOptions,
): void {
  if (!opts.allowExec) {
    log("exec", "channel_open rejected: --allow-exec not set", {
      id: msg.id,
      argv0: msg.argv[0],
    });
    channel.sendApp({
      type: "channel_open_error",
      id: msg.id,
      code: "mode_not_enabled",
      message: "exec mode not enabled on this daemon",
    });
    return;
  }

  const allowed = checkArgvAllowed(msg.argv[0]);
  if (!allowed) {
    log("exec", "channel_open rejected: argv not allowed", {
      id: msg.id,
      argv0: msg.argv[0],
    });
    channel.sendApp({
      type: "channel_open_error",
      id: msg.id,
      code: "argv_not_allowed",
      message: `argv[0] '${msg.argv[0]}' not in exec allow-list`,
    });
    return;
  }

  const spawnFn = opts.spawnFn ?? realSpawn;
  const channelId = msg.id;
  const bridge = new ExecBridge(
    channelId,
    // sendData — wraps in this channel's DATA frame and ships.
    (payload) => {
      try {
        channel.sendChannelData(channelId, payload);
      } catch (err) {
        log("exec", "outbound DATA send failed", {
          channelId,
          error: (err as Error)?.message,
        });
      }
    },
    (m) => channel.sendApp(m),
    spawnFn,
    {
      argv: msg.argv,
      env: msg.env ?? undefined,
      cwd: msg.cwd ?? undefined,
    },
  );

  try {
    channel.registry.open(channelId, bridge as ChannelHandler);
  } catch (err) {
    if (err instanceof ChannelOpenError) {
      channel.sendApp({
        type: "channel_open_error",
        id: channelId,
        code: err.code,
        message: err.message,
      });
      return;
    }
    throw err;
  }

  try {
    bridge.start();
  } catch (err) {
    // Synchronous spawn failure (e.g. ENOENT before the child even
    // exists). Roll back the registration and reply with
    // channel_open_error.
    channel.registry.close(channelId, "spawn_failed");
    channel.sendApp({
      type: "channel_open_error",
      id: channelId,
      code: "spawn_failed",
      message: (err as Error)?.message ?? "spawn failed",
    });
    return;
  }

  log("exec", "channel_open accepted", {
    channelId,
    argv0: allowed,
  });
  channel.sendApp({ type: "channel_open_ack", id: channelId });
}

// Re-export the type so the daemon glue can name it without an extra
// import. Mostly cosmetic but keeps server/start.ts clean.
export type { ExecChild };
