/**
 * Channel 0 (connection control) message schemas + a pure parser.
 *
 * Every channel-0 frame's payload is UTF-8 JSON. This module owns the
 * type discriminator + validation; the dispatcher hands raw payload
 * bytes to `parseControlMessage` and gets back either a typed message
 * or a structured error code suitable for an `error`-on-channel-0
 * response. No I/O.
 *
 * See `docs/channel-protocol.md` § "Channel 0 — connection control".
 */

/** Bumps to 2 with the channel-mux landing. */
export const PROTOCOL_VERSION = 2;

export interface ChannelOpenPty {
  type: "channel_open";
  id: number;
  mode: "pty";
  session: string;
  cols?: number;
  rows?: number;
}

export interface ChannelOpenExec {
  type: "channel_open";
  id: number;
  mode: "exec";
  argv: string[];
  /** Optional. Omitted/null means the daemon inherits its own env. */
  env?: Record<string, string> | null;
  /** Optional. Omitted/null means the daemon's $HOME. */
  cwd?: string | null;
}

export type ChannelOpen = ChannelOpenPty | ChannelOpenExec;

export interface ChannelOpenAck {
  type: "channel_open_ack";
  id: number;
}

export type ChannelOpenErrorCode =
  | "mode_not_enabled"
  | "argv_not_allowed"
  | "session_not_found"
  | "spawn_failed"
  | "id_collision"
  | "channel_limit";

export interface ChannelOpenErrorMsg {
  type: "channel_open_error";
  id: number;
  code: ChannelOpenErrorCode;
  message: string;
}

export type ChannelCloseReason =
  | "client_detach"
  | "operator_close"
  | "peer_lost"
  | "protocol_error"
  | "exit";

export interface ChannelClose {
  type: "channel_close";
  id: number;
  reason: ChannelCloseReason;
}

export interface ChannelExit {
  type: "channel_exit";
  id: number;
  /** Non-null when the process exited normally. */
  exit_code: number | null;
  /** Non-null when the process was killed by a signal. */
  signal: string | null;
}

export interface Keepalive {
  type: "keepalive";
}

export type ConnectionErrorCode =
  | "frame_too_short"
  | "frame_too_large"
  | "control_frame_type"
  | "control_frame_decode"
  | "control_frame_json"
  | "control_frame_shape"
  | "unknown_control_type";

export interface ConnectionError {
  type: "error";
  code: ConnectionErrorCode;
  message: string;
}

export type ControlMessage =
  | ChannelOpen
  | ChannelOpenAck
  | ChannelOpenErrorMsg
  | ChannelClose
  | ChannelExit
  | Keepalive
  | ConnectionError;

export type ParseError =
  | "control_frame_decode"
  | "control_frame_json"
  | "control_frame_shape"
  | "unknown_control_type";

export type ParseResult =
  | { ok: true; msg: ControlMessage }
  | { ok: false; code: ParseError; detail?: string };

/**
 * Parse + validate a channel-0 payload.
 *
 * Layered failures:
 *  1. UTF-8 decode (`fatal` mode — any invalid bytes fail).
 *  2. JSON parse.
 *  3. Top-level object shape (must be `{type: string, ...}`).
 *  4. Per-type field validation.
 *
 * Unknown `type` values are surfaced as `unknown_control_type` so the
 * dispatcher can decide whether to ignore (forward-compat) or close.
 */
export function parseControlMessage(payload: Uint8Array): ParseResult {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(payload);
  } catch {
    return { ok: false, code: "control_frame_decode" };
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return { ok: false, code: "control_frame_json" };
  }
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    return { ok: false, code: "control_frame_shape", detail: "not an object" };
  }
  const o = json as Record<string, unknown>;
  if (typeof o.type !== "string") {
    return { ok: false, code: "control_frame_shape", detail: "missing type" };
  }

  switch (o.type) {
    case "channel_open":
      return parseChannelOpen(o);
    case "channel_open_ack":
      return parseChannelOpenAck(o);
    case "channel_open_error":
      return parseChannelOpenError(o);
    case "channel_close":
      return parseChannelClose(o);
    case "channel_exit":
      return parseChannelExit(o);
    case "keepalive":
      return { ok: true, msg: { type: "keepalive" } };
    case "error":
      return parseConnectionError(o);
    default:
      return {
        ok: false,
        code: "unknown_control_type",
        detail: o.type,
      };
  }
}

function parseChannelOpen(o: Record<string, unknown>): ParseResult {
  if (!isValidId(o.id)) return shape("channel_open.id");
  if (o.mode === "pty") {
    if (typeof o.session !== "string" || o.session.length === 0) {
      return shape("channel_open.session");
    }
    const msg: ChannelOpenPty = {
      type: "channel_open",
      id: o.id as number,
      mode: "pty",
      session: o.session,
    };
    if (typeof o.cols === "number") msg.cols = o.cols;
    if (typeof o.rows === "number") msg.rows = o.rows;
    return { ok: true, msg };
  }
  if (o.mode === "exec") {
    if (!Array.isArray(o.argv) || o.argv.length === 0) {
      return shape("channel_open.argv");
    }
    for (const a of o.argv) {
      if (typeof a !== "string") return shape("channel_open.argv (non-string)");
    }
    const msg: ChannelOpenExec = {
      type: "channel_open",
      id: o.id as number,
      mode: "exec",
      argv: o.argv as string[],
    };
    if (o.env !== undefined) {
      if (o.env === null) msg.env = null;
      else if (typeof o.env === "object" && !Array.isArray(o.env)) {
        const env: Record<string, string> = {};
        for (const [k, v] of Object.entries(o.env)) {
          if (typeof v !== "string") return shape("channel_open.env value");
          env[k] = v;
        }
        msg.env = env;
      } else {
        return shape("channel_open.env");
      }
    }
    if (o.cwd !== undefined) {
      if (o.cwd === null) msg.cwd = null;
      else if (typeof o.cwd === "string") msg.cwd = o.cwd;
      else return shape("channel_open.cwd");
    }
    return { ok: true, msg };
  }
  return shape("channel_open.mode");
}

function parseChannelOpenAck(o: Record<string, unknown>): ParseResult {
  if (!isValidId(o.id)) return shape("channel_open_ack.id");
  return { ok: true, msg: { type: "channel_open_ack", id: o.id as number } };
}

function parseChannelOpenError(o: Record<string, unknown>): ParseResult {
  if (!isValidId(o.id)) return shape("channel_open_error.id");
  if (
    o.code !== "mode_not_enabled" &&
    o.code !== "argv_not_allowed" &&
    o.code !== "session_not_found" &&
    o.code !== "spawn_failed" &&
    o.code !== "id_collision" &&
    o.code !== "channel_limit"
  ) {
    return shape("channel_open_error.code");
  }
  const message = typeof o.message === "string" ? o.message : "";
  return {
    ok: true,
    msg: {
      type: "channel_open_error",
      id: o.id as number,
      code: o.code as ChannelOpenErrorCode,
      message,
    },
  };
}

function parseChannelClose(o: Record<string, unknown>): ParseResult {
  if (!isValidId(o.id)) return shape("channel_close.id");
  if (
    o.reason !== "client_detach" &&
    o.reason !== "operator_close" &&
    o.reason !== "peer_lost" &&
    o.reason !== "protocol_error" &&
    o.reason !== "exit"
  ) {
    return shape("channel_close.reason");
  }
  return {
    ok: true,
    msg: {
      type: "channel_close",
      id: o.id as number,
      reason: o.reason as ChannelCloseReason,
    },
  };
}

function parseChannelExit(o: Record<string, unknown>): ParseResult {
  if (!isValidId(o.id)) return shape("channel_exit.id");
  const exit_code =
    typeof o.exit_code === "number" ? o.exit_code : o.exit_code === null ? null : undefined;
  const signal =
    typeof o.signal === "string" ? o.signal : o.signal === null ? null : undefined;
  if (exit_code === undefined || signal === undefined) {
    return shape("channel_exit.exit_code/signal");
  }
  if ((exit_code === null) === (signal === null)) {
    // Exactly one must be non-null.
    return shape("channel_exit must set exactly one of exit_code/signal");
  }
  return {
    ok: true,
    msg: {
      type: "channel_exit",
      id: o.id as number,
      exit_code,
      signal,
    },
  };
}

function parseConnectionError(o: Record<string, unknown>): ParseResult {
  if (typeof o.code !== "string") return shape("error.code");
  const message = typeof o.message === "string" ? o.message : "";
  return {
    ok: true,
    msg: {
      type: "error",
      code: o.code as ConnectionErrorCode,
      message,
    },
  };
}

function isValidId(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= 0xffffffff;
}

function shape(detail: string): ParseResult {
  return { ok: false, code: "control_frame_shape", detail };
}

/**
 * Encode a control message to a `Uint8Array` payload — the bytes that
 * go between `[0x00000000][0x00]` and the encrypted frame boundary.
 * Used by the dispatcher's reply path.
 */
export function encodeControlMessage(msg: ControlMessage): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(msg));
}
