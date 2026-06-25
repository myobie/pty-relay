/**
 * Channel-mux v2 framing — see `docs/channel-protocol.md`.
 *
 * Every Noise-decrypted plaintext frame is:
 *
 *   +------------------+------+----------------+
 *   | channel-id u32BE | type | payload (rest) |
 *   +------------------+------+----------------+
 *          4 B            1 B    0..N bytes
 *
 * The framing layer is pure (no I/O). `encodeFrame` produces a Uint8Array
 * the Noise transport will encrypt verbatim; `decodeFrame` validates the
 * shape of an already-decrypted plaintext and surfaces structured errors
 * for malformed input. Callers translate decode errors into the right
 * connection-level vs per-channel response (see ChannelDispatcher).
 */

/** Floor on a usable frame: channel-id (4) + type (1) + 0 bytes payload. */
export const MIN_FRAME_BYTES = 5;

/**
 * Ceiling on one frame's encrypted ciphertext. 64 KiB matches SSH's
 * default packet size and stays well within libsodium's secretbox
 * per-message budget. Logical payloads larger than this are split into
 * multiple DATA frames on the same channel.
 */
export const MAX_FRAME_BYTES = 65_536;

/** Channel 0 is reserved for JSON connection control messages. */
export const CONTROL_CHANNEL_ID = 0;

/**
 * The single, implicit pty bridge channel id used through the phase-3
 * port. Phase 4 introduces `channel_open` so callers can allocate
 * channel ids freely (including multiple pty channels per connection);
 * until then, every connection has at most one pty channel and it's
 * here.
 */
export const DEFAULT_PTY_CHANNEL_ID = 1;

/** Per-frame `type` byte values. */
export const FRAME_TYPE = {
  /** Stdio / pty-packet payload. The common case. */
  DATA: 0x00,
  /**
   * Exec-mode only: client → daemon ASCII signal name in payload
   * (e.g. "SIGINT", "SIGTERM"). Other modes treat this as a protocol
   * error on their channel.
   */
  SIGNAL: 0x01,
} as const;

/** Exec-mode sub-stream prefix byte (first byte of DATA payload). */
export const SUBSTREAM = {
  STDIN: 0x00,
  STDOUT: 0x01,
  STDERR: 0x02,
} as const;

export type SubstreamId = (typeof SUBSTREAM)[keyof typeof SUBSTREAM];

export interface Frame {
  channelId: number;
  type: number;
  payload: Uint8Array;
}

export type DecodeError =
  | "frame_too_short"
  | "frame_too_large";

export type DecodeResult =
  | { ok: true; frame: Frame }
  | { ok: false; code: DecodeError };

/**
 * Serialize a frame to a `Uint8Array`. Throws `RangeError` on inputs
 * that can't be represented (negative/too-large channel id, too-large
 * type byte, payload that would push the frame past `MAX_FRAME_BYTES`).
 * Throws on inputs the *caller* controls — never on inputs from the
 * wire (those are decoded, not encoded).
 */
export function encodeFrame(
  channelId: number,
  type: number,
  payload: Uint8Array,
): Uint8Array {
  if (
    !Number.isInteger(channelId) ||
    channelId < 0 ||
    channelId > 0xffffffff
  ) {
    throw new RangeError(
      `channel id must be a uint32 (got ${channelId})`,
    );
  }
  if (!Number.isInteger(type) || type < 0 || type > 0xff) {
    throw new RangeError(`type must be a uint8 (got ${type})`);
  }
  const total = MIN_FRAME_BYTES + payload.length;
  if (total > MAX_FRAME_BYTES) {
    throw new RangeError(
      `frame would be ${total} bytes; max is ${MAX_FRAME_BYTES}`,
    );
  }

  const buf = new Uint8Array(total);
  const view = new DataView(buf.buffer);
  view.setUint32(0, channelId, false); // big-endian
  buf[4] = type;
  if (payload.length > 0) buf.set(payload, MIN_FRAME_BYTES);
  return buf;
}

/**
 * Parse a frame out of a decrypted plaintext. Returns a structured
 * error for sizes outside `[MIN, MAX]` — the dispatcher decides whether
 * the error is connection-fatal (it always is, today) or per-channel.
 *
 * The returned `payload` is a defensive copy: callers can keep it
 * across the boundary without worrying about the decrypt buffer being
 * reused.
 */
export function decodeFrame(bytes: Uint8Array): DecodeResult {
  if (bytes.length < MIN_FRAME_BYTES) {
    return { ok: false, code: "frame_too_short" };
  }
  if (bytes.length > MAX_FRAME_BYTES) {
    return { ok: false, code: "frame_too_large" };
  }
  const view = new DataView(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength,
  );
  const channelId = view.getUint32(0, false);
  const type = bytes[4];
  // slice() copies; protects callers from buffer reuse.
  const payload = bytes.slice(MIN_FRAME_BYTES);
  return { ok: true, frame: { channelId, type, payload } };
}

/**
 * Helper for exec-mode senders: prepend the sub-stream id byte.
 *   `wrapSubstream(STDOUT, bytes)` → `[0x01, …bytes]`
 */
export function wrapSubstream(
  substream: SubstreamId,
  payload: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(1 + payload.length);
  out[0] = substream;
  if (payload.length > 0) out.set(payload, 1);
  return out;
}

/**
 * Helper for exec-mode receivers: pull the sub-stream id off the front.
 * Returns null when the payload is empty (no leading byte). Callers
 * check the substream value against the small allowed set.
 */
export function unwrapSubstream(
  payload: Uint8Array,
): { substream: number; bytes: Uint8Array } | null {
  if (payload.length < 1) return null;
  return { substream: payload[0], bytes: payload.slice(1) };
}
