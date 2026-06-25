/**
 * Channel-mux dispatcher — see `docs/channel-protocol.md`
 * § "Daemon-side architecture".
 *
 * Inbound Noise plaintexts arrive here; outbound frames go through
 * `send`. The dispatcher owns the routing logic only — it doesn't know
 * what a pty session or a child process is. Channel handlers (the
 * registry's payload) handle mode-specific behavior.
 *
 * Pure-ish: depends on a registry + a `send` callback + an
 * `onFatal`/`onControlMessage` callback pair. No network or process
 * I/O on its own, so it unit-tests against a fake registry + capture
 * arrays for send/fatal/control events.
 */

import {
  decodeFrame,
  encodeFrame,
  CONTROL_CHANNEL_ID,
  FRAME_TYPE,
  type DecodeError,
} from "./channel-framing.ts";
import {
  encodeControlMessage,
  parseControlMessage,
  type ControlMessage,
  type ConnectionErrorCode,
  type ParseError,
} from "./channel-control.ts";
import type { ChannelRegistry } from "./channel-registry.ts";

/** Callback that ships an already-encoded frame across the Noise transport. */
export type SendFrame = (frame: Uint8Array) => void;

export interface DispatcherEvents {
  /**
   * A well-formed control message arrived on channel 0. The application
   * decides what to do (open a bridge, ack, error, etc.). The dispatcher
   * itself only handles malformed frames + per-channel routing.
   */
  onControlMessage: (msg: ControlMessage) => void;
  /**
   * Connection-fatal error — frame too short/long, channel-0 with the
   * wrong frame type, garbage JSON on channel 0. The application sends
   * a final `error` control message and closes the WS. The dispatcher
   * does NOT auto-send the error frame: that's the application's call
   * (it may want to do its own logging first, and we want a single
   * code path that sends `error` + closes).
   */
  onFatalError: (code: ConnectionErrorCode, message: string) => void;
}

export class ChannelDispatcher {
  constructor(
    private readonly registry: ChannelRegistry,
    private readonly send: SendFrame,
    private readonly events: DispatcherEvents,
  ) {}

  /**
   * Called once per decrypted Noise plaintext. Returns nothing; side
   * effects are dispatched into the registry / events.
   */
  handlePlaintext(bytes: Uint8Array): void {
    const decoded = decodeFrame(bytes);
    if (!decoded.ok) {
      this.events.onFatalError(
        decodeErrorToCode(decoded.code),
        `frame decode failed: ${decoded.code}`,
      );
      return;
    }
    const { channelId, type, payload } = decoded.frame;

    if (channelId === CONTROL_CHANNEL_ID) {
      this.handleControlFrame(type, payload);
      return;
    }

    const handler = this.registry.get(channelId);
    if (!handler) {
      // Stale frame post-close, or a frame for an id we never opened.
      // Drop silently — sending a `channel_close` here would race the
      // peer's own close + create reply storms. Logging happens in the
      // caller / application layer.
      return;
    }
    handler.onFrame(type, payload);
  }

  private handleControlFrame(type: number, payload: Uint8Array): void {
    if (type !== FRAME_TYPE.DATA) {
      this.events.onFatalError(
        "control_frame_type",
        `channel 0 frames must have type=DATA (got 0x${type.toString(16)})`,
      );
      return;
    }
    const parsed = parseControlMessage(payload);
    if (!parsed.ok) {
      this.events.onFatalError(
        parseErrorToCode(parsed.code),
        parsed.detail
          ? `control parse: ${parsed.code} (${parsed.detail})`
          : `control parse: ${parsed.code}`,
      );
      return;
    }
    this.events.onControlMessage(parsed.msg);
  }

  /** Convenience: encode + ship a control message on channel 0. */
  sendControl(msg: ControlMessage): void {
    const payload = encodeControlMessage(msg);
    this.send(encodeFrame(CONTROL_CHANNEL_ID, FRAME_TYPE.DATA, payload));
  }

  /** Convenience: encode + ship a data frame on a non-control channel. */
  sendData(channelId: number, type: number, payload: Uint8Array): void {
    this.send(encodeFrame(channelId, type, payload));
  }
}

function decodeErrorToCode(e: DecodeError): ConnectionErrorCode {
  return e;
}

function parseErrorToCode(e: ParseError): ConnectionErrorCode {
  return e;
}
