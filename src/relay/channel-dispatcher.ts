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
   * A well-formed channel-lifecycle control message arrived on channel 0
   * (channel_open / _ack / _error / _close / channel_exit / keepalive /
   * error). The application reacts (open a bridge, ack, route exits) —
   * the dispatcher itself just routes.
   */
  onControlMessage: (msg: ControlMessage) => void;
  /**
   * A well-formed JSON object arrived on channel 0 with a `type` that
   * isn't one of the channel-lifecycle messages. These are the v1
   * session-level RPCs (hello / list / peek / send / tag / events_* /
   * spawn / approved / latency_report / mint_request) flowing through
   * the new framing layer unchanged. The application's existing
   * dispatcher (handleSessionControlMessage et al.) consumes the raw
   * object.
   *
   * `type` is provided as a convenience; it is also `json.type`.
   */
  onAppMessage: (type: string, json: Record<string, unknown>) => void;
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
  private readonly registry: ChannelRegistry;
  private readonly send: SendFrame;
  private readonly events: DispatcherEvents;

  constructor(
    registry: ChannelRegistry,
    send: SendFrame,
    events: DispatcherEvents,
  ) {
    this.registry = registry;
    this.send = send;
    this.events = events;
  }

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
    if (parsed.kind === "control") {
      this.events.onControlMessage(parsed.msg);
    } else {
      this.events.onAppMessage(parsed.type, parsed.json);
    }
  }

  /**
   * Convenience: encode + ship an application-level JSON message on
   * channel 0. Used for the v1 session-level RPCs (hello / list /
   * approved / …) that flow through the new framing layer unchanged.
   */
  sendApp(msg: Record<string, unknown>): void {
    const payload = new TextEncoder().encode(JSON.stringify(msg));
    this.send(encodeFrame(CONTROL_CHANNEL_ID, FRAME_TYPE.DATA, payload));
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
