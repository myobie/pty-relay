/**
 * Per-connection channel-mux wrapper — owns the ChannelRegistry +
 * ChannelDispatcher pair and exposes a small, uniform send/recv surface
 * for the four sites that wire it up (self-hosted daemon, public-mode
 * daemon, CLI client, web UI).
 *
 * The underlying Noise transport stays in place: `rawSend` ships an
 * already-encoded channel frame across the encrypted tunnel, and
 * `handlePlaintext` is called with each decrypted plaintext from the
 * peer. The wrapper handles framing + routing on both directions.
 *
 * Phase 3b parks the single implicit pty bridge on
 * `DEFAULT_PTY_CHANNEL_ID = 1`. Phase 4 introduces `channel_open` so
 * callers can allocate channels dynamically (multiple pty bridges,
 * exec channels for rsync/git, etc).
 */

import {
  ChannelRegistry,
  type ChannelHandler,
} from "./channel-registry.ts";
import {
  ChannelDispatcher,
  type SendFrame,
} from "./channel-dispatcher.ts";
import {
  DEFAULT_PTY_CHANNEL_ID,
  FRAME_TYPE,
} from "./channel-framing.ts";
import type {
  ControlMessage,
  ConnectionErrorCode,
} from "./channel-control.ts";

export interface ChannelConnectionEvents {
  /**
   * Application-level JSON message arrived on channel 0 — the v1
   * session vocabulary (hello / list / peek / send / tag / events_* /
   * spawn / approved / latency_report / mint_request / attach /
   * attached / spawned / error / sessions / peek_result / send_ok /
   * tag_result / event / event_ping / events_snapshot).
   *
   * The application's existing handler consumes the raw object. `type`
   * is provided for fast dispatch.
   */
  onApp: (type: string, json: Record<string, unknown>) => void;
  /**
   * Phase-4 channel-lifecycle message (channel_open / _ack / _error /
   * _close / channel_exit / keepalive / error). Phase 3b doesn't send
   * these yet, but the surface is here so a peer that does will be
   * routed cleanly.
   */
  onControl?: (msg: ControlMessage) => void;
  /**
   * Connection-fatal protocol error from the dispatcher (frame too
   * short/long, channel-0 frame type mismatch, garbage JSON on channel
   * 0). Caller should send an `error` control message + close the WS.
   */
  onFatal?: (code: ConnectionErrorCode, message: string) => void;
}

export class ChannelConnection {
  readonly registry: ChannelRegistry;
  private dispatcher: ChannelDispatcher;

  constructor(rawSend: SendFrame, events: ChannelConnectionEvents) {
    this.registry = new ChannelRegistry();
    this.dispatcher = new ChannelDispatcher(this.registry, rawSend, {
      onAppMessage: events.onApp,
      onControlMessage: events.onControl ?? (() => {}),
      onFatalError: events.onFatal ?? (() => {}),
    });
  }

  /** Channel-0 application JSON — replaces `connection.send(JSON.stringify(obj))`. */
  sendApp(obj: Record<string, unknown>): void {
    this.dispatcher.sendApp(obj);
  }

  /** Channel-`DEFAULT_PTY_CHANNEL_ID` pty packet bytes — replaces
   *  raw `connection.send(ptyBytes)` and the bridge's outbound path. */
  sendBridgeData(payload: Uint8Array): void {
    this.dispatcher.sendData(
      DEFAULT_PTY_CHANNEL_ID,
      FRAME_TYPE.DATA,
      payload,
    );
  }

  /** Generic per-channel-id DATA frame — used by exec channels (and any
   *  future channel mode that allocates its own channel id) for
   *  outbound payloads. Pty bridge keeps using `sendBridgeData` to
   *  pin its implicit channel. */
  sendChannelData(channelId: number, payload: Uint8Array): void {
    this.dispatcher.sendData(channelId, FRAME_TYPE.DATA, payload);
  }

  /** Wire a SessionBridge (or another ChannelHandler) onto the single
   *  pty channel. Idempotent on the same handler; throws on a different
   *  handler for an already-open id. */
  attachBridge(bridge: ChannelHandler): void {
    if (this.registry.has(DEFAULT_PTY_CHANNEL_ID)) {
      const existing = this.registry.get(DEFAULT_PTY_CHANNEL_ID);
      if (existing === bridge) return;
      this.registry.close(DEFAULT_PTY_CHANNEL_ID, "client_detach");
    }
    this.registry.open(DEFAULT_PTY_CHANNEL_ID, bridge);
  }

  /** Detach the current bridge (no-op if none). */
  detachBridge(reason: string = "client_detach"): void {
    this.registry.close(DEFAULT_PTY_CHANNEL_ID, reason);
  }

  /** Feed a decrypted plaintext from the Noise transport into the
   *  dispatcher. */
  handlePlaintext(plaintext: Uint8Array): void {
    this.dispatcher.handlePlaintext(plaintext);
  }

  /** Cascade-close every registered channel. Called when the WS ends. */
  closeAll(reason: string): void {
    this.registry.closeAll(reason);
  }
}
