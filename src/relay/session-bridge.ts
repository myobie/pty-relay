import * as net from "node:net";
import { Buffer } from "node:buffer";
import {
  encodeAttach,
  encodeDetach,
} from "@myobie/pty/protocol";
import { getSocketPath } from "@myobie/pty/client";
import type { ChannelHandler } from "./channel-registry.ts";
import { log, now, sinceMs } from "../log.ts";

/**
 * Bridges a pty Unix socket session to one channel of an encrypted
 * Noise tunnel. Ports the v1 SessionBridge to the channel-mux model
 * (see `docs/channel-protocol.md`):
 *
 * Flow:
 * 1. Caller has accepted a `channel_open {mode:"pty", session, cols, rows}`
 *    (or is opening one) and constructs a `SessionBridge`.
 * 2. `attach(session, cols, rows)` connects to `~/.local/state/pty/<name>.sock`
 *    and sends ATTACH.
 * 3. Each pty packet from the local socket is shipped via the
 *    `sendData` callback the caller supplies. The callback is
 *    responsible for wrapping the bytes in the channel's frame —
 *    SessionBridge is mode-aware but channel-id-agnostic.
 * 4. Inbound bytes from the peer arrive via `onFrame(type, payload)`
 *    and are written to the pty socket.
 *
 * The bridge implements `ChannelHandler` so the dispatcher can store it
 * in a `ChannelRegistry` and route inbound frames by channel id without
 * special-casing pty mode.
 */
export class SessionBridge implements ChannelHandler {
  readonly mode = "pty" as const;

  private socket: net.Socket | null = null;
  private sessionName: string | null = null;
  private readonly sendData: (payload: Uint8Array) => void;

  /**
   * @param sendData  Wrap bytes in this channel's frame (caller closes
   *                  over `channelId`) and ship via the Noise transport.
   *                  Called whenever the pty socket has bytes to forward.
   */
  constructor(sendData: (payload: Uint8Array) => void) {
    this.sendData = sendData;
  }

  /**
   * Connect to the pty session's local Unix socket and send the
   * initial ATTACH packet. Resolves once the connection is established;
   * pty bytes start flowing through `sendData` from that point on.
   *
   * Rejects if the socket connect errors (session doesn't exist, etc.).
   * The caller translates the rejection into a `channel_open_error`
   * with `code:"session_not_found"`.
   */
  attach(session: string, cols: number, rows: number): Promise<void> {
    return new Promise((resolve, reject) => {
      this.sessionName = session;
      const socketPath = getSocketPath(session);
      const t0 = now();
      log("bridge", "attach", { session, cols, rows, socketPath });

      this.socket = net.createConnection(socketPath);

      this.socket.on("connect", () => {
        this.socket!.write(encodeAttach(rows, cols));
        log("bridge", "attached", { session, ms: sinceMs(t0) });
        resolve();
      });

      this.socket.on("data", (data: Buffer) => {
        // pty socket → peer (via channel frame)
        try {
          this.sendData(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
        } catch (err) {
          log("bridge", "send failed, closing", {
            session: this.sessionName,
            error: (err as Error)?.message,
          });
          this.close("send_failed");
        }
      });

      this.socket.on("close", () => {
        log("bridge", "pty socket close", { session: this.sessionName });
        this.socket = null;
      });

      this.socket.on("error", (err: Error) => {
        log("bridge", "pty socket error", {
          session: this.sessionName,
          error: err.message,
        });
        this.socket = null;
        reject(err);
      });
    });
  }

  /**
   * `ChannelHandler.onFrame`. Inbound frames on this bridge's channel
   * carry pty packet bytes; we forward them verbatim to the local pty
   * socket. The frame `type` byte is currently always `DATA` for pty
   * channels (SIGNAL is reserved for exec mode); unknown types are
   * dropped silently so a future SIGNAL/RESIZE expansion doesn't crash
   * old daemons.
   */
  onFrame(_type: number, payload: Uint8Array): void {
    if (this.socket && !this.socket.destroyed) {
      this.socket.write(Buffer.from(payload));
    }
  }

  /**
   * `ChannelHandler.close`. Tears down the pty socket if still up.
   * Idempotent — the registry's cascade-close may invoke this while a
   * peer-initiated close is already in flight.
   */
  close(_reason: string): void {
    if (this.socket && !this.socket.destroyed) {
      log("bridge", "close", { session: this.sessionName, reason: _reason });
      try {
        this.socket.write(encodeDetach());
      } catch {
        // Best-effort; if write fails we still destroy below.
      }
      this.socket.destroy();
    }
    this.socket = null;
    this.sessionName = null;
  }

  isConnected(): boolean {
    return this.socket !== null && !this.socket.destroyed;
  }

  getSessionName(): string | null {
    return this.sessionName;
  }
}
