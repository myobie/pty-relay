import * as net from "node:net";
import { Buffer } from "node:buffer";
import {
  encodeAttach,
  encodeDetach,
} from "@myobie/pty/protocol";
import { getSocketPath } from "@myobie/pty/client";
import type { RelayConnection } from "./relay-connection.ts";

/**
 * Bridges a pty Unix socket session to an encrypted relay tunnel.
 *
 * Flow:
 * 1. Client sends {"type":"attach","session":"name","cols":N,"rows":N} (already decrypted)
 * 2. Bridge connects to ~/.local/state/pty/<name>.sock
 * 3. Sends ATTACH packet with terminal size
 * 4. Forwards packets bidirectionally:
 *    - Pty socket → encrypt → relay
 *    - Relay → decrypt → pty socket
 */
export class SessionBridge {
  private socket: net.Socket | null = null;
  private relay: RelayConnection;
  private sessionName: string | null = null;

  constructor(relay: RelayConnection) {
    this.relay = relay;
  }

  /**
   * Handle the initial attach request from the client.
   * Connects to the pty session and starts bridging.
   */
  attach(
    session: string,
    cols: number,
    rows: number
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      this.sessionName = session;
      const socketPath = getSocketPath(session);

      this.socket = net.createConnection(socketPath);

      this.socket.on("connect", () => {
        // Send ATTACH packet to the pty server
        this.socket!.write(encodeAttach(rows, cols));
        resolve();
      });

      this.socket.on("data", (data: Buffer) => {
        // Forward raw bytes from pty socket → encrypted → relay
        try {
          this.relay.send(data);
        } catch (err) {
          // Relay not ready or closed
          this.close();
        }
      });

      this.socket.on("close", () => {
        this.socket = null;
      });

      this.socket.on("error", (err: Error) => {
        this.socket = null;
        reject(err);
      });
    });
  }

  /**
   * Handle decrypted data from the relay (originally from the client).
   * Forward it directly to the pty socket.
   */
  handleRelayData(data: Uint8Array): void {
    if (this.socket && !this.socket.destroyed) {
      this.socket.write(Buffer.from(data));
    }
  }

  /** Close the pty socket connection. */
  close(): void {
    if (this.socket && !this.socket.destroyed) {
      // Send DETACH to the pty server
      try {
        this.socket.write(encodeDetach());
      } catch {}
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
