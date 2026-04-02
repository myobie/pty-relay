import WebSocket from "ws";
import {
  ResponderHandshake,
  Transport,
} from "../crypto/index.ts";
import type { Config } from "../crypto/index.ts";

export interface RelayEvents {
  onConnected?: () => void;
  onPaired: () => void;
  onHandshakeComplete: (transport: Transport) => void;
  onEncryptedMessage: (plaintext: Uint8Array) => void;
  onPeerDisconnected: () => void;
  onError: (error: Error) => void;
  onClose: (code?: number) => void;
}

/**
 * Manages the WebSocket connection to the relay as a daemon.
 * Handles pairing, Noise NK handshake, and encrypted message forwarding.
 *
 * The daemon does not send pings — clients are responsible for keepalive.
 */
export class RelayConnection {
  private ws: WebSocket | null = null;
  private transport: Transport | null = null;
  private handshake: ResponderHandshake | null = null;
  private config: Config;
  private wsUrlFactory: string | (() => string);
  private events: RelayEvents;
  private state: "connecting" | "waiting" | "handshaking" | "ready" | "closed" =
    "connecting";

  constructor(wsUrl: string | (() => string), config: Config, events: RelayEvents) {
    this.wsUrlFactory = wsUrl;
    this.config = config;
    this.events = events;
  }

  /** Connect to the relay. */
  connect(): void {
    this.state = "connecting";
    this.transport = null;
    this.handshake = null;

    const url = typeof this.wsUrlFactory === "function" ? this.wsUrlFactory() : this.wsUrlFactory;
    this.ws = new WebSocket(url);
    this.ws.binaryType = "nodebuffer";

    this.ws.on("open", () => {
      this.state = "waiting";
      this.events.onConnected?.();
    });

    this.ws.on("message", (data: Buffer | string, isBinary: boolean) => {
      if (isBinary) {
        this.handleBinaryMessage(Buffer.isBuffer(data) ? data : Buffer.from(data));
      } else {
        this.handleTextMessage(typeof data === "string" ? data : data.toString("utf-8"));
      }
    });

    this.ws.on("close", (code: number) => {
      this.state = "closed";
      this.events.onClose(code);
    });

    this.ws.on("error", (err: Error) => {
      this.events.onError(err);
    });
  }

  /** Send an encrypted message through the tunnel. */
  send(plaintext: Uint8Array): void {
    if (!this.transport || !this.ws || this.state !== "ready") {
      throw new Error("Not ready to send");
    }

    const ciphertext = this.transport.encrypt(plaintext);
    this.ws.send(ciphertext);
  }

  /** Close the connection. */
  close(): void {
    this.state = "closed";
    this.ws?.close();
  }

  isReady(): boolean {
    return this.state === "ready";
  }

  // ── Message Handling ──

  private handleTextMessage(text: string): void {
    try {
      const msg = JSON.parse(text);

      switch (msg.type) {
        case "paired":
          this.state = "handshaking";
          this.handshake = new ResponderHandshake(
            this.config.publicKey,
            this.config.secretKey
          );
          this.events.onPaired();
          break;

        case "peer_disconnected":
          this.transport = null;
          this.handshake = null;
          this.state = "waiting";
          this.events.onPeerDisconnected();
          break;

        case "error":
          this.events.onError(new Error(msg.message || "Relay error"));
          break;
      }
    } catch {
      // Ignore unparseable text
    }
  }

  private handleBinaryMessage(data: Buffer): void {
    if (this.state === "handshaking" && this.handshake) {
      try {
        this.handshake.readHello(new Uint8Array(data));
        const { message: welcome, result } = this.handshake.writeWelcome();

        this.ws!.send(welcome);

        this.transport = new Transport(result);
        this.state = "ready";
        this.handshake = null;

        this.events.onHandshakeComplete(this.transport);
      } catch (err) {
        this.events.onError(
          err instanceof Error ? err : new Error(`Handshake failed: ${err}`)
        );
        this.close();
      }
    } else if (this.state === "ready" && this.transport) {
      try {
        const plaintext = this.transport.decrypt(new Uint8Array(data));
        this.events.onEncryptedMessage(plaintext);
      } catch (err) {
        // Decryption failure is fatal — nonce counters are now desynchronized
        this.events.onError(
          err instanceof Error ? err : new Error(String(err))
        );
        this.close();
      }
    }
  }
}
