import WebSocket from "ws";
import {
  InitiatorHandshake,
  Transport,
} from "../crypto/index.ts";

const PING_INTERVAL_MS = 15000;
const SLEEP_DRIFT_MS = 10000; // if timer fires >10s late, system was asleep
const PONG_TIMEOUT_MS = 5000;

export interface ClientRelayEvents {
  onReady: (transport: Transport) => void;
  onEncryptedMessage: (plaintext: Uint8Array) => void;
  onPeerDisconnected: () => void;
  onError: (error: Error) => void;
  onClose: () => void;
  onWaitingForApproval?: () => void;
}

/**
 * Manages the WebSocket connection to the relay as a client.
 * Handles pairing, Noise NK handshake (as initiator), and encrypted forwarding.
 *
 * The client sends WebSocket pings every 15s to keep the connection alive
 * through NAT, firewalls, and proxies. If no pong is received within 5s
 * of a ping, the connection is terminated immediately.
 */
export class ClientRelayConnection {
  private ws: WebSocket | null = null;
  private transport: Transport | null = null;
  private handshake: InitiatorHandshake | null = null;
  private wsUrl: string;
  private daemonPublicKey: Uint8Array;
  private events: ClientRelayEvents;
  private pingTimer: ReturnType<typeof setTimeout> | null = null;
  private pongTimer: ReturnType<typeof setTimeout> | null = null;
  private lastPong: number = Date.now();
  private state:
    | "connecting"
    | "waiting"
    | "handshaking"
    | "ready"
    | "closed" = "connecting";

  constructor(
    wsUrl: string,
    daemonPublicKey: Uint8Array,
    events: ClientRelayEvents
  ) {
    this.wsUrl = wsUrl;
    this.daemonPublicKey = daemonPublicKey;
    this.events = events;
  }

  connect(): void {
    this.state = "connecting";
    this.transport = null;
    this.handshake = null;

    this.ws = new WebSocket(this.wsUrl);
    this.ws.binaryType = "nodebuffer";

    this.ws.on("open", () => {
      this.state = "waiting";
      this.lastPong = Date.now();
      this.schedulePing();
    });

    this.ws.on("pong", () => {
      this.lastPong = Date.now();
      this.clearPongTimer();
    });

    this.ws.on("message", (data: Buffer | string, isBinary: boolean) => {
      if (typeof data === "string" || !isBinary) {
        const text = typeof data === "string" ? data : data.toString("utf-8");
        this.handleTextMessage(text);
      } else {
        this.handleBinaryMessage(data as Buffer);
      }
    });

    this.ws.on("close", () => {
      this.state = "closed";
      this.clearPing();
      this.clearPongTimer();
      this.events.onClose();
    });

    this.ws.on("error", (err: Error) => {
      this.events.onError(err);
    });
  }

  send(plaintext: Uint8Array): void {
    if (!this.transport || !this.ws || this.state !== "ready") {
      throw new Error("Not ready to send");
    }

    const ciphertext = this.transport.encrypt(plaintext);
    this.ws.send(ciphertext);
  }

  close(): void {
    this.state = "closed";
    this.clearPing();
    this.clearPongTimer();
    this.ws?.close();
  }

  private nextPingExpectedAt = 0;

  private schedulePing(): void {
    this.clearPing();
    this.nextPingExpectedAt = Date.now() + PING_INTERVAL_MS;
    this.pingTimer = setTimeout(() => {
      // Detect sleep/wake: if the timer fired much later than expected,
      // the system was asleep and the connection is certainly dead.
      const drift = Date.now() - this.nextPingExpectedAt;
      if (drift > SLEEP_DRIFT_MS) {
        if (this.ws) this.ws.terminate();
        return;
      }

      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.ping();
        this.schedulePongTimeout();
      }
      if (this.state !== "closed") {
        this.schedulePing();
      }
    }, PING_INTERVAL_MS);
  }

  private schedulePongTimeout(): void {
    this.clearPongTimer();
    this.pongTimer = setTimeout(() => {
      if (this.state === "closed") return;
      // No pong received in time — terminate immediately
      if (this.ws) {
        this.ws.terminate();
      }
    }, PONG_TIMEOUT_MS);
  }

  private clearPongTimer(): void {
    if (this.pongTimer) {
      clearTimeout(this.pongTimer);
      this.pongTimer = null;
    }
  }

  private clearPing(): void {
    if (this.pingTimer) {
      clearTimeout(this.pingTimer);
      this.pingTimer = null;
    }
  }

  isReady(): boolean {
    return this.state === "ready";
  }

  private handleTextMessage(text: string): void {
    try {
      const msg = JSON.parse(text);

      switch (msg.type) {
        case "paired":
          this.state = "handshaking";
          this.startHandshake();
          break;

        case "waiting_for_approval":
          if (this.events.onWaitingForApproval) {
            this.events.onWaitingForApproval();
          }
          break;

        case "peer_disconnected":
          this.transport = null;
          this.state = "closed";
          this.events.onPeerDisconnected();
          break;

        case "error":
          this.events.onError(new Error(msg.message || "Relay error"));
          break;
      }
    } catch {
      // Ignore unparseable text frames
    }
  }

  private handleBinaryMessage(data: Buffer): void {
    if (this.state === "handshaking" && this.handshake) {
      try {
        const result = this.handshake.readWelcome(new Uint8Array(data));
        this.transport = new Transport(result);
        this.state = "ready";
        this.handshake = null;

        this.events.onReady(this.transport);
      } catch (err) {
        this.handshake = null;
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

  private startHandshake(): void {
    this.handshake = new InitiatorHandshake(this.daemonPublicKey);
    const hello = this.handshake.writeHello();
    this.ws!.send(hello);
  }
}
