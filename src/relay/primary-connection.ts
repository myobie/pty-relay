import WebSocket from "ws";
import { log, now, sinceMs, redactAuthQuery } from "../log.ts";

export interface RelayEvent {
  seq: number;
  event_type: string;
  sender_key_id?: string;
  payloads?: Record<string, string>;
}

export interface ClientConnectMeta {
  remote_addr?: string | null;
  user_agent?: string | null;
  origin?: string | null;
}

export interface PrimaryRelayEvents {
  onConnected: () => void;
  onClientWaiting: (
    clientId: string,
    clientToken?: string,
    meta?: ClientConnectMeta
  ) => void;
  onClientDisconnected: (clientId: string) => void;
  onEvent?: (event: RelayEvent) => void;
  onError: (error: Error) => void;
  onClose: (code?: number) => void;
  /** Called when the relay sends a `{"type":"revoked"}` frame or closes
   *  with code 4001. Revocation is terminal: the daemon should tear
   *  down, surface a clear message to the operator, and NOT auto-
   *  reconnect with this key (the key is no longer valid on the relay).
   *  Optional — callers that don't provide it fall back to onClose +
   *  the daemon's default reconnect loop, which will loop on 401. */
  onRevoked?: () => void;
}

/** Close code the relay uses when terminating sockets for a revoked
 *  key or a deleted account. */
export const REVOKED_CLOSE_CODE = 4001;

/**
 * The daemon's primary control WebSocket to the relay.
 * This does NOT do Noise NK handshake -- it only handles text control messages.
 *
 * The daemon does not send pings — clients are responsible for keepalive.
 *
 * Messages received:
 * - {"type":"client_waiting","client_id":"abc"} -> onClientWaiting
 * - {"type":"client_disconnected","client_id":"abc"} -> onClientDisconnected
 * - {"type":"error","message":"..."} -> onError
 * - {"type":"draining"} -> reconnect
 *
 * The daemon should respond to onClientWaiting by opening a new RelayConnection
 * with client_id in the URL for each waiting client.
 */
export class PrimaryRelayConnection {
  private ws: WebSocket | null = null;
  private wsUrlFactory: string | (() => string);
  private events: PrimaryRelayEvents;
  private closed = false;

  constructor(wsUrl: string | (() => string), events: PrimaryRelayEvents) {
    this.wsUrlFactory = wsUrl;
    this.events = events;
  }

  /** Connect to the relay as the primary daemon control socket. */
  connect(): void {
    this.closed = false;

    const url =
      typeof this.wsUrlFactory === "function"
        ? this.wsUrlFactory()
        : this.wsUrlFactory;

    const connectStart = now();
    log("ws-primary", "connect", { url: redactAuthQuery(url) });
    this.ws = new WebSocket(url);
    this.ws.binaryType = "nodebuffer";

    this.ws.on("open", () => {
      log("ws-primary", "open", { ms: sinceMs(connectStart) });
      this.events.onConnected();
    });

    this.ws.on("message", (data: Buffer | string, isBinary: boolean) => {
      // Primary connection only handles text messages
      if (!isBinary) {
        const text = typeof data === "string" ? data : data.toString("utf-8");
        this.handleTextMessage(text);
      } else {
        log("ws-primary", "unexpected binary frame", { bytes: Buffer.isBuffer(data) ? data.length : 0 });
      }
    });

    this.ws.on("close", (code: number) => {
      log("ws-primary", "close", { code, ms: sinceMs(connectStart), closedByUs: this.closed });
      if (!this.closed) {
        this.events.onClose(code);
      }
    });

    this.ws.on("error", (err: Error) => {
      log("ws-primary", "error", {
        error: err?.message,
        type: (err as any)?.type,
        code: (err as any)?.code,
      });
      this.events.onError(err);
    });
  }

  /** Close the connection. */
  close(): void {
    this.closed = true;
    log("ws-primary", "close requested");
    this.ws?.close();
    this.ws = null;
  }

  /** Send a text frame on the primary WebSocket. */
  sendText(text: string): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(text);
    } else {
      log("ws-primary", "sendText dropped (not open)", {
        readyState: this.ws?.readyState,
        preview: text.slice(0, 80),
      });
    }
  }

  /** Check if the connection is open. */
  isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  /** Send a sync message to catch up on events since the given cursor. */
  sendSync(cursor: number): void {
    this.sendText(JSON.stringify({ type: "sync", cursor }));
  }

  /** Emit a custom event to the relay's event log. */
  sendEvent(eventType: string, payload: Record<string, unknown>): void {
    this.sendText(JSON.stringify({
      type: "emit_event",
      event_type: eventType,
      payload,
    }));
  }

  // -- Message Handling --

  private handleTextMessage(text: string): void {
    try {
      const msg = JSON.parse(text);
      log("ws-primary", "text recv", { type: msg.type, size: text.length });

      switch (msg.type) {
        case "client_waiting":
          if (msg.client_id) {
            this.events.onClientWaiting(
              msg.client_id,
              msg.client_token,
              msg.meta
            );
          }
          break;

        case "client_disconnected":
          if (msg.client_id) {
            this.events.onClientDisconnected(msg.client_id);
          }
          break;

        case "error":
          this.events.onError(new Error(msg.message || "Relay error"));
          break;

        case "event":
          if (this.events.onEvent && typeof msg.seq === "number") {
            this.events.onEvent({
              seq: msg.seq,
              event_type: msg.event_type,
              sender_key_id: msg.sender_key_id,
              payloads: msg.payloads,
            });
          }
          break;

        case "draining":
          // Server is draining, reconnect
          this.close();
          this.events.onClose(1012);
          break;

        case "revoked":
          // Relay is about to close this socket with code 4001 because
          // the key was revoked (or the account was deleted). Surface
          // the fact to the daemon BEFORE the close event fires so the
          // reconnect loop has a chance to short-circuit. The close
          // listener will still fire with code 4001 afterwards.
          this.events.onRevoked?.();
          break;
      }
    } catch {
      // Ignore unparseable text
    }
  }
}
