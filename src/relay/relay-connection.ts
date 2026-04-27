import WebSocket from "ws";
import sodium from "libsodium-wrappers-sumo";
import {
  Handshake,
  NK,
  KK,
  Transport,
  type Pattern,
} from "../crypto/index.ts";
import type { Config } from "../crypto/index.ts";
import { log, now, sinceMs, redactAuthQuery } from "../log.ts";

/** Turn a rejected WS upgrade into a human-readable error string.
 *  Extracts the reason field from a JSON body when present; otherwise
 *  includes the raw body (trimmed). Adds extra hints for the relay's
 *  well-known 403 texts so a user with a pinned client key can tell
 *  immediately why pairing failed. Exported for tests. */
export function formatUpgradeRejection(status: number, body: string): string {
  let reason = "";
  const trimmed = body.trim();
  if (trimmed) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === "object") {
        const p = parsed as Record<string, unknown>;
        if (typeof p.error === "string") reason = p.error;
        else if (typeof p.reason === "string") reason = p.reason;
        else if (typeof p.message === "string") reason = p.message;
      }
    } catch {
      // Body wasn't JSON; surface it verbatim, capped.
      reason = trimmed.length > 256 ? `${trimmed.slice(0, 256)}…` : trimmed;
    }
  }
  let msg = `WS upgrade rejected with HTTP ${status}`;
  if (reason) msg += `: ${reason}`;
  // Known relay reason texts get a suggested next-action so the user
  // isn't left guessing why pairing failed — the actionable info
  // (check your pin, ask the daemon owner for an ACL row) isn't
  // obvious from the bare reason.
  const lowered = reason.toLowerCase();
  if (lowered.includes("pinned to a different daemon")) {
    msg +=
      "\nThis client key was claimed via a preauth from a specific daemon and cannot pair with any other daemon on the account." +
      "\nRun `pty-relay server status` to see which daemon this key is pinned to.";
  } else if (lowered.includes("not permitted")) {
    msg +=
      "\nAn ACL row denies this client → daemon pair. Ask a daemon-role key-holder on the account to `pty-relay server acls allow` it.";
  }
  return msg;
}

/**
 * Metadata that arrives in the relay's `paired` frame. Presence of a
 * field signals which Noise pattern the peer expects:
 *
 *   - Only `pairing_hash_id`      → client_mint (NK; joiner is
 *                                    anonymous, no registered key yet).
 *   - Only `client_public_key`    → client_pair       (KK; both sides
 *                                    are registered on the account).
 *   - Neither                     → self-hosted paired (NK).
 */
export interface PairedMeta {
  /** Present for enrollment peers; the daemon uses it as the
   *  `preauth_hash_id` in the minter signing payload. */
  pairing_hash_id?: string;
  /** Present for client_pair peers; the daemon derives the peer's
   *  Curve25519 Noise static via ed25519→curve25519 and feeds it into
   *  the KK handshake as `remoteStaticPublicKey`. Base64url. */
  client_public_key?: string;
}

export interface RelayEvents {
  onConnected?: () => void;
  onPaired: (meta: PairedMeta) => void;
  onHandshakeComplete: (transport: Transport) => void;
  onEncryptedMessage: (plaintext: Uint8Array) => void;
  onPeerDisconnected: () => void;
  onError: (error: Error) => void;
  onClose: (code?: number) => void;
  /** Relay sent `{"type":"revoked"}` (followed shortly by close code
   *  4001). The caller's auth key is no longer valid on this relay —
   *  don't auto-reconnect. Optional; callers without a handler fall
   *  back to onClose + whatever reconnect policy they have. */
  onRevoked?: () => void;
}

/**
 * Daemon-side WebSocket + Noise responder.
 *
 * Noise pattern is chosen at pair time from the paired frame's
 * metadata — the caller doesn't need to know which kind of client is
 * arriving. The daemon always contributes its static Curve25519
 * keypair (required for NK's responder pre-message and for KK's
 * `ss`/`es`/`se`).
 */
export class RelayConnection {
  private ws: WebSocket | null = null;
  private transport: Transport | null = null;
  private handshake: Handshake | null = null;
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

  connect(): void {
    this.state = "connecting";
    this.transport = null;
    this.handshake = null;

    const url =
      typeof this.wsUrlFactory === "function" ? this.wsUrlFactory() : this.wsUrlFactory;
    const connectStart = now();
    log("ws-pair", "connect", { url: redactAuthQuery(url) });
    this.ws = new WebSocket(url);
    this.ws.binaryType = "nodebuffer";

    this.ws.on("open", () => {
      this.state = "waiting";
      log("ws-pair", "open", { ms: sinceMs(connectStart) });
      this.events.onConnected?.();
    });

    this.ws.on("message", (data: Buffer | string, isBinary: boolean) => {
      if (isBinary) {
        this.handleBinaryMessage(Buffer.isBuffer(data) ? data : Buffer.from(data));
      } else {
        this.handleTextMessage(typeof data === "string" ? data : data.toString("utf-8"));
      }
    });

    this.ws.on("close", (code: number, reason: Buffer) => {
      // unexpected-response already closed us out and called onClose.
      // The subsequent ws "close" event (which fires after req.destroy)
      // would otherwise log a second "disconnected" and re-teardown.
      if (this.state === "closed") return;
      this.state = "closed";
      log("ws-pair", "close", {
        code,
        reason: reason?.toString?.() ?? "",
        ms: sinceMs(connectStart),
      });
      this.events.onClose(code);
    });

    this.ws.on("error", (err: Error) => {
      log("ws-pair", "error", {
        error: err?.message ?? "(empty)",
        type: (err as any)?.type,
        code: (err as any)?.code,
      });
      this.events.onError(err);
    });

    this.ws.on("unexpected-response", (req, res) => {
      log("ws-pair", "unexpected-response", {
        status: res.statusCode,
        ms: sinceMs(connectStart),
      });
      // Registering an 'unexpected-response' listener suppresses ws's
      // default auto-close, so we have to tear the request down
      // ourselves. Without this, the socket lingers and onClose never
      // fires — which in server/serve.ts means the ClientSession row
      // stays pinned in the MAX_CLIENTS-bounded map forever.
      //
      // Read a small bounded slice of the response body so the 403
      // reason text from the relay (e.g. "client is pinned to a
      // different daemon") reaches the user. Capped at 4KB — the
      // relay's bodies are always short JSON/text; anything larger
      // is unexpected and we'd rather cut it off than buffer pages.
      const chunks: Buffer[] = [];
      let total = 0;
      const MAX = 4096;
      res.on("data", (chunk: Buffer) => {
        if (total >= MAX) return;
        const take = Math.min(chunk.length, MAX - total);
        chunks.push(chunk.subarray(0, take));
        total += take;
      });
      res.on("end", () => {
        const body = chunks.length ? Buffer.concat(chunks).toString("utf8") : "";
        try { req.destroy(); } catch {}
        this.events.onError(
          new Error(formatUpgradeRejection(res.statusCode ?? 0, body))
        );
        this.state = "closed";
        this.events.onClose(res.statusCode);
      });
      res.on("error", () => {
        try { req.destroy(); } catch {}
        this.events.onError(
          new Error(`WS upgrade rejected with HTTP ${res.statusCode}`)
        );
        this.state = "closed";
        this.events.onClose(res.statusCode);
      });
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
    this.ws?.close();
  }

  isReady(): boolean {
    return this.state === "ready";
  }

  // ── Message Handling ──

  private handleTextMessage(text: string): void {
    let msg: any;
    try { msg = JSON.parse(text); } catch {
      log("ws-pair", "text: unparseable", { preview: text.slice(0, 80) });
      return;
    }
    log("ws-pair", "text recv", { type: msg.type });

    switch (msg.type) {
      case "paired": {
        const meta: PairedMeta = {
          pairing_hash_id:
            typeof msg.pairing_hash_id === "string" ? msg.pairing_hash_id : undefined,
          client_public_key:
            typeof msg.client_public_key === "string" ? msg.client_public_key : undefined,
        };
        // beginHandshake is synchronous by design: both `state =
        // "handshaking"` and `this.handshake = ...` must be set before
        // the *next* event-loop turn, otherwise a binary frame that
        // arrives in between would be dropped silently. The Curve25519
        // conversion we need for KK is a pure sync libsodium call;
        // `await ready()` happened at daemon startup so no await is
        // needed here.
        try {
          this.beginHandshake(meta);
        } catch (err) {
          this.events.onError(err instanceof Error ? err : new Error(String(err)));
          this.close();
          break;
        }
        this.events.onPaired(meta);
        break;
      }

      case "peer_disconnected":
        this.transport = null;
        this.handshake = null;
        this.state = "waiting";
        this.events.onPeerDisconnected();
        break;

      case "error":
        this.events.onError(new Error(msg.message || "Relay error"));
        break;

      case "revoked":
        // Relay will follow up with close code 4001. Surface the
        // revocation so callers can mark the key dead instead of
        // looping on reconnect.
        log("ws-pair", "revoked frame — close imminent (code 4001)");
        this.events.onRevoked?.();
        break;
    }
  }

  /** Pick the Noise pattern from the paired metadata and construct
   *  the responder Handshake. Synchronous — see the caller's comment
   *  about the "paired → binary frame" race. */
  private beginHandshake(meta: PairedMeta): void {
    let pattern: Pattern;
    let remoteStaticPublicKey: Uint8Array | undefined;

    if (meta.client_public_key) {
      pattern = KK;
      const edBytes = sodium.from_base64(
        meta.client_public_key,
        sodium.base64_variants.URLSAFE_NO_PADDING
      );
      // Synchronous: libsodium's Ed25519→Curve25519 is a pure call,
      // and `await sodium.ready` happened globally at daemon start.
      remoteStaticPublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(edBytes);
    } else {
      pattern = NK;
    }

    // Assign handshake FIRST, then flip state. If this order is
    // inverted, handleBinaryMessage's `state === "handshaking" &&
    // this.handshake` guard could see (true, null) and silently drop
    // the first Noise message from a fast initiator.
    this.handshake = new Handshake({
      pattern,
      initiator: false,
      staticKeys: {
        publicKey: this.config.publicKey,
        privateKey: this.config.secretKey,
      },
      remoteStaticPublicKey,
    });
    this.state = "handshaking";
    log("ws-pair", "handshake begin", { pattern: pattern.name });
  }

  private handleBinaryMessage(data: Buffer): void {
    if (this.state === "handshaking" && this.handshake) {
      try {
        this.handshake.readMessage(new Uint8Array(data));
        const welcome = this.handshake.writeMessage();
        this.ws!.send(welcome);

        const result = this.handshake.split();
        this.transport = new Transport(result);
        this.state = "ready";
        this.handshake = null;

        log("ws-pair", "handshake complete + welcome sent", {
          welcomeBytes: welcome.length,
        });
        this.events.onHandshakeComplete(this.transport);
      } catch (err) {
        log("ws-pair", "handshake failed", { error: (err as any)?.message ?? String(err) });
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
        log("ws-pair", "decrypt failed", { error: (err as any)?.message ?? String(err) });
        this.events.onError(err instanceof Error ? err : new Error(String(err)));
        this.close();
      }
    }
  }
}
