import sodium from "libsodium-wrappers-sumo";
import {
  ready,
  parseToken,
  computeSecretHash,
  getWebSocketUrl,
  Handshake,
  NK,
  KK,
  Transport,
} from "../crypto/index.ts";
import {
  ed25519PkToCurve25519,
  ed25519SkToCurve25519,
} from "../crypto/key-conversion.ts";
import { buildPublicClientPairUrl } from "./public-server-url.ts";
import type { EventRecord } from "@myobie/pty/client";
import type { PublicTarget, RemoteSession } from "./relay-client.ts";
import WebSocket from "ws";
import { log, redactAuthQuery } from "../log.ts";

export interface SubscribeRemoteEventsOptions {
  /** Called with the current running-session list right after each (re)connect.
   *  Consumers should use this to reconcile their view: everything not in the
   *  snapshot has "gone away" from their perspective. */
  onSnapshot: (sessions: RemoteSession[]) => void;
  /** Called for each event streamed from the remote daemon. `event.session`
   *  identifies the session. */
  onEvent: (event: EventRecord) => void;
  /** Called on non-fatal errors surfaced by the remote (e.g. "approval timed
   *  out" during a reconnect cycle). The subscription stays open; the library
   *  continues to retry. */
  onError?: (err: Error) => void;
  /** Called before each reconnect attempt. Useful for showing a "reconnecting…"
   *  indicator in a UI. `attempt` starts at 1 for the first retry. */
  onReconnecting?: (attempt: number) => void;
  /** Called when the library has given up after MAX_RECONNECT_ATTEMPTS. The
   *  subscription is terminal at this point — create a new one to resume. */
  onGaveUp?: () => void;
}

export interface RemoteEventsSubscription {
  /** Close the subscription. Disables further reconnects. */
  close(): void;
}

const INITIAL_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 30_000;
const BACKOFF_MULTIPLIER = 2;
const MAX_RECONNECT_ATTEMPTS = 30;
/** How long we give a subscription to go idle before assuming the tunnel
 *  is half-open. The server sends `event_ping` every 30s, so 75s is >2×
 *  that — any longer gap is almost certainly a dead TCP connection. */
const IDLE_TIMEOUT_MS = 75_000;

/**
 * Open a streaming event subscription against a remote daemon via the relay.
 *
 * The subscription is long-lived: it auto-reconnects with exponential backoff
 * on transient failures, and re-subscribes on every successful reconnect. Each
 * successful (re)connect delivers a fresh `onSnapshot` — consumers reconcile
 * their state against that rather than relying on a monotonic cursor.
 *
 * The returned handle's `close()` stops the current connection and disables
 * further reconnects.
 */
export function subscribeRemoteEvents(
  tokenUrl: string,
  options: SubscribeRemoteEventsOptions
): RemoteEventsSubscription {
  let closed = false;
  let ws: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let idleTimer: ReturnType<typeof setTimeout> | null = null;
  let attempts = 0;

  const clearReconnectTimer = () => {
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  };
  const clearIdleTimer = () => {
    if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
  };
  const resetIdleTimer = () => {
    clearIdleTimer();
    if (closed) return;
    idleTimer = setTimeout(() => {
      // Treat the tunnel as stale — force a reconnect.
      try { ws?.close(); } catch {}
    }, IDLE_TIMEOUT_MS);
  };

  const scheduleReconnect = () => {
    if (closed) return;
    if (attempts >= MAX_RECONNECT_ATTEMPTS) {
      log("events", "gave up", { attempts });
      options.onGaveUp?.();
      closed = true;
      return;
    }
    attempts++;
    options.onReconnecting?.(attempts);
    const delay = Math.min(
      INITIAL_BACKOFF_MS * Math.pow(BACKOFF_MULTIPLIER, attempts - 1),
      MAX_BACKOFF_MS
    );
    log("events", "scheduling reconnect", { attempt: attempts, delayMs: delay });
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connectOnce().catch((err) => {
        options.onError?.(err);
        scheduleReconnect();
      });
    }, delay);
  };

  async function connectOnce(): Promise<void> {
    await ready();
    if (closed) return;

    const parsed = parseToken(tokenUrl);
    const secretHash = computeSecretHash(parsed.secret);
    const wsUrl = getWebSocketUrl(
      parsed.host,
      "client",
      secretHash,
      undefined,
      parsed.clientToken ?? undefined
    );
    log("events", "connect (self-hosted)", { url: redactAuthQuery(wsUrl) });

    const sock = new WebSocket(wsUrl);
    ws = sock;
    sock.binaryType = "nodebuffer";

    let handshake: Handshake | null = null;
    let transport: Transport | null = null;

    const fatalError = (msg: string): void => {
      options.onError?.(new Error(msg));
      try { sock.close(); } catch {}
    };

    sock.onopen = () => { /* wait for "paired" text frame */ };

    sock.onmessage = (event) => {
      resetIdleTimer();
      if (typeof event.data === "string") {
        let msg: { type: string; [k: string]: unknown };
        try {
          msg = JSON.parse(event.data);
        } catch {
          return;
        }
        if (msg.type === "paired") {
          handshake = new Handshake({
            pattern: NK,
            initiator: true,
            remoteStaticPublicKey: parsed.publicKey,
          });
          sock.send(handshake.writeMessage());
        } else if (msg.type === "waiting_for_approval") {
          // The relay is holding us in the approval queue. There's no graceful
          // way for a long-lived subscription to wait here — treat it as a
          // transient connect failure so the reconnect loop keeps trying.
          fatalError("waiting for approval (not yet approved on this daemon)");
        } else if (msg.type === "error") {
          fatalError(String(msg.message ?? "relay error"));
        }
        return;
      }

      const data = Buffer.isBuffer(event.data)
        ? event.data
        : Buffer.from(event.data as ArrayBuffer);

      if (!transport && handshake) {
        // First binary: welcome. Finish the handshake, send events_subscribe.
        handshake.readMessage(new Uint8Array(data));
        transport = new Transport(handshake.split());
        handshake = null;
        attempts = 0; // successful handshake resets backoff
        const request = JSON.stringify({ type: "events_subscribe" });
        sock.send(transport.encrypt(new TextEncoder().encode(request)));
        return;
      }

      if (!transport) return;
      let plaintext: Uint8Array;
      try {
        plaintext = transport.decrypt(new Uint8Array(data));
      } catch (err: any) {
        // AEAD failure on the long-lived events stream: the tunnel is
        // compromised/desynced. Close and let the reconnect loop take
        // over rather than throw out of ws.onmessage.
        fatalError(`decrypt failed: ${err?.message ?? err}`);
        return;
      }
      let inner: { type: string; [k: string]: unknown };
      try {
        inner = JSON.parse(new TextDecoder().decode(plaintext));
      } catch {
        return;
      }
      switch (inner.type) {
        case "approved":
          // Silent ack for token-authed connections; see sendRemoteCommand.
          return;
        case "events_snapshot":
          options.onSnapshot((inner.sessions as RemoteSession[]) ?? []);
          return;
        case "event":
          if (inner.event) options.onEvent(inner.event as EventRecord);
          return;
        case "event_ping":
          return; // just keep-alive; resetIdleTimer already ran
        case "error":
          fatalError(String(inner.message ?? "remote error"));
          return;
      }
    };

    sock.onerror = (evt) => {
      // `ws` fires onerror + onclose; let onclose drive the reconnect.
      const message = (evt as { message?: string }).message ?? "websocket error";
      options.onError?.(new Error(message));
    };

    sock.onclose = () => {
      log("events", "close (self-hosted)");
      clearIdleTimer();
      ws = null;
      if (closed) return;
      scheduleReconnect();
    };
  }

  // Initial connect (async, but we return the handle synchronously).
  connectOnce().catch((err) => {
    options.onError?.(err);
    scheduleReconnect();
  });

  return {
    close(): void {
      closed = true;
      clearReconnectTimer();
      clearIdleTimer();
      try { ws?.close(); } catch {}
      ws = null;
    },
  };
}

/**
 * Public-relay twin of `subscribeRemoteEvents`: same semantics, but the
 * transport is `role=client_pair` + Ed25519-signed query params instead
 * of self-hosted `role=client` + secret_hash.
 *
 * Target's Noise responder static is derived from its Ed25519 pubkey
 * (matching what the minter uses). A fresh URL is built on every
 * (re)connect because Ed25519 payloads expire after 60 seconds.
 */
export function subscribePublicRemoteEvents(
  target: PublicTarget,
  options: SubscribeRemoteEventsOptions
): RemoteEventsSubscription {
  let closed = false;
  let ws: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let idleTimer: ReturnType<typeof setTimeout> | null = null;
  let attempts = 0;

  const clearReconnectTimer = () => {
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  };
  const clearIdleTimer = () => {
    if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
  };
  const resetIdleTimer = () => {
    clearIdleTimer();
    if (closed) return;
    idleTimer = setTimeout(() => {
      try { ws?.close(); } catch {}
    }, IDLE_TIMEOUT_MS);
  };

  const scheduleReconnect = () => {
    if (closed) return;
    if (attempts >= MAX_RECONNECT_ATTEMPTS) {
      log("events", "gave up", { attempts });
      options.onGaveUp?.();
      closed = true;
      return;
    }
    attempts++;
    options.onReconnecting?.(attempts);
    const delay = Math.min(
      INITIAL_BACKOFF_MS * Math.pow(BACKOFF_MULTIPLIER, attempts - 1),
      MAX_BACKOFF_MS
    );
    log("events", "scheduling reconnect", { attempt: attempts, delayMs: delay });
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connectOnce().catch((err) => {
        options.onError?.(err);
        scheduleReconnect();
      });
    }, delay);
  };

  async function connectOnce(): Promise<void> {
    await ready();
    if (closed) return;

    const wsUrl = buildPublicClientPairUrl(
      target.relayUrl,
      target.accountKeys,
      target.targetPublicKeyB64
    );
    log("events", "connect (public)", {
      url: redactAuthQuery(wsUrl),
      target: target.targetPublicKeyB64,
    });
    const targetEdBytes = sodium.from_base64(
      target.targetPublicKeyB64,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    const targetCurvePk = await ed25519PkToCurve25519(targetEdBytes);
    const clientStaticKeys = {
      publicKey: await ed25519PkToCurve25519(target.accountKeys.public),
      privateKey: await ed25519SkToCurve25519(target.accountKeys.secret),
    };

    const sock = new WebSocket(wsUrl);
    ws = sock;
    sock.binaryType = "nodebuffer";

    let handshake: Handshake | null = null;
    let transport: Transport | null = null;

    const fatalError = (msg: string): void => {
      options.onError?.(new Error(msg));
      try { sock.close(); } catch {}
    };

    sock.onopen = () => { /* wait for "paired" text frame */ };

    sock.onmessage = (event) => {
      resetIdleTimer();
      if (typeof event.data === "string") {
        let msg: { type: string; [k: string]: unknown };
        try {
          msg = JSON.parse(event.data);
        } catch {
          return;
        }
        if (msg.type === "paired") {
          handshake = new Handshake({
            pattern: KK,
            initiator: true,
            remoteStaticPublicKey: targetCurvePk,
            staticKeys: clientStaticKeys,
          });
          sock.send(handshake.writeMessage());
        } else if (msg.type === "error") {
          fatalError(String(msg.message ?? "relay error"));
        }
        // Public-mode never emits waiting_for_approval.
        return;
      }

      const data = Buffer.isBuffer(event.data)
        ? event.data
        : Buffer.from(event.data as ArrayBuffer);

      if (!transport && handshake) {
        handshake.readMessage(new Uint8Array(data));
        transport = new Transport(handshake.split());
        handshake = null;
        attempts = 0;
        const request = JSON.stringify({ type: "events_subscribe" });
        sock.send(transport.encrypt(new TextEncoder().encode(request)));
        return;
      }

      if (!transport) return;
      let plaintext: Uint8Array;
      try {
        plaintext = transport.decrypt(new Uint8Array(data));
      } catch (err: any) {
        fatalError(`decrypt failed: ${err?.message ?? err}`);
        return;
      }
      let inner: { type: string; [k: string]: unknown };
      try {
        inner = JSON.parse(new TextDecoder().decode(plaintext));
      } catch {
        return;
      }
      switch (inner.type) {
        case "events_snapshot":
          options.onSnapshot((inner.sessions as RemoteSession[]) ?? []);
          return;
        case "event":
          if (inner.event) options.onEvent(inner.event as EventRecord);
          return;
        case "event_ping":
          return;
        case "error":
          fatalError(String(inner.message ?? "remote error"));
          return;
      }
    };

    sock.onerror = (evt) => {
      const message = (evt as { message?: string }).message ?? "websocket error";
      options.onError?.(new Error(message));
    };

    sock.onclose = () => {
      log("events", "close (public)");
      clearIdleTimer();
      ws = null;
      if (closed) return;
      scheduleReconnect();
    };
  }

  connectOnce().catch((err) => {
    options.onError?.(err);
    scheduleReconnect();
  });

  return {
    close(): void {
      closed = true;
      clearReconnectTimer();
      clearIdleTimer();
      try { ws?.close(); } catch {}
      ws = null;
    },
  };
}
