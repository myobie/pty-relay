import {
  ready,
  parseToken,
  computeSecretHash,
  getWebSocketUrl,
  Handshake,
  NK,
  KK,
  Transport,
  type Pattern,
} from "../crypto/index.ts";
import type { ParsedToken } from "../crypto/index.ts";
import WebSocket from "ws";
import sodium from "libsodium-wrappers-sumo";
import {
  ed25519PkToCurve25519,
  ed25519SkToCurve25519,
} from "../crypto/key-conversion.ts";
import { buildPublicClientPairUrl } from "./public-server-url.ts";
import { formatUpgradeRejection } from "./relay-connection.ts";
import { log, now, sinceMs, redactAuthQuery } from "../log.ts";

export interface RemoteSession {
  name: string;
  status: string;
  /** Optional presentation name set by `pty rename` or a `pty run` without
   *  --no-display-name. When present, UIs should lead with this and use
   *  `name` only as the stable identifier. */
  displayName?: string;
  command?: string;
  cwd?: string;
  tags?: Record<string, string>;
}

export interface RemoteListResult {
  sessions: RemoteSession[];
  spawnEnabled: boolean;
}

/**
 * Perform a Noise-handshake + one-shot encrypted JSON request/response
 * against a remote daemon. Sends `request` after the handshake completes
 * and resolves with the first decrypted response JSON object.
 *
 * This is the building block for all non-streaming remote CLIs:
 * list, peek, send, tag. Anything that wants a streaming response
 * (attach, events) should go through a different path.
 */
export async function sendRemoteCommand<TResponse = unknown>(
  tokenUrl: string,
  request: Record<string, unknown>,
  timeoutMs = 15000
): Promise<TResponse> {
  await ready();

  const parsed = parseToken(tokenUrl);
  const secretHash = computeSecretHash(parsed.secret);
  const wsUrl = getWebSocketUrl(
    parsed.host,
    "client",
    secretHash,
    undefined,
    parsed.clientToken ?? undefined
  );

  return sendOverTunnel<TResponse>(
    wsUrl,
    { pattern: NK, remoteStaticPublicKey: parsed.publicKey },
    request,
    timeoutMs
  );
}

/** Identifies a public-relay daemon target. Used by the public-mode
 *  one-shots below so `ls`, `peek`, `send`, `tag` can all share the
 *  same connection shape. */
export interface PublicTarget {
  relayUrl: string;
  /** Target daemon's Ed25519 public key, base64url. */
  targetPublicKeyB64: string;
  /** Caller's own Ed25519 keypair (raw bytes). */
  accountKeys: { public: Uint8Array; secret: Uint8Array };
}

/**
 * Public-relay twin of `sendRemoteCommand`: opens
 * `/ws?role=client_pair&target_public_key=...` with signed Ed25519
 * auth, does Noise NK against the target daemon's Curve25519 pubkey
 * (derived from its Ed25519), sends one encrypted JSON request, and
 * resolves with the first decrypted response.
 *
 * Retries transport-level failures a few times with short backoff.
 * fly.io's edge sometimes drops the first WS upgrade; the second or
 * third connection always works. Application errors (remote `{type:
 * "error"}` over the tunnel) bypass the retry and surface immediately.
 */
export async function sendPublicRemoteCommand<TResponse = unknown>(
  target: PublicTarget,
  request: Record<string, unknown>,
  timeoutMs = 15000
): Promise<TResponse> {
  await ready();

  // Both statics derived from Ed25519 pubkeys. The daemon learns our
  // static via the relay's paired-frame `client_public_key`; we pass
  // the target's via remoteStaticPublicKey.
  const targetEdBytes = sodium.from_base64(
    target.targetPublicKeyB64,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );
  const targetCurvePk = await ed25519PkToCurve25519(targetEdBytes);
  const clientStaticKeys = {
    publicKey: await ed25519PkToCurve25519(target.accountKeys.public),
    privateKey: await ed25519SkToCurve25519(target.accountKeys.secret),
  };

  const maxAttempts = 3;
  let lastErr: Error | null = null;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    // Fresh URL per attempt — Ed25519 signed payloads are time-bounded
    // and we want a new uuid so the relay doesn't collapse retries.
    const wsUrl = buildPublicClientPairUrl(
      target.relayUrl,
      target.accountKeys,
      target.targetPublicKeyB64
    );
    try {
      return await sendOverTunnel<TResponse>(
        wsUrl,
        {
          pattern: KK,
          remoteStaticPublicKey: targetCurvePk,
          staticKeys: clientStaticKeys,
        },
        request,
        timeoutMs
      );
    } catch (err: any) {
      const message = err?.message ?? String(err);
      // Retry transport-level failures + WS upgrade rejections from 5xx
      // (fly-proxy cold-start occasionally 503s before the app is live).
      // Application errors over the tunnel ("session not found") fail
      // fast; 4xx upgrade rejections (401 auth, 403 wrong account, etc.)
      // fail fast too — those are "you did something wrong."
      const isTransport =
        message.startsWith("Connection failed:") ||
        message.startsWith("WS closed before pairing") ||
        message.startsWith("Handshake failed:") ||
        message.startsWith("Timeout waiting for");
      const isRetriable5xx = /WS upgrade rejected with HTTP 5\d\d/.test(message);
      const retry = isTransport || isRetriable5xx;
      lastErr = err;
      if (!retry || attempt === maxAttempts - 1) {
        log("ws-oneshot", "give up", { attempt, reason: message });
        throw err;
      }
      const backoff = 250 * Math.pow(2, attempt); // 250, 500, 1000 ms
      log("ws-oneshot", "retry backoff", { attempt, backoffMs: backoff, reason: message });
      await new Promise((r) => setTimeout(r, backoff));
    }
  }
  throw lastErr!;
}

/** Handshake-layer config: pattern + required keys. */
interface NoiseConfig {
  pattern: Pattern;
  remoteStaticPublicKey: Uint8Array;
  staticKeys?: { publicKey: Uint8Array; privateKey: Uint8Array };
}

/** Core Noise one-shot: connect, handshake, send request, resolve with
 *  the first decrypted response. Transport-agnostic — used by both the
 *  self-hosted `sendRemoteCommand` and the public `sendPublicRemoteCommand`. */
function sendOverTunnel<TResponse>(
  wsUrl: string,
  noise: NoiseConfig,
  request: Record<string, unknown>,
  timeoutMs: number
): Promise<TResponse> {
  return new Promise<TResponse>((resolve, reject) => {
    const start = now();
    const safeUrl = redactAuthQuery(wsUrl);
    log("ws-oneshot", "connect", {
      url: safeUrl,
      pattern: noise.pattern.name ?? "?",
      requestType: request.type,
      timeoutMs,
    });
    const ws = new WebSocket(wsUrl);
    ws.binaryType = "nodebuffer";

    let handshake: Handshake | null = null;
    let transport: Transport | null = null;

    const timer = setTimeout(() => {
      ws.close();
      reject(new Error(`Timeout waiting for ${request.type ?? "response"}`));
    }, timeoutMs);

    // ws.onclose/onerror don't give us the rejected upgrade's response
    // body — only the 'unexpected-response' event on the underlying
    // ClientRequest does. Listen for it so a 403 from the relay (e.g.
    // "client is pinned to a different daemon") reaches the user with
    // the actionable reason text instead of a bare status code.
    (ws as any).on("unexpected-response", (req: any, res: any) => {
      const chunks: Buffer[] = [];
      let total = 0;
      const MAX = 4096;
      res.on("data", (chunk: Buffer) => {
        if (total >= MAX) return;
        const take = Math.min(chunk.length, MAX - total);
        chunks.push(chunk.subarray(0, take));
        total += take;
      });
      const finish = () => {
        const body = chunks.length ? Buffer.concat(chunks).toString("utf8") : "";
        try { req.destroy(); } catch {}
        clearTimeout(timer);
        reject(new Error(formatUpgradeRejection(res.statusCode ?? 0, body)));
      };
      res.on("end", finish);
      res.on("error", finish);
    });

    ws.onopen = () => {
      log("ws-oneshot", "open", { ms: sinceMs(start) });
    };

    ws.onmessage = (event) => {
      if (typeof event.data === "string") {
        const msg = JSON.parse(event.data);
        log("ws-oneshot", "text recv", { type: msg.type, ms: sinceMs(start) });
        if (msg.type === "paired") {
          handshake = new Handshake({
            pattern: noise.pattern,
            initiator: true,
            remoteStaticPublicKey: noise.remoteStaticPublicKey,
            staticKeys: noise.staticKeys,
          });
          const hello = handshake.writeMessage();
          log("ws-oneshot", "noise hello", { bytes: hello.length });
          ws.send(hello);
        } else if (msg.type === "waiting_for_approval") {
          clearTimeout(timer);
          ws.close();
          reject(new Error("Waiting for approval (not yet approved on this daemon)"));
        } else if (msg.type === "error") {
          clearTimeout(timer);
          ws.close();
          reject(new Error(msg.message));
        } else if (msg.type === "revoked") {
          // Relay will follow up with close code 4001. Reject the
          // in-flight request immediately with a clear reason instead
          // of letting the close handler surface a generic 1005/1006.
          clearTimeout(timer);
          ws.close();
          reject(new Error("Key revoked by relay — re-enroll this device before retrying."));
        }
      } else {
        const data = Buffer.isBuffer(event.data)
          ? event.data
          : Buffer.from(event.data as ArrayBuffer);

        if (!transport && handshake) {
          log("ws-oneshot", "noise welcome recv", { bytes: data.length });
          try {
            handshake.readMessage(new Uint8Array(data));
            transport = new Transport(handshake.split());
            handshake = null;
            log("ws-oneshot", "noise complete", { ms: sinceMs(start) });
          } catch (err: any) {
            clearTimeout(timer);
            ws.close();
            reject(new Error(`Handshake failed: ${err?.message ?? err}`));
            return;
          }

          // Send the request now that the transport is open.
          const payload = JSON.stringify(request);
          const ct = transport.encrypt(new TextEncoder().encode(payload));
          log("ws-oneshot", "encrypted request sent", {
            requestType: request.type,
            bytes: ct.length,
            ms: sinceMs(start),
          });
          ws.send(ct);
        } else if (transport) {
          // decrypt throws on AEAD failure (corrupt/replayed frame,
          // desynchronized nonce). A bare throw escapes ws.onmessage
          // as uncaught; reject the promise cleanly instead.
          let plaintext: Uint8Array;
          try {
            plaintext = transport.decrypt(new Uint8Array(data));
          } catch (err: any) {
            clearTimeout(timer);
            ws.close();
            reject(new Error(`decrypt failed: ${err?.message ?? err}`));
            return;
          }
          try {
            const msg = JSON.parse(new TextDecoder().decode(plaintext));
            log("ws-oneshot", "encrypted response recv", {
              type: msg.type,
              bytes: data.length,
              ms: sinceMs(start),
            });
            // "approved" is an unsolicited post-handshake notification the
            // self-hosted daemon sends when the client was authenticated
            // via a token. It's informational and must NOT end the request.
            // Public-mode never emits it.
            if (msg.type === "approved") {
              return;
            }
            // Remote can signal a per-request error over the tunnel.
            if (msg.type === "error") {
              clearTimeout(timer);
              ws.close();
              reject(new Error(msg.message || "remote error"));
              return;
            }
            clearTimeout(timer);
            log("ws-oneshot", "resolve + close", { ms: sinceMs(start) });
            ws.close();
            resolve(msg as TResponse);
          } catch {
            // Non-JSON / partial; wait for the next packet.
          }
        }
      }
    };

    ws.onerror = (err) => {
      clearTimeout(timer);
      // Keep the original error message if we have one; surface the error
      // *type* via a debug env var if the empty-message case turns up in
      // the wild (usually a network/TLS-level failure we can't narrow).
      const detail =
        err?.message ||
        (err as any)?.code ||
        (err as any)?.type ||
        "(no detail)";
      log("ws-oneshot", "error", { detail, ms: sinceMs(start) });
      reject(new Error(`Connection failed: ${detail}`));
    };

    // Helpful diagnostic for the empty-error case: if the WS closes before
    // the handshake completes with a non-1000 code, surface that. Doesn't
    // fire on normal success (the timer resolve path tears down first).
    ws.onclose = (ev: any) => {
      log("ws-oneshot", "close", {
        code: ev?.code,
        reason: ev?.reason,
        hadTransport: !!transport,
        hadHandshake: !!handshake,
        ms: sinceMs(start),
      });
      if (!transport && !handshake) {
        // Never got past the WebSocket upgrade OR never heard "paired".
        clearTimeout(timer);
        reject(
          new Error(
            `WS closed before pairing (code=${ev?.code ?? "?"}, reason=${ev?.reason ?? ""})`
          )
        );
      }
    };
  });
}

/**
 * Connect to a daemon via the relay, perform the Noise NK handshake,
 * and list its running sessions. Returns the session list and whether
 * the daemon supports spawning new sessions.
 */
export async function listRemoteSessions(
  tokenUrl: string,
  timeoutMs = 15000
): Promise<RemoteListResult> {
  const response = await sendRemoteCommand<{
    type: string;
    sessions?: RemoteSession[];
    spawn_enabled?: boolean;
  }>(tokenUrl, { type: "list" }, timeoutMs);
  if (response.type !== "sessions") {
    throw new Error(`Unexpected response type: ${response.type}`);
  }
  return {
    sessions: response.sessions || [],
    spawnEnabled: !!response.spawn_enabled,
  };
}

export interface RemotePeekResult {
  screen: string;
}

export async function peekRemoteSession(
  tokenUrl: string,
  session: string,
  opts: {
    plain?: boolean;
    full?: boolean;
    /** Wait until one of these substrings appears on the plain-text screen. */
    wait?: string[];
    /** Maximum seconds the server will poll (0 / undefined = no timeout). */
    timeoutSec?: number;
  } = {},
  timeoutMs?: number
): Promise<RemotePeekResult> {
  // Pick a WS timeout that outlives the server-side poll; otherwise the
  // encrypted channel fires its own "Timeout waiting for peek" before the
  // server gets a chance to reply. Add a small grace period.
  const resolvedTimeoutMs =
    timeoutMs ??
    (opts.wait && opts.wait.length > 0
      ? (opts.timeoutSec ? opts.timeoutSec * 1000 : 60_000) + 5_000
      : 15_000);
  const response = await sendRemoteCommand<{ type: string; screen?: string }>(
    tokenUrl,
    {
      type: "peek",
      session,
      plain: !!opts.plain,
      full: !!opts.full,
      ...(opts.wait && opts.wait.length > 0 ? { wait: opts.wait } : {}),
      ...(opts.timeoutSec ? { timeoutSec: opts.timeoutSec } : {}),
    },
    resolvedTimeoutMs
  );
  if (response.type !== "peek_result") {
    throw new Error(`Unexpected response type: ${response.type}`);
  }
  return { screen: response.screen ?? "" };
}

export async function sendToRemoteSession(
  tokenUrl: string,
  session: string,
  data: string[],
  opts: { delayMs?: number; paste?: boolean } = {},
  timeoutMs = 15000
): Promise<void> {
  const response = await sendRemoteCommand<{ type: string }>(
    tokenUrl,
    {
      type: "send",
      session,
      data,
      delayMs: opts.delayMs,
      ...(opts.paste ? { paste: true } : {}),
    },
    timeoutMs
  );
  if (response.type !== "send_ok") {
    throw new Error(`Unexpected response type: ${response.type}`);
  }
}

export interface RemoteTagResult {
  tags: Record<string, string>;
}

export async function tagRemoteSession(
  tokenUrl: string,
  session: string,
  opts: { set?: Record<string, string>; remove?: string[] } = {},
  timeoutMs = 15000
): Promise<RemoteTagResult> {
  const response = await sendRemoteCommand<{
    type: string;
    tags?: Record<string, string>;
  }>(
    tokenUrl,
    {
      type: "tag",
      session,
      ...(opts.set ? { set: opts.set } : {}),
      ...(opts.remove ? { remove: opts.remove } : {}),
    },
    timeoutMs
  );
  if (response.type !== "tag_result") {
    throw new Error(`Unexpected response type: ${response.type}`);
  }
  return { tags: response.tags ?? {} };
}

// ── Public-relay variants ────────────────────────────────────────────
// Parallel signatures that take a PublicTarget instead of a token URL.
// The on-the-wire request shapes are identical; only the transport
// (role=client_pair + Ed25519-signed URL, Curve25519-from-Ed25519 target)
// differs.

export async function listPublicRemoteSessions(
  target: PublicTarget,
  timeoutMs = 15000
): Promise<RemoteListResult> {
  const response = await sendPublicRemoteCommand<{
    type: string;
    sessions?: RemoteSession[];
    spawn_enabled?: boolean;
  }>(target, { type: "list" }, timeoutMs);
  if (response.type !== "sessions") {
    throw new Error(`Unexpected response type: ${response.type}`);
  }
  return {
    sessions: response.sessions || [],
    spawnEnabled: !!response.spawn_enabled,
  };
}

export async function peekPublicRemoteSession(
  target: PublicTarget,
  session: string,
  opts: {
    plain?: boolean;
    full?: boolean;
    wait?: string[];
    timeoutSec?: number;
  } = {},
  timeoutMs?: number
): Promise<RemotePeekResult> {
  const resolvedTimeoutMs =
    timeoutMs ??
    (opts.wait && opts.wait.length > 0
      ? (opts.timeoutSec ? opts.timeoutSec * 1000 : 60_000) + 5_000
      : 15_000);
  const response = await sendPublicRemoteCommand<{ type: string; screen?: string }>(
    target,
    {
      type: "peek",
      session,
      plain: !!opts.plain,
      full: !!opts.full,
      ...(opts.wait && opts.wait.length > 0 ? { wait: opts.wait } : {}),
      ...(opts.timeoutSec ? { timeoutSec: opts.timeoutSec } : {}),
    },
    resolvedTimeoutMs
  );
  if (response.type !== "peek_result") {
    throw new Error(`Unexpected response type: ${response.type}`);
  }
  return { screen: response.screen ?? "" };
}

export async function sendToPublicRemoteSession(
  target: PublicTarget,
  session: string,
  data: string[],
  opts: { delayMs?: number; paste?: boolean } = {},
  timeoutMs = 15000
): Promise<void> {
  const response = await sendPublicRemoteCommand<{ type: string }>(
    target,
    {
      type: "send",
      session,
      data,
      delayMs: opts.delayMs,
      ...(opts.paste ? { paste: true } : {}),
    },
    timeoutMs
  );
  if (response.type !== "send_ok") {
    throw new Error(`Unexpected response type: ${response.type}`);
  }
}

export async function tagPublicRemoteSession(
  target: PublicTarget,
  session: string,
  opts: { set?: Record<string, string>; remove?: string[] } = {},
  timeoutMs = 15000
): Promise<RemoteTagResult> {
  const response = await sendPublicRemoteCommand<{
    type: string;
    tags?: Record<string, string>;
  }>(
    target,
    {
      type: "tag",
      session,
      ...(opts.set ? { set: opts.set } : {}),
      ...(opts.remove ? { remove: opts.remove } : {}),
    },
    timeoutMs
  );
  if (response.type !== "tag_result") {
    throw new Error(`Unexpected response type: ${response.type}`);
  }
  return { tags: response.tags ?? {} };
}
