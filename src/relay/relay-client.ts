import {
  ready,
  parseToken,
  computeSecretHash,
  getWebSocketUrl,
  InitiatorHandshake,
  Transport,
} from "../crypto/index.ts";
import type { ParsedToken } from "../crypto/index.ts";
import WebSocket from "ws";

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

  return new Promise<TResponse>((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    ws.binaryType = "nodebuffer";

    let initiator: InstanceType<typeof InitiatorHandshake> | null = null;
    let transport: Transport | null = null;

    const timer = setTimeout(() => {
      ws.close();
      reject(new Error(`Timeout waiting for ${request.type ?? "response"}`));
    }, timeoutMs);

    ws.onopen = () => {};

    ws.onmessage = (event) => {
      if (typeof event.data === "string") {
        const msg = JSON.parse(event.data);
        if (msg.type === "paired") {
          initiator = new InitiatorHandshake(parsed.publicKey);
          ws.send(initiator.writeHello());
        } else if (msg.type === "waiting_for_approval") {
          clearTimeout(timer);
          ws.close();
          reject(new Error("Waiting for approval (not yet approved on this daemon)"));
        } else if (msg.type === "error") {
          clearTimeout(timer);
          ws.close();
          reject(new Error(msg.message));
        }
      } else {
        const data = Buffer.isBuffer(event.data)
          ? event.data
          : Buffer.from(event.data as ArrayBuffer);

        if (!transport && initiator) {
          const result = initiator.readWelcome(new Uint8Array(data));
          transport = new Transport(result);
          initiator = null;

          // Send the request now that the transport is open.
          const payload = JSON.stringify(request);
          const ct = transport.encrypt(new TextEncoder().encode(payload));
          ws.send(ct);
        } else if (transport) {
          const plaintext = transport.decrypt(new Uint8Array(data));
          try {
            const msg = JSON.parse(new TextDecoder().decode(plaintext));
            // "approved" is a unsolicited post-handshake notification the
            // daemon sends when the client was authenticated via a token.
            // It's informational (updates the saved known-hosts URL with
            // the accepted client_token) and must NOT end the request: the
            // actual response still needs to arrive on a later packet.
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
      reject(new Error(`Connection failed: ${err.message}`));
    };

    ws.onclose = () => {};
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
