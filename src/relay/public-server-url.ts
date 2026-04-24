import {
  createAuthParams,
  canonicalQuery,
  sha256Hex,
} from "../crypto/signing.ts";

/**
 * Build a signed WebSocket URL for a public-relay daemon role. Returns a
 * fresh signature each call — Ed25519 payloads are time-bounded (±60s on
 * the relay), so re-use on reconnect would fail.
 *
 * As of v2, the signature binds to `{method: "GET", path: "/ws",
 * hash: sha256(canonicalQuery(non_auth_params))}` — so a captured
 * URL signature for `role=daemon&client_id=abc` can't be replayed as
 * `role=client_pair&target_public_key=…`. The non-auth params are
 * whatever the relay needs for routing (role, label, client_id,
 * target_public_key).
 *
 * Modes:
 *   - primary daemon: no client_id; registers as the account's main socket
 *   - per-client daemon: client_id set; pairs with a specific waiting client
 */
export function buildPublicDaemonUrl(
  relayUrl: string,
  keys: { public: Uint8Array; secret: Uint8Array },
  opts: {
    label?: string;
    clientId?: string;
  } = {}
): string {
  const nonAuth: Record<string, string> = { role: "daemon" };
  if (opts.label) nonAuth.label = opts.label;
  if (opts.clientId) nonAuth.client_id = opts.clientId;
  return buildSignedWsUrl(relayUrl, keys, nonAuth);
}

/**
 * Build a signed WebSocket URL for a client-pair connection. Used when a
 * daily-use `pty-relay client connect <host>` targets a public-relay
 * daemon.
 *
 * `target_public_key` is the daemon's Ed25519 pubkey (the account-level
 * identity); the relay routes the pair to whichever daemon socket holds
 * that key. It's part of `canonical_query` so a sig for daemon A can't
 * be replayed to target daemon B.
 */
export function buildPublicClientPairUrl(
  relayUrl: string,
  keys: { public: Uint8Array; secret: Uint8Array },
  targetPublicKeyB64: string
): string {
  return buildSignedWsUrl(relayUrl, keys, {
    role: "client_pair",
    target_public_key: targetPublicKeyB64,
  });
}

/** Shared body: sign `{method: "GET", path: "/ws", hash: sha256(canonical)}`,
 *  append the `{public_key, payload, sig}` triple to the query. `params`
 *  must contain only the routing params — the auth triple is added here,
 *  after the hash has been committed to. */
function buildSignedWsUrl(
  relayUrl: string,
  keys: { public: Uint8Array; secret: Uint8Array },
  params: Record<string, string>
): string {
  const auth = createAuthParams(keys.public, keys.secret, {
    method: "GET",
    path: "/ws",
    hash: sha256Hex(canonicalQuery(params)),
  });
  const full = new URLSearchParams({
    ...params,
    public_key: auth.public_key,
    payload: auth.payload,
    sig: auth.sig,
  });
  return `${toWsUrl(relayUrl)}/ws?${full.toString()}`;
}

/** http(s):// → ws(s)://. Keeps hostname + port; strips a trailing slash. */
function toWsUrl(httpUrl: string): string {
  const u = new URL(httpUrl);
  const scheme = u.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${u.host}`;
}
