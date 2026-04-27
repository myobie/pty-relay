import sodium from "libsodium-wrappers-sumo";
import { createHash, randomUUID } from "node:crypto";
import { log } from "../log.ts";

/**
 * v2 canonical signed payloads for relay HTTP + WebSocket auth.
 *
 * Previously the signed payload was just `"<ts>.<uuid>"` — which meant
 * any captured `{public_key, payload, sig}` triple worked against any
 * signed endpoint the key was authorized on, with attacker-chosen
 * parameters. v2 binds the signature to METHOD + PATH + body/query
 * hash, so a captured sig for `/api/keys/revoke` can't be replayed
 * against `/api/account/delete`, and a WS upgrade sig for
 * `role=daemon` can't be replayed as `role=client_pair`.
 *
 * Wire format (six UTF-8 lines, no trailing newline):
 *
 *   v2
 *   <METHOD>        uppercase HTTP verb ("GET" for WS upgrades)
 *   <PATH>          request path without query, e.g. "/api/keys/revoke" or "/ws"
 *   <HASH>          lowercase hex sha256
 *                    - POST/PUT/DELETE: sha256 of raw body bytes
 *                    - GET / WS upgrade: sha256 of `canonical_query()`
 *                       (all query params EXCEPT public_key/payload/sig,
 *                        sorted by key, URL-encoded, joined with &)
 *   <ts>            unix seconds, ±60s freshness on the server
 *   <uuid>          opaque nonce, fresh per request
 */

/** Low-level detached Ed25519 sign over UTF-8 bytes. */
export function signPayload(
  payload: string,
  signSecretKey: Uint8Array
): Uint8Array {
  return sodium.crypto_sign_detached(
    new TextEncoder().encode(payload),
    signSecretKey
  );
}

/** Verify a detached Ed25519 signature. Returns false on any failure. */
export function verifySignature(
  payload: string,
  signature: Uint8Array,
  signPublicKey: Uint8Array
): boolean {
  try {
    return sodium.crypto_sign_verify_detached(
      signature,
      new TextEncoder().encode(payload),
      signPublicKey
    );
  } catch {
    return false;
  }
}

/** Lowercase hex SHA-256. Accepts a UTF-8 string or raw bytes. Used to
 *  build the HASH field in a v2 payload. */
export function sha256Hex(bin: string | Uint8Array): string {
  return createHash("sha256").update(bin).digest("hex");
}

/** Canonical query string used for GET and WS upgrade signatures.
 *
 *  - Excludes `public_key`, `payload`, `sig` (the auth triple itself
 *    never appears in the signed bytes — the signature is over
 *    everything else).
 *  - Keys sorted in ascending byte order.
 *  - Values URL-encoded with `encodeURIComponent` (matches the
 *    Elixir reference). Keys left verbatim because the relay only
 *    uses ASCII-safe keys; changing that on either side must be a
 *    coordinated protocol bump.
 */
export function canonicalQuery(params: Record<string, string>): string {
  return Object.entries(params)
    .filter(
      ([k]) => k !== "public_key" && k !== "payload" && k !== "sig"
    )
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join("&");
}

export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE";

export interface SignBinding {
  method: HttpMethod;
  /** Request path without query string. */
  path: string;
  /** Lowercase hex sha256 of body (POST/PUT/DELETE) or of
   *  `canonicalQuery(non_auth_params)` (GET/WS). Caller computes it. */
  hash: string;
  /** Unix seconds. Defaults to now. Overridable for deterministic tests. */
  ts?: number;
  /** Nonce. Defaults to `randomUUID()`. Overridable for deterministic tests. */
  uuid?: string;
}

/** Build the raw 6-line v2 payload. Exported for callers that want to
 *  sign/verify without the full `createAuthParams` wrapper (e.g. tests
 *  asserting on the exact bytes that get signed). */
export function buildV2Payload(binding: SignBinding): string {
  const ts = binding.ts ?? Math.floor(Date.now() / 1000);
  const uuid = binding.uuid ?? randomUUID();
  return [
    "v2",
    binding.method,
    binding.path,
    binding.hash,
    String(ts),
    uuid,
  ].join("\n");
}

/** Build the `{public_key, payload, sig}` triple callers fold into
 *  the query string (HTTP + WS, uniformly, as of v2). */
export function createAuthParams(
  signPublicKey: Uint8Array,
  signSecretKey: Uint8Array,
  binding: SignBinding
): { public_key: string; payload: string; sig: string } {
  const payload = buildV2Payload(binding);
  const sig = signPayload(payload, signSecretKey);
  log("sign", "createAuthParams", {
    method: binding.method,
    path: binding.path,
    ts: binding.ts ?? Math.floor(Date.now() / 1000),
  });

  return {
    public_key: sodium.to_base64(
      signPublicKey,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
    payload,
    sig: sodium.to_base64(sig, sodium.base64_variants.URLSAFE_NO_PADDING),
  };
}

export interface ParsedV2Payload {
  version: "v2";
  method: string;
  path: string;
  hash: string;
  ts: number;
  uuid: string;
}

/** Parse a v2 payload into its fields. Returns null if the input
 *  isn't a six-line v2 payload. Useful in tests that want to assert
 *  on bound fields without duplicating the line-splitting logic. */
export function parseV2Payload(payload: string): ParsedV2Payload | null {
  const lines = payload.split("\n");
  if (lines.length !== 6) return null;
  const [version, method, path, hash, tsStr, uuid] = lines;
  if (version !== "v2") return null;
  const ts = Number(tsStr);
  if (!Number.isFinite(ts)) return null;
  return { version: "v2", method, path, hash, ts, uuid };
}

/** Is the payload's timestamp within `maxAgeSeconds` of now? v2-only;
 *  v1 `"<ts>.<uuid>"` payloads parse as null and are rejected. */
export function isPayloadFresh(
  payload: string,
  maxAgeSeconds = 60
): boolean {
  const parsed = parseV2Payload(payload);
  if (!parsed) return false;
  const now = Math.floor(Date.now() / 1000);
  return Math.abs(now - parsed.ts) <= maxAgeSeconds;
}
