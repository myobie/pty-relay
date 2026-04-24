/**
 * Byte-for-byte reproduction of Elixir's `Relay.Accounts.signing_payload/5`
 * output. Used to generate the exact bytes that Ed25519 signatures are
 * computed over for `/api/keys/mint`. A one-byte mismatch between sender and
 * verifier breaks signature verification, so the escape rules here must
 * stay locked to what Jason emits on the relay side.
 *
 * Rules:
 *   - Object keys emitted in alphabetical (byte-wise lexicographic) order.
 *   - Numbers emitted as plain integers — no floats in our signing payloads.
 *   - Strings use the standard JSON escape set: `"`, `\`, and control
 *     characters 0x00–0x1F. Forward slash `/` is NOT escaped. Non-ASCII
 *     passes through as raw UTF-8 (no `\uXXXX`). U+2028 / U+2029 also pass
 *     through (ES2019-aligned behavior, matches Jason).
 *   - Arrays preserve insertion order.
 *   - No whitespace.
 *
 * Verified against Elixir fixtures in test/canonical-json.test.ts.
 */

type CanonicalValue =
  | string
  | number
  | boolean
  | null
  | CanonicalValue[]
  | { [k: string]: CanonicalValue };

/** Recursively reorder keys so JSON.stringify emits them alphabetically. */
function sortKeys(value: CanonicalValue): CanonicalValue {
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  if (value !== null && typeof value === "object") {
    const sorted: { [k: string]: CanonicalValue } = {};
    for (const key of Object.keys(value).sort()) {
      sorted[key] = sortKeys(value[key]);
    }
    return sorted;
  }
  return value;
}

/** Canonical JSON string. Output matches Elixir's `Jason.encode!` byte-for-byte
 *  when the same keys/values are passed in. */
export function canonicalize(value: CanonicalValue): string {
  return JSON.stringify(sortKeys(value));
}

/** Canonical JSON bytes, ready to feed into Ed25519 sign/verify. */
export function canonicalizeBytes(value: CanonicalValue): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}

export interface PreauthSigningFields {
  accountId: string;
  exp: number;
  nonce: string;
  preauthHashId: string;
  publicKey: string;
}

/** Build the canonical signing payload for `/api/keys/mint` — the exact bytes
 *  the relay recomputes via `Relay.Accounts.preauth_signing_payload/5`. */
export function preauthSigningPayload(fields: PreauthSigningFields): string {
  return canonicalize({
    account_id: fields.accountId,
    exp: fields.exp,
    nonce: fields.nonce,
    preauth_hash_id: fields.preauthHashId,
    public_key: fields.publicKey,
  });
}
