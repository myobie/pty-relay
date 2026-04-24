import sodium from "libsodium-wrappers-sumo";
import { ready } from "../../crypto/index.ts";
import { preauthSigningPayload } from "../../crypto/canonical-json.ts";
import { signPayload } from "../../crypto/signing.ts";

/**
 * Wire protocol messages exchanged over the Noise tunnel between a
 * minting daemon and a joining device. These are plain JSON frames on
 * top of the encrypted transport; no binary payloads.
 *
 * The relay historically called this "enroll" on the wire; the type
 * strings (`mint_request`, `mint_ready`) track the current server
 * vocabulary. Renaming at both ends on a flag day was part of the
 * 2026-04-22 relay migration.
 */

/** Joiner → Minter. */
export interface MintRequest {
  type: "mint_request";
  /** Joiner's newly-generated Ed25519 public key, base64url. */
  public_key: string;
  /** Host label the joiner wants to advertise. */
  label: string;
  /** Preauth claims always produce role=client on the new relay; the
   *  field is kept here so the minter side can see (and reject) any
   *  other value instead of blindly signing it. */
  role: "client";
  /** Joiner-chosen random nonce, base64url. The minter includes this in
   *  the canonical signing payload so replays with a different public_key
   *  or label produce a different hash. */
  nonce: string;
  /** Joiner-proposed expiry timestamp (unix seconds). Bounded server-side
   *  by the preauth's own ttl — the minter rejects anything > its pairing
   *  hash's expires_at. */
  exp: number;
}

/** Minter → Joiner. */
export interface MintReady {
  type: "mint_ready";
  /** Ed25519 signature over the canonical preauth signing payload,
   *  base64url. Joiner relays this to /api/keys/mint; the relay re-signs
   *  the same bytes with the minter's public key to verify. */
  minter_signature: string;
  /** Preauth hash id (ULID) — joiner cannot know this without the
   *  minter because it's an internal record id. */
  preauth_hash_id: string;
  /** Account id the joiner is minting into. Informational for the
   *  joiner's local state; not required for /api/keys/mint. */
  account_id: string;
}

/** Either direction can abort the flow with a typed error. */
export interface MintError {
  type: "error";
  message: string;
}

export type MintMessage = MintRequest | MintReady | MintError;

/**
 * Compute the minter's signature for a preauth claim.
 *
 * Pulled out as a pure function (no IO, no Noise state) so both the
 * minting daemon (serve) and the unit tests can call it directly.
 * If the TS canonical JSON ever drifts from the relay's byte-for-byte
 * output this is the function that lies — and the canonical-json.test.ts
 * fixtures are the first line of defense.
 */
export async function signMinterPayload(
  fields: {
    minterSecretKey: Uint8Array;
    accountId: string;
    joinerPublicKeyB64: string;
    preauthHashId: string;
    nonce: string;
    exp: number;
  }
): Promise<string> {
  await ready();
  const payload = preauthSigningPayload({
    accountId: fields.accountId,
    exp: fields.exp,
    nonce: fields.nonce,
    preauthHashId: fields.preauthHashId,
    publicKey: fields.joinerPublicKeyB64,
  });
  const sig = signPayload(payload, fields.minterSecretKey);
  return sodium.to_base64(sig, sodium.base64_variants.URLSAFE_NO_PADDING);
}

/** Build the /api/keys/mint POST body from an accepted MintReady. */
export function buildMintBody(
  req: MintRequest,
  ready: MintReady
): Record<string, unknown> {
  return {
    public_key: req.public_key,
    label: req.label,
    role: req.role,
    preauth_hash_id: ready.preauth_hash_id,
    nonce: req.nonce,
    exp: req.exp,
    minter_signature: ready.minter_signature,
  };
}

/** Generate a 16-byte base64url nonce for MintRequest.nonce. Matches
 *  the Elixir test client's `Base.url_encode64(:crypto.strong_rand_bytes(16))`. */
export async function newMintNonce(): Promise<string> {
  await ready();
  return sodium.to_base64(
    sodium.randombytes_buf(16),
    sodium.base64_variants.URLSAFE_NO_PADDING
  );
}
