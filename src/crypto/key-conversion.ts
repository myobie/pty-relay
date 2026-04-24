import sodium from "libsodium-wrappers-sumo";
import { ready } from "./index.ts";

/**
 * Derive the Curve25519 public key corresponding to an Ed25519 public key.
 * Lets us use a single Ed25519 identity for both account-level signing and
 * Noise DH (NK responder static). libsodium guarantees the conversion is
 * deterministic so both parties reach the same Curve25519 key.
 */
export async function ed25519PkToCurve25519(edPk: Uint8Array): Promise<Uint8Array> {
  await ready();
  if (edPk.length !== 32) {
    throw new Error(`ed25519 public key must be 32 bytes, got ${edPk.length}`);
  }
  return sodium.crypto_sign_ed25519_pk_to_curve25519(edPk);
}

/**
 * Derive the Curve25519 secret key corresponding to an Ed25519 secret key.
 * libsodium's Ed25519 secret key is 64 bytes (seed + public); the Curve25519
 * output is 32 bytes.
 */
export async function ed25519SkToCurve25519(edSk: Uint8Array): Promise<Uint8Array> {
  await ready();
  if (edSk.length !== 64) {
    throw new Error(`ed25519 secret key must be 64 bytes, got ${edSk.length}`);
  }
  return sodium.crypto_sign_ed25519_sk_to_curve25519(edSk);
}
