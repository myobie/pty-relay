import sodium from "libsodium-wrappers-sumo";
import { randomUUID } from "node:crypto";

/**
 * Create an auth payload for relay authentication.
 * Format: "timestamp.uuid" where timestamp is Unix seconds.
 */
export function createAuthPayload(): string {
  const timestamp = Math.floor(Date.now() / 1000);
  const uuid = randomUUID();
  return `${timestamp}.${uuid}`;
}

/**
 * Sign a payload with an Ed25519 secret key.
 * Returns a detached signature as Uint8Array (64 bytes).
 */
export function signPayload(
  payload: string,
  signSecretKey: Uint8Array
): Uint8Array {
  return sodium.crypto_sign_detached(
    new TextEncoder().encode(payload),
    signSecretKey
  );
}

/**
 * Verify an Ed25519 signature against a payload and public key.
 */
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

/**
 * Check that a payload's timestamp is within the allowed window.
 * Payload format: "timestamp.uuid"
 */
export function isPayloadFresh(
  payload: string,
  maxAgeSeconds: number = 60
): boolean {
  const dot = payload.indexOf(".");
  if (dot === -1) return false;

  const timestamp = parseInt(payload.slice(0, dot), 10);
  if (isNaN(timestamp)) return false;

  const now = Math.floor(Date.now() / 1000);
  return Math.abs(now - timestamp) <= maxAgeSeconds;
}

/**
 * Create a complete set of auth query params for a WebSocket connection.
 */
export function createAuthParams(
  signPublicKey: Uint8Array,
  signSecretKey: Uint8Array
): { public_key: string; payload: string; sig: string } {
  const payload = createAuthPayload();
  const sig = signPayload(payload, signSecretKey);

  return {
    public_key: sodium.to_base64(
      signPublicKey,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
    payload,
    sig: sodium.to_base64(sig, sodium.base64_variants.URLSAFE_NO_PADDING),
  };
}
