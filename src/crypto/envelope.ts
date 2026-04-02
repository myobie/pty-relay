import sodium from "libsodium-wrappers-sumo";
import { encryptBlob, decryptBlob, type KdfProfile } from "./aead.ts";

export interface KdfInfo {
  alg: "argon2id";
  salt: string;
  profile: KdfProfile;
}

export interface Envelope {
  v: 1;
  kdf: KdfInfo | null;
  nonce: string;
  ct: string;
}

/**
 * Encrypt plaintext using the given key and return a JSON envelope string.
 *
 * `kdfInfo` describes how the key was derived (salt + profile) so later calls
 * can re-derive it from a passphrase. Pass `null` for random keys (keychain).
 */
export function encode(
  plaintext: Uint8Array,
  key: Uint8Array,
  kdfInfo: { salt: string; profile: KdfProfile } | null
): string {
  const { nonce, ct } = encryptBlob(key, plaintext);

  const envelope: Envelope = {
    v: 1,
    kdf: kdfInfo
      ? { alg: "argon2id", salt: kdfInfo.salt, profile: kdfInfo.profile }
      : null,
    nonce: b64encode(nonce),
    ct: b64encode(ct),
  };

  return JSON.stringify(envelope);
}

/**
 * Decode an envelope JSON string.
 *
 * `deriveKeyFn` is called with the envelope's kdf info (or null for keychain
 * backend) and must return a 32-byte key.
 */
export async function decode(
  json: string,
  deriveKeyFn: (kdf: KdfInfo | null) => Uint8Array | Promise<Uint8Array>
): Promise<Uint8Array> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (err: any) {
    throw new Error(`envelope: invalid JSON: ${err?.message ?? err}`);
  }

  if (!parsed || typeof parsed !== "object") {
    throw new Error("envelope: not an object");
  }

  const env = parsed as Partial<Envelope>;

  if (env.v !== 1) {
    throw new Error(`envelope: unsupported version ${String(env.v)}`);
  }

  if (typeof env.nonce !== "string" || typeof env.ct !== "string") {
    throw new Error("envelope: missing nonce or ct");
  }

  let nonce: Uint8Array;
  let ct: Uint8Array;
  try {
    nonce = b64decode(env.nonce);
    ct = b64decode(env.ct);
  } catch (err: any) {
    throw new Error(`envelope: invalid base64: ${err?.message ?? err}`);
  }

  let kdf: KdfInfo | null = null;
  if (env.kdf !== null && env.kdf !== undefined) {
    const k = env.kdf;
    if (
      k.alg !== "argon2id" ||
      typeof k.salt !== "string" ||
      (k.profile !== "moderate" && k.profile !== "interactive")
    ) {
      throw new Error("envelope: invalid kdf section");
    }
    kdf = { alg: "argon2id", salt: k.salt, profile: k.profile };
  }

  const key = await deriveKeyFn(kdf);

  try {
    return decryptBlob(key, nonce, ct);
  } catch (err: any) {
    throw new Error(
      `envelope: decryption failed (wrong key or corrupted data): ${
        err?.message ?? err
      }`
    );
  }
}

export function b64encode(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}

export function b64decode(s: string): Uint8Array {
  return sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
}
