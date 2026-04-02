import sodium from "libsodium-wrappers-sumo";
import type { SecretStore } from "../storage/secret-store.ts";

export interface Config {
  publicKey: Uint8Array;      // Curve25519 DH public key (for Noise NK)
  secretKey: Uint8Array;      // Curve25519 DH secret key
  secret: Uint8Array;         // 32-byte random pairing secret
  signPublicKey: Uint8Array;  // Ed25519 signing public key (for relay auth)
  signSecretKey: Uint8Array;  // Ed25519 signing secret key
}

interface ConfigJSON {
  publicKey: string;
  secretKey: string;
  secret: string;
  signPublicKey: string;
  signSecretKey: string;
}

/** Ensure libsodium is initialized before use. */
export async function ready(): Promise<void> {
  await sodium.ready;
}

/** Generate a Curve25519 keypair for Noise NK DH. */
export function generateKeypair(): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
} {
  const { publicKey, privateKey } = sodium.crypto_box_keypair();
  return { publicKey, secretKey: privateKey };
}

/** Generate an Ed25519 keypair for signing (relay auth). */
export function generateSigningKeypair(): {
  signPublicKey: Uint8Array;
  signSecretKey: Uint8Array;
} {
  const { publicKey, privateKey } = sodium.crypto_sign_keypair();
  return { signPublicKey: publicKey, signSecretKey: privateKey };
}

/** Generate a 32-byte random secret. */
export function generateSecret(): Uint8Array {
  return sodium.randombytes_buf(32);
}

function b64(buf: Uint8Array): string {
  return sodium.to_base64(buf, sodium.base64_variants.ORIGINAL);
}
function fromB64(s: string): Uint8Array {
  return sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
}

function encodeConfig(config: Config): Uint8Array {
  const json: ConfigJSON = {
    publicKey: b64(config.publicKey),
    secretKey: b64(config.secretKey),
    secret: b64(config.secret),
    signPublicKey: b64(config.signPublicKey),
    signSecretKey: b64(config.signSecretKey),
  };
  return new TextEncoder().encode(JSON.stringify(json));
}

function decodeConfig(bytes: Uint8Array): Config | null {
  try {
    const json: ConfigJSON = JSON.parse(new TextDecoder().decode(bytes));
    if (!json.signPublicKey || !json.signSecretKey) return null;
    return {
      publicKey: fromB64(json.publicKey),
      secretKey: fromB64(json.secretKey),
      secret: fromB64(json.secret),
      signPublicKey: fromB64(json.signPublicKey),
      signSecretKey: fromB64(json.signSecretKey),
    };
  } catch {
    return null;
  }
}

/**
 * Ensure a config exists in the given store. If not, generate one and
 * persist it. Returns the config and whether it was newly created.
 */
export async function setupConfig(
  store: SecretStore
): Promise<{ config: Config; created: boolean }> {
  await ready();

  const existingBytes = await store.load("config");
  if (existingBytes) {
    const existing = decodeConfig(existingBytes);
    if (existing) return { config: existing, created: false };
  }

  const { publicKey, secretKey } = generateKeypair();
  const { signPublicKey, signSecretKey } = generateSigningKeypair();
  const secret = generateSecret();
  const config: Config = {
    publicKey,
    secretKey,
    secret,
    signPublicKey,
    signSecretKey,
  };

  await store.save("config", encodeConfig(config));
  return { config, created: true };
}
