import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import sodium from "libsodium-wrappers-sumo";
import {
  ready,
  generateKeypair,
  generateSigningKeypair,
  generateSecret,
  setupConfig,
} from "../src/crypto/keys.ts";
import type { Config } from "../src/crypto/keys.ts";
import { PassphraseStore } from "../src/storage/passphrase-store.ts";
import { randomSalt } from "../src/crypto/aead.ts";

function makeConfig(): Config {
  const { publicKey, secretKey } = generateKeypair();
  const { signPublicKey, signSecretKey } = generateSigningKeypair();
  const secret = generateSecret();
  return { publicKey, secretKey, secret, signPublicKey, signSecretKey };
}

beforeAll(async () => {
  await ready();
  process.env.PTY_RELAY_KDF_PROFILE = "interactive";
});

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pty-relay-test-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

async function makeStore(dir: string): Promise<PassphraseStore> {
  const salt = randomSalt();
  return PassphraseStore.open(dir, "test-pass", salt, "interactive");
}

describe("generateKeypair", () => {
  it("returns 32-byte public key and 32-byte secret key", () => {
    const { publicKey, secretKey } = generateKeypair();
    expect(publicKey).toBeInstanceOf(Uint8Array);
    expect(secretKey).toBeInstanceOf(Uint8Array);
    expect(publicKey.length).toBe(32);
    expect(secretKey.length).toBe(32);
    expect(Buffer.from(publicKey).equals(Buffer.from(secretKey))).toBe(false);
  });

  it("produces unique keys each call", () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    expect(Buffer.from(kp1.publicKey).equals(Buffer.from(kp2.publicKey))).toBe(
      false
    );
  });
});

describe("generateSecret", () => {
  it("returns a 32-byte random buffer", () => {
    const secret = generateSecret();
    expect(secret).toBeInstanceOf(Uint8Array);
    expect(secret.length).toBe(32);
  });

  it("produces unique secrets each call", () => {
    const s1 = generateSecret();
    const s2 = generateSecret();
    expect(Buffer.from(s1).equals(Buffer.from(s2))).toBe(false);
  });
});

describe("setupConfig", () => {
  it("creates a new config if none exists", async () => {
    const store = await makeStore(tmp);
    const { config, created } = await setupConfig(store);
    expect(created).toBe(true);
    expect(config.publicKey.length).toBe(32);
    expect(config.secretKey.length).toBe(32);
    expect(config.secret.length).toBe(32);

    // File should exist (encrypted envelope)
    expect(fs.existsSync(path.join(tmp, "config.json"))).toBe(true);
  });

  it("does not overwrite existing config", async () => {
    const store = await makeStore(tmp);
    const { config: config1 } = await setupConfig(store);
    const { config: config2, created } = await setupConfig(store);

    expect(created).toBe(false);
    expect(
      Buffer.from(config2.publicKey).equals(Buffer.from(config1.publicKey))
    ).toBe(true);
    expect(
      Buffer.from(config2.secretKey).equals(Buffer.from(config1.secretKey))
    ).toBe(true);
    expect(
      Buffer.from(config2.secret).equals(Buffer.from(config1.secret))
    ).toBe(true);
  });

  it("written file is an encrypted envelope (no plaintext keys visible)", async () => {
    const store = await makeStore(tmp);
    const { config } = await setupConfig(store);

    const raw = fs.readFileSync(path.join(tmp, "config.json"), "utf-8");
    const b64PubKey = sodium.to_base64(
      config.publicKey,
      sodium.base64_variants.ORIGINAL
    );
    expect(raw).not.toContain(b64PubKey);
    expect(raw).toContain('"ct"');
  });
});
