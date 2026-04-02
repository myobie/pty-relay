import { describe, it, expect, beforeAll } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import {
  deriveKey,
  encryptBlob,
  decryptBlob,
  randomSalt,
  randomKey,
  zeroize,
} from "./aead.ts";

beforeAll(async () => {
  await sodium.ready;
});

describe("encryptBlob / decryptBlob", () => {
  it("round-trips a plaintext", () => {
    const key = randomKey();
    const plaintext = new TextEncoder().encode("hello, world");
    const { nonce, ct } = encryptBlob(key, plaintext);

    expect(nonce.length).toBe(24);
    expect(ct.length).toBeGreaterThan(plaintext.length); // includes MAC

    const decrypted = decryptBlob(key, nonce, ct);
    expect(new TextDecoder().decode(decrypted)).toBe("hello, world");
  });

  it("produces distinct nonces each call", () => {
    const key = randomKey();
    const plaintext = new TextEncoder().encode("same message");
    const a = encryptBlob(key, plaintext);
    const b = encryptBlob(key, plaintext);
    expect(Buffer.from(a.nonce).equals(Buffer.from(b.nonce))).toBe(false);
    expect(Buffer.from(a.ct).equals(Buffer.from(b.ct))).toBe(false);
  });

  it("fails to decrypt with the wrong key", () => {
    const key = randomKey();
    const wrongKey = randomKey();
    const plaintext = new TextEncoder().encode("secret");
    const { nonce, ct } = encryptBlob(key, plaintext);
    expect(() => decryptBlob(wrongKey, nonce, ct)).toThrow();
  });

  it("fails to decrypt with the wrong nonce", () => {
    const key = randomKey();
    const plaintext = new TextEncoder().encode("secret");
    const { ct } = encryptBlob(key, plaintext);
    const wrongNonce = new Uint8Array(24);
    expect(() => decryptBlob(key, wrongNonce, ct)).toThrow();
  });
});

describe("deriveKey", () => {
  it("produces the same key for the same inputs", () => {
    const salt = randomSalt();
    const a = deriveKey("hunter2", salt, "interactive");
    const b = deriveKey("hunter2", salt, "interactive");
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });

  it("produces different keys for different passphrases", () => {
    const salt = randomSalt();
    const a = deriveKey("pass1", salt, "interactive");
    const b = deriveKey("pass2", salt, "interactive");
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it("produces different keys for different salts", () => {
    const a = deriveKey("hunter2", randomSalt(), "interactive");
    const b = deriveKey("hunter2", randomSalt(), "interactive");
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it("returns a 32-byte key", () => {
    const key = deriveKey("hunter2", randomSalt(), "interactive");
    expect(key.length).toBe(32);
  });

  it("interactive profile is much faster than moderate", () => {
    const salt = randomSalt();
    const start1 = Date.now();
    deriveKey("hunter2", salt, "interactive");
    const interactiveMs = Date.now() - start1;

    const start2 = Date.now();
    deriveKey("hunter2", salt, "moderate");
    const moderateMs = Date.now() - start2;

    // Moderate should be noticeably slower than interactive.
    expect(moderateMs).toBeGreaterThan(interactiveMs);
  }, 10000);
});

describe("randomSalt / randomKey", () => {
  it("returns salts of the right length", () => {
    expect(randomSalt().length).toBe(16);
  });

  it("returns keys of the right length", () => {
    expect(randomKey().length).toBe(32);
  });

  it("produces unique values", () => {
    const a = randomKey();
    const b = randomKey();
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe("zeroize", () => {
  it("overwrites a buffer with zeros", () => {
    const buf = new Uint8Array([1, 2, 3, 4, 5]);
    zeroize(buf);
    expect(Array.from(buf)).toEqual([0, 0, 0, 0, 0]);
  });
});
