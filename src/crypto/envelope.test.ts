import { describe, it, expect, beforeAll } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import { encode, decode, b64encode } from "./envelope.ts";
import { deriveKey, randomKey, randomSalt } from "./aead.ts";

beforeAll(async () => {
  await sodium.ready;
});

describe("envelope.encode / decode", () => {
  it("round-trips with a passphrase-derived key", async () => {
    const salt = randomSalt();
    const key = deriveKey("hunter2", salt, "interactive");
    const plaintext = new TextEncoder().encode("secret data");

    const json = encode(plaintext, key, {
      salt: b64encode(salt),
      profile: "interactive",
    });

    const parsed = JSON.parse(json);
    expect(parsed.v).toBe(1);
    expect(parsed.kdf.alg).toBe("argon2id");
    expect(parsed.kdf.profile).toBe("interactive");

    const decrypted = await decode(json, (kdf) => {
      expect(kdf).not.toBeNull();
      expect(kdf!.alg).toBe("argon2id");
      return deriveKey(
        "hunter2",
        sodium.from_base64(kdf!.salt, sodium.base64_variants.ORIGINAL),
        kdf!.profile
      );
    });
    expect(new TextDecoder().decode(decrypted)).toBe("secret data");
  });

  it("round-trips with a random key (kdf: null)", async () => {
    const key = randomKey();
    const plaintext = new TextEncoder().encode("keychain-stored");

    const json = encode(plaintext, key, null);
    const parsed = JSON.parse(json);
    expect(parsed.kdf).toBeNull();

    const decrypted = await decode(json, (kdf) => {
      expect(kdf).toBeNull();
      return key;
    });
    expect(new TextDecoder().decode(decrypted)).toBe("keychain-stored");
  });

  it("rejects unknown versions", async () => {
    const key = randomKey();
    const json = encode(new Uint8Array([1, 2, 3]), key, null);
    const parsed = JSON.parse(json);
    parsed.v = 2;
    await expect(decode(JSON.stringify(parsed), () => key)).rejects.toThrow(
      /unsupported version/i
    );
  });

  it("rejects missing nonce or ct", async () => {
    const key = randomKey();
    const json = encode(new Uint8Array([1, 2, 3]), key, null);
    const parsed = JSON.parse(json);
    delete parsed.nonce;
    await expect(decode(JSON.stringify(parsed), () => key)).rejects.toThrow(
      /missing nonce or ct/i
    );
  });

  it("rejects corrupted ciphertext", async () => {
    const key = randomKey();
    const json = encode(new TextEncoder().encode("hi"), key, null);
    const parsed = JSON.parse(json);
    // Flip a byte in the ct
    const rawCt = sodium.from_base64(parsed.ct, sodium.base64_variants.ORIGINAL);
    rawCt[0] ^= 0xff;
    parsed.ct = b64encode(rawCt);

    await expect(decode(JSON.stringify(parsed), () => key)).rejects.toThrow(
      /decryption failed/i
    );
  });

  it("rejects invalid base64 in nonce or ct", async () => {
    const key = randomKey();
    const env = {
      v: 1,
      kdf: null,
      nonce: "not valid base64 !!!",
      ct: "also not",
    };
    await expect(decode(JSON.stringify(env), () => key)).rejects.toThrow(
      /invalid base64/i
    );
  });

  it("rejects invalid JSON", async () => {
    const key = randomKey();
    await expect(decode("not json at all", () => key)).rejects.toThrow(
      /invalid JSON/i
    );
  });

  it("rejects invalid kdf section", async () => {
    const key = randomKey();
    const json = encode(new Uint8Array([1]), key, null);
    const parsed = JSON.parse(json);
    parsed.kdf = { alg: "bogus", salt: "x", profile: "interactive" };
    await expect(decode(JSON.stringify(parsed), () => key)).rejects.toThrow(
      /invalid kdf/i
    );
  });
});
