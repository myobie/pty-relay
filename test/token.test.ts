import { describe, it, expect, beforeAll } from "vitest";
import {
  ready,
  generateKeypair,
  generateSecret,
} from "../src/crypto/keys.ts";
import {
  createToken,
  parseToken,
  computeSecretHash,
  getWebSocketUrl,
} from "../src/crypto/token.ts";

beforeAll(async () => {
  await ready();
});

describe("createToken", () => {
  it("produces a valid http:// URL for localhost", () => {
    const { publicKey } = generateKeypair();
    const secret = generateSecret();

    const token = createToken("localhost:4000", publicKey, secret);
    expect(token).toMatch(/^http:\/\/localhost:4000#/);

    // Fragment should contain exactly one "." separator
    const fragment = new URL(token).hash.slice(1);
    expect(fragment.split(".").length).toBe(2);
  });

  it("produces https:// URL for non-localhost", () => {
    const { publicKey } = generateKeypair();
    const secret = generateSecret();

    const token = createToken("relay.example.com", publicKey, secret);
    expect(token).toMatch(/^https:\/\/relay\.example\.com#/);
  });

  it("includes session name in path", () => {
    const { publicKey } = generateKeypair();
    const secret = generateSecret();

    const token = createToken(
      "localhost:4000",
      publicKey,
      secret,
      "my-session"
    );
    expect(token).toMatch(/^http:\/\/localhost:4000\/my-session#/);
  });

  it("appends clientToken as third fragment segment", () => {
    const { publicKey } = generateKeypair();
    const secret = generateSecret();

    const token = createToken("localhost:4000", publicKey, secret, undefined, "abc123");
    const fragment = new URL(token).hash.slice(1);
    const parts = fragment.split(".");
    expect(parts.length).toBe(3);
    expect(parts[2]).toBe("abc123");
  });

  it("produces 2-segment fragment without clientToken", () => {
    const { publicKey } = generateKeypair();
    const secret = generateSecret();

    const token = createToken("localhost:4000", publicKey, secret);
    const fragment = new URL(token).hash.slice(1);
    expect(fragment.split(".").length).toBe(2);
  });
});

describe("parseToken", () => {
  it("extracts host, publicKey, and secret", () => {
    const { publicKey } = generateKeypair();
    const secret = generateSecret();

    const token = createToken("localhost:4000", publicKey, secret);
    const parsed = parseToken(token);

    expect(parsed.host).toBe("localhost:4000");
    expect(parsed.session).toBeNull();
    expect(Buffer.from(parsed.publicKey).equals(Buffer.from(publicKey))).toBe(
      true
    );
    expect(Buffer.from(parsed.secret).equals(Buffer.from(secret))).toBe(true);
  });

  it("extracts session name from path", () => {
    const { publicKey } = generateKeypair();
    const secret = generateSecret();

    const token = createToken(
      "localhost:4000",
      publicKey,
      secret,
      "my-session"
    );
    const parsed = parseToken(token);

    expect(parsed.session).toBe("my-session");
  });

  it("round-trips with createToken", () => {
    const { publicKey } = generateKeypair();
    const secret = generateSecret();

    const token = createToken(
      "relay.example.com",
      publicKey,
      secret,
      "test-session"
    );
    const parsed = parseToken(token);

    expect(parsed.host).toBe("relay.example.com");
    expect(parsed.session).toBe("test-session");
    expect(Buffer.from(parsed.publicKey).equals(Buffer.from(publicKey))).toBe(
      true
    );
    expect(Buffer.from(parsed.secret).equals(Buffer.from(secret))).toBe(true);
  });

  it("rejects invalid URLs", () => {
    expect(() => parseToken("not a url")).toThrow();
    expect(() => parseToken("ftp://example.com#abc.def")).toThrow(
      /scheme/
    );
    expect(() => parseToken("http://host#onlyonepart")).toThrow(/two or three/);
    expect(() => parseToken("http://host#!!!.???")).toThrow();
  });

  it("parses clientToken as null when absent", () => {
    const { publicKey } = generateKeypair();
    const secret = generateSecret();

    const token = createToken("localhost:4000", publicKey, secret);
    const parsed = parseToken(token);
    expect(parsed.clientToken).toBeNull();
  });

  it("parses clientToken from 3-segment fragment", () => {
    const { publicKey } = generateKeypair();
    const secret = generateSecret();

    const token = createToken("localhost:4000", publicKey, secret, undefined, "abc123def456");
    const parsed = parseToken(token);
    expect(parsed.clientToken).toBe("abc123def456");
  });

  it("round-trips with clientToken", () => {
    const { publicKey } = generateKeypair();
    const secret = generateSecret();

    const token = createToken("relay.example.com", publicKey, secret, "my-session", "tokenid123");
    const parsed = parseToken(token);

    expect(parsed.host).toBe("relay.example.com");
    expect(parsed.session).toBe("my-session");
    expect(parsed.clientToken).toBe("tokenid123");
    expect(Buffer.from(parsed.publicKey).equals(Buffer.from(publicKey))).toBe(true);
    expect(Buffer.from(parsed.secret).equals(Buffer.from(secret))).toBe(true);
  });

  it("rejects 4+ segment fragments", () => {
    const { publicKey } = generateKeypair();
    const secret = generateSecret();

    const token = createToken("localhost:4000", publicKey, secret);
    const withExtra = token + ".extra.extra2";
    expect(() => parseToken(withExtra)).toThrow(/two or three/);
  });
});

describe("computeSecretHash", () => {
  it("returns a 64-character hex string", () => {
    const secret = generateSecret();
    const hash = computeSecretHash(secret);

    expect(hash.length).toBe(64);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic for the same secret", () => {
    const secret = generateSecret();
    const hash1 = computeSecretHash(secret);
    const hash2 = computeSecretHash(secret);

    expect(hash1).toBe(hash2);
  });

  it("produces different hashes for different secrets", () => {
    const s1 = generateSecret();
    const s2 = generateSecret();

    expect(computeSecretHash(s1)).not.toBe(computeSecretHash(s2));
  });
});

describe("getWebSocketUrl", () => {
  it("uses ws:// for localhost", () => {
    const url = getWebSocketUrl("localhost:4000", "daemon", "abc123");
    expect(url).toBe("ws://localhost:4000/ws?role=daemon&secret_hash=abc123");
  });

  it("uses wss:// for non-localhost", () => {
    const url = getWebSocketUrl("relay.example.com", "client", "def456");
    expect(url).toBe(
      "wss://relay.example.com/ws?role=client&secret_hash=def456"
    );
  });

  it("appends client_token when provided", () => {
    const url = getWebSocketUrl("localhost:4000", "client", "abc123", undefined, "mytoken");
    expect(url).toBe(
      "ws://localhost:4000/ws?role=client&secret_hash=abc123&client_token=mytoken"
    );
  });

  it("does not append client_token when not provided", () => {
    const url = getWebSocketUrl("localhost:4000", "client", "abc123");
    expect(url).not.toContain("client_token");
  });
});
