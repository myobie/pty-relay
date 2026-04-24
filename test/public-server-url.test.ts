import { describe, it, expect, beforeAll } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import {
  buildPublicDaemonUrl,
  buildPublicClientPairUrl,
} from "../src/relay/public-server-url.ts";
import {
  verifySignature,
  isPayloadFresh,
  parseV2Payload,
  sha256Hex,
  canonicalQuery,
} from "../src/crypto/signing.ts";

beforeAll(async () => {
  await sodium.ready;
});

describe("buildPublicDaemonUrl", () => {
  it("emits ws:// for http relay URLs and includes signed auth", () => {
    const kp = sodium.crypto_sign_keypair();
    const url = buildPublicDaemonUrl(
      "http://localhost:4000",
      { public: kp.publicKey, secret: kp.privateKey },
      { label: "laptop" }
    );
    const u = new URL(url);
    expect(u.protocol).toBe("ws:");
    expect(u.host).toBe("localhost:4000");
    expect(u.pathname).toBe("/ws");
    expect(u.searchParams.get("role")).toBe("daemon");
    expect(u.searchParams.get("label")).toBe("laptop");
    expect(u.searchParams.get("client_id")).toBeNull();
    const payload = u.searchParams.get("payload")!;
    expect(isPayloadFresh(payload)).toBe(true);
    const sig = sodium.from_base64(
      u.searchParams.get("sig")!,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    expect(verifySignature(payload, sig, kp.publicKey)).toBe(true);
  });

  it("includes client_id for per-client daemon connections", () => {
    const kp = sodium.crypto_sign_keypair();
    const url = buildPublicDaemonUrl(
      "http://localhost:4000",
      { public: kp.publicKey, secret: kp.privateKey },
      { clientId: "abc123" }
    );
    expect(new URL(url).searchParams.get("client_id")).toBe("abc123");
  });

  it("upgrades to wss:// for https origins", () => {
    const kp = sodium.crypto_sign_keypair();
    const url = buildPublicDaemonUrl(
      "https://relay.pty.computer",
      { public: kp.publicKey, secret: kp.privateKey }
    );
    expect(new URL(url).protocol).toBe("wss:");
  });

  it("produces a fresh signature on each call (payload uuid changes)", () => {
    const kp = sodium.crypto_sign_keypair();
    const a = buildPublicDaemonUrl(
      "http://localhost:4000",
      { public: kp.publicKey, secret: kp.privateKey }
    );
    const b = buildPublicDaemonUrl(
      "http://localhost:4000",
      { public: kp.publicKey, secret: kp.privateKey }
    );
    expect(a).not.toBe(b);
  });
});

describe("buildPublicClientPairUrl", () => {
  it("builds a signed URL with role=client_pair and target_public_key", () => {
    const kp = sodium.crypto_sign_keypair();
    const url = buildPublicClientPairUrl(
      "http://localhost:4000",
      { public: kp.publicKey, secret: kp.privateKey },
      "target_pk_b64"
    );
    const u = new URL(url);
    expect(u.searchParams.get("role")).toBe("client_pair");
    expect(u.searchParams.get("target_public_key")).toBe("target_pk_b64");
    const payload = u.searchParams.get("payload")!;
    expect(isPayloadFresh(payload)).toBe(true);
  });

  it("v2 payload binds to role + target_public_key via canonical_query hash", () => {
    // A sig for role=client_pair&target_public_key=A must not verify
    // as role=client_pair&target_public_key=B, because the hash commits
    // to exactly those bytes.
    const kp = sodium.crypto_sign_keypair();
    const url = buildPublicClientPairUrl(
      "http://localhost:4000",
      { public: kp.publicKey, secret: kp.privateKey },
      "target_A"
    );
    const payload = new URL(url).searchParams.get("payload")!;
    const parsed = parseV2Payload(payload)!;
    expect(parsed.method).toBe("GET");
    expect(parsed.path).toBe("/ws");
    expect(parsed.hash).toBe(
      sha256Hex(
        canonicalQuery({
          role: "client_pair",
          target_public_key: "target_A",
        })
      )
    );
    // Sanity: different target yields different hash, so a captured
    // sig can't be swung at another daemon.
    const otherHash = sha256Hex(
      canonicalQuery({ role: "client_pair", target_public_key: "target_B" })
    );
    expect(parsed.hash).not.toBe(otherHash);
  });
});

describe("buildPublicDaemonUrl v2 binding", () => {
  it("commits role + label + client_id to the payload hash", () => {
    const kp = sodium.crypto_sign_keypair();
    const url = buildPublicDaemonUrl(
      "http://localhost:4000",
      { public: kp.publicKey, secret: kp.privateKey },
      { label: "laptop", clientId: "abc123" }
    );
    const payload = new URL(url).searchParams.get("payload")!;
    const parsed = parseV2Payload(payload)!;
    expect(parsed.hash).toBe(
      sha256Hex(
        canonicalQuery({
          role: "daemon",
          label: "laptop",
          client_id: "abc123",
        })
      )
    );
  });
});
