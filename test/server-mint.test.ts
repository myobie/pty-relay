import { describe, it, expect, beforeAll } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import {
  runMint,
  buildPreauthUrl,
} from "../src/commands/server/mint.ts";
import { PublicApi } from "../src/relay/public-api.ts";
import {
  ed25519PkToCurve25519,
} from "../src/crypto/key-conversion.ts";
import { parseToken, computeSecretHash } from "../src/crypto/index.ts";
import {
  verifySignature,
  isPayloadFresh,
  parseV2Payload,
  sha256Hex,
} from "../src/crypto/signing.ts";

beforeAll(async () => {
  await sodium.ready;
});

describe("runMint", () => {
  it("signs /api/pairing_hashes/mint and builds a valid preauth URL", async () => {
    // Deterministic keypair so we can assert on the URL's pubkey bytes.
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seed[i] = i + 1;
    const kp = sodium.crypto_sign_seed_keypair(seed);
    const account = {
      relayUrl: "http://localhost:4000",
      signingKeys: {
        public: sodium.to_base64(kp.publicKey, sodium.base64_variants.URLSAFE_NO_PADDING),
        secret: sodium.to_base64(kp.privateKey, sodium.base64_variants.URLSAFE_NO_PADDING),
      },
    };

    const rawSecretBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) rawSecretBytes[i] = (i * 3 + 17) & 0xff;
    const rawSecretB64 = sodium.to_base64(
      rawSecretBytes,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    const futureExp = new Date(Date.now() + 5 * 60_000).toISOString();

    let capturedUrl: URL | null = null;
    let capturedBodyRaw: string | null = null;
    let capturedBody: any = null;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedUrl = new URL(typeof input === "string" ? input : input.toString());
      capturedBodyRaw = (init?.body as string) ?? "";
      capturedBody = capturedBodyRaw ? JSON.parse(capturedBodyRaw) : null;
      return new Response(
        JSON.stringify({
          id: "01HVCPH",
          raw_secret: rawSecretB64,
          secret_hash: computeSecretHash(rawSecretBytes),
          expires_at: futureExp,
          purpose: "pairing",
          single_use: true,
        }),
        { status: 201, headers: { "content-type": "application/json" } }
      );
    }) as typeof fetch;

    const api = new PublicApi("http://localhost:4000");
    const out = await runMint(account, { totpCode: "123456" }, api);

    // v2: body is the business payload only (no auth triple).
    expect(capturedBody).toEqual({ totp_code: "123456", ttl_seconds: 300 });

    // Auth triple rides on the URL query; payload binds to sha256(body).
    const url = capturedUrl!;
    expect(url.pathname).toBe("/api/pairing_hashes/mint");
    const payload = url.searchParams.get("payload");
    const sigB64 = url.searchParams.get("sig");
    expect(payload && sigB64).toBeTruthy();
    expect(isPayloadFresh(payload!)).toBe(true);
    const parsedPayload = parseV2Payload(payload!);
    expect(parsedPayload!.method).toBe("POST");
    expect(parsedPayload!.path).toBe("/api/pairing_hashes/mint");
    expect(parsedPayload!.hash).toBe(sha256Hex(capturedBodyRaw!));
    const sigBytes = sodium.from_base64(
      sigB64!,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    expect(verifySignature(payload!, sigBytes, kp.publicKey)).toBe(true);

    // URL is parseable as a token with the derived Curve25519 pubkey.
    const parsed = parseToken(out.url);
    const expectedCurvePk = await ed25519PkToCurve25519(kp.publicKey);
    expect(Array.from(parsed.publicKey)).toEqual(Array.from(expectedCurvePk));
    expect(Array.from(parsed.secret)).toEqual(Array.from(rawSecretBytes));

    // Computed TTL is positive and within one second of the 5-minute window.
    expect(out.ttlSeconds).toBeGreaterThan(290);
    expect(out.ttlSeconds).toBeLessThanOrEqual(300);
  });

  it("passes through a custom TTL", async () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) seed[i] = 2;
    const kp = sodium.crypto_sign_seed_keypair(seed);
    const account = {
      relayUrl: "http://localhost:4000",
      signingKeys: {
        public: sodium.to_base64(kp.publicKey, sodium.base64_variants.URLSAFE_NO_PADDING),
        secret: sodium.to_base64(kp.privateKey, sodium.base64_variants.URLSAFE_NO_PADDING),
      },
    };
    let capturedBody: any = null;
    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      capturedBody = JSON.parse(init?.body as string);
      return new Response(
        JSON.stringify({
          id: "x",
          raw_secret: "A".repeat(43), // arbitrary 32-byte-ish
          secret_hash: "0".repeat(64),
          expires_at: new Date(Date.now() + 60_000).toISOString(),
          purpose: "pairing",
          single_use: true,
        }),
        { status: 201, headers: { "content-type": "application/json" } }
      );
    }) as typeof fetch;

    const api = new PublicApi("http://localhost:4000");
    try {
      await runMint(account, { totpCode: "999111", ttlSeconds: 60 }, api);
    } catch {
      // parseToken may choke on the dummy raw_secret; we only care about the body.
    }
    expect(capturedBody.ttl_seconds).toBe(60);
    expect(capturedBody.totp_code).toBe("999111");
  });
});

describe("buildPreauthUrl", () => {
  it("emits fragment with curve25519 pk and raw secret", async () => {
    await sodium.ready;
    const pk = new Uint8Array(32);
    for (let i = 0; i < 32; i++) pk[i] = 7;
    const url = buildPreauthUrl("http://localhost:4000", pk, "RAW_SECRET_B64");
    expect(url).toBe(
      `http://localhost:4000/#${sodium.to_base64(pk, sodium.base64_variants.URLSAFE_NO_PADDING)}.RAW_SECRET_B64`
    );
  });

  it("strips a trailing slash from relayUrl before appending the fragment", async () => {
    await sodium.ready;
    const pk = new Uint8Array(32);
    const url = buildPreauthUrl("http://localhost:4000/", pk, "S");
    expect(url).not.toContain("//#");
    expect(url.endsWith(".S")).toBe(true);
  });
});
