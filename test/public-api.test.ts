import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import { PublicApi, PublicApiError } from "../src/relay/public-api.ts";
import {
  verifySignature,
  isPayloadFresh,
  parseV2Payload,
  sha256Hex,
  canonicalQuery,
} from "../src/crypto/signing.ts";

interface CapturedRequest {
  url: string;
  method: string;
  body: string | null;
  headers: Record<string, string>;
}

let captured: CapturedRequest[];
let nextResponse: () => Response | Promise<Response>;

function mockFetch() {
  captured = [];
  nextResponse = () => new Response(null, { status: 204 });
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const headers: Record<string, string> = {};
    if (init?.headers) {
      for (const [k, v] of Object.entries(init.headers as Record<string, string>)) {
        headers[k.toLowerCase()] = v;
      }
    }
    captured.push({
      url,
      method: (init?.method ?? "GET").toUpperCase(),
      body: typeof init?.body === "string" ? init.body : null,
      headers,
    });
    const signal = init?.signal;
    const response = Promise.resolve(nextResponse());
    if (!signal) return response;
    // Race against the AbortSignal so timeout tests can trip the real path.
    return await new Promise<Response>((resolve, reject) => {
      if (signal.aborted) {
        const err = new Error("aborted");
        err.name = "AbortError";
        reject(err);
        return;
      }
      signal.addEventListener("abort", () => {
        const err = new Error("aborted");
        err.name = "AbortError";
        reject(err);
      });
      response.then(resolve, reject);
    });
  }) as typeof fetch;
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("PublicApi", () => {
  beforeEach(() => {
    mockFetch();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("strips a trailing slash from relayUrl", () => {
    const api = new PublicApi("http://localhost:4000/");
    expect(api.relayUrl).toBe("http://localhost:4000");
  });

  it("POSTs JSON with a content-type header", async () => {
    nextResponse = () => jsonResponse(200, { ok: true });
    const api = new PublicApi("http://localhost:4000");
    const out = await api.post<{ ok: boolean }>("/api/signup", {
      email: "me@example.com",
    });
    expect(out).toEqual({ ok: true });
    const req = captured[0];
    expect(req.url).toBe("http://localhost:4000/api/signup");
    expect(req.method).toBe("POST");
    expect(req.headers["content-type"]).toBe("application/json");
    expect(JSON.parse(req.body!)).toEqual({ email: "me@example.com" });
  });

  it("GETs with a query string", async () => {
    nextResponse = () => jsonResponse(200, { status: "pending" });
    const api = new PublicApi("http://localhost:4000");
    await api.get("/api/verify/poll", {
      query: { request_id: "abc", unused: undefined },
    });
    expect(captured[0].url).toBe(
      "http://localhost:4000/api/verify/poll?request_id=abc"
    );
  });

  it("signed POST: body stays pure JSON, auth triple in URL query (v2)", async () => {
    await sodium.ready;
    const keypair = sodium.crypto_sign_keypair();
    const api = new PublicApi("http://localhost:4000");
    nextResponse = () => jsonResponse(201, { id: "xyz" });

    await api.post(
      "/api/pairing_hashes/mint",
      { totp_code: "123456", ttl_seconds: 300 },
      { signWith: { public: keypair.publicKey, secret: keypair.privateKey } }
    );

    const req = captured[0];
    // Body is JUST the business payload — no auth fields.
    const body = JSON.parse(req.body!);
    expect(body).toEqual({ totp_code: "123456", ttl_seconds: 300 });

    // Auth triple rides in the URL query.
    const url = new URL(req.url);
    expect(url.pathname).toBe("/api/pairing_hashes/mint");
    const pk = url.searchParams.get("public_key");
    const payload = url.searchParams.get("payload");
    const sig = url.searchParams.get("sig");
    expect(pk && payload && sig).toBeTruthy();
    expect(isPayloadFresh(payload!)).toBe(true);

    // Payload binds to METHOD + PATH + sha256(body).
    const parsed = parseV2Payload(payload!);
    expect(parsed).not.toBeNull();
    expect(parsed!.method).toBe("POST");
    expect(parsed!.path).toBe("/api/pairing_hashes/mint");
    expect(parsed!.hash).toBe(sha256Hex(req.body!));

    // Signature verifies against the client's key.
    const sigBytes = sodium.from_base64(
      sig!,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    expect(verifySignature(payload!, sigBytes, keypair.publicKey)).toBe(true);
  });

  it("signed GET: hash binds to canonical query (v2)", async () => {
    await sodium.ready;
    const keypair = sodium.crypto_sign_keypair();
    const api = new PublicApi("http://localhost:4000");
    nextResponse = () => jsonResponse(200, { hosts: [] });

    // Pass a non-trivial query so canonicalQuery sorts meaningfully.
    await api.get("/api/hosts", {
      signWith: { public: keypair.publicKey, secret: keypair.privateKey },
      query: { foo: "b ar", zzz: "last", aaa: "first" },
    });

    const url = new URL(captured[0].url);
    expect(url.pathname).toBe("/api/hosts");
    const pk = url.searchParams.get("public_key");
    const payload = url.searchParams.get("payload");
    const sig = url.searchParams.get("sig");
    expect(pk && payload && sig).toBeTruthy();

    const parsed = parseV2Payload(payload!);
    expect(parsed!.method).toBe("GET");
    expect(parsed!.path).toBe("/api/hosts");
    // Hash must match sha256 of the canonical-sorted non-auth query.
    expect(parsed!.hash).toBe(
      sha256Hex(canonicalQuery({ foo: "b ar", zzz: "last", aaa: "first" }))
    );

    const sigBytes = sodium.from_base64(
      sig!,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    expect(verifySignature(payload!, sigBytes, keypair.publicKey)).toBe(true);
  });

  it("signed GET with no non-auth params: hashes empty canonical query", async () => {
    await sodium.ready;
    const keypair = sodium.crypto_sign_keypair();
    const api = new PublicApi("http://localhost:4000");
    nextResponse = () => jsonResponse(200, { hosts: [] });

    await api.get("/api/hosts", {
      signWith: { public: keypair.publicKey, secret: keypair.privateKey },
    });

    const payload = new URL(captured[0].url).searchParams.get("payload");
    const parsed = parseV2Payload(payload!);
    expect(parsed!.hash).toBe(sha256Hex("")); // empty canonical query
  });

  it("throws PublicApiError with relay's error message on 4xx", async () => {
    nextResponse = () =>
      jsonResponse(401, { error: "invalid totp_code" });
    const api = new PublicApi("http://localhost:4000");

    await expect(
      api.post("/api/pairing_hashes/mint", {})
    ).rejects.toMatchObject({
      name: "PublicApiError",
      status: 401,
      message: "invalid totp_code",
    });
  });

  it("throws PublicApiError with fallback message on 5xx with no body", async () => {
    nextResponse = () => new Response(null, { status: 500 });
    const api = new PublicApi("http://localhost:4000");

    await expect(api.get("/api/verify/poll")).rejects.toThrow(PublicApiError);
  });

  it("throws on timeout", async () => {
    nextResponse = () =>
      new Promise((resolve) =>
        setTimeout(() => resolve(jsonResponse(200, {})), 50)
      );
    const api = new PublicApi("http://localhost:4000");

    await expect(
      api.post("/api/signup", {}, { timeoutMs: 5 })
    ).rejects.toThrow(/timed out/);
  });

  it("returns null for a 204 No Content response", async () => {
    nextResponse = () => new Response(null, { status: 204 });
    const api = new PublicApi("http://localhost:4000");
    expect(await api.post("/api/whatever", {})).toBeNull();
  });
});
