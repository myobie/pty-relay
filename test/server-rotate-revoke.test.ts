import { describe, it, expect, beforeAll } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import { PublicApi } from "../src/relay/public-api.ts";
import {
  verifySignature,
  parseV2Payload,
  sha256Hex,
} from "../src/crypto/signing.ts";

beforeAll(async () => {
  await sodium.ready;
});

// The rotate / revoke / add-email / delete-account commands are thin
// HTTP wrappers over already-tested PublicApi signing. These tests pin
// the wire shape (paths, bodies, signed auth triples) so a drift
// between TS and the Elixir relay is caught early.
//
// v2 shape (all signed POSTs):
//   - body JSON contains ONLY the business fields
//   - auth triple (public_key, payload, sig) rides on the URL query
//   - signed payload is "v2\nPOST\n<path>\n<sha256(body)>\n<ts>\n<uuid>"

interface CapturedPost {
  url: URL;
  body: any;
  bodyRaw: string;
}

function captureOneSignedPost(response: unknown): Promise<CapturedPost> {
  return new Promise((resolve) => {
    globalThis.fetch = (async (input, init) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      const bodyRaw = (init?.body as string) ?? "";
      const body = bodyRaw ? JSON.parse(bodyRaw) : null;
      resolve({ url, body, bodyRaw });
      return new Response(JSON.stringify(response), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;
  });
}

function expectV2Signed(
  captured: CapturedPost,
  signer: ReturnType<typeof sodium.crypto_sign_keypair>,
  expectedPath: string
) {
  // Body is pure business payload — no auth triple inside.
  expect(captured.body?.public_key).toBeUndefined();
  expect(captured.body?.payload).toBeUndefined();
  expect(captured.body?.sig).toBeUndefined();

  // URL points at the right path and carries the triple.
  expect(captured.url.pathname).toBe(expectedPath);
  const pk = captured.url.searchParams.get("public_key");
  const payload = captured.url.searchParams.get("payload");
  const sigB64 = captured.url.searchParams.get("sig");
  expect(pk && payload && sigB64).toBeTruthy();

  // Payload parses as v2 and binds to method + path + body hash.
  const parsed = parseV2Payload(payload!);
  expect(parsed).not.toBeNull();
  expect(parsed!.method).toBe("POST");
  expect(parsed!.path).toBe(expectedPath);
  expect(parsed!.hash).toBe(sha256Hex(captured.bodyRaw));

  // Signature verifies against the caller's public key.
  const sig = sodium.from_base64(
    sigB64!,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );
  expect(verifySignature(payload!, sig, signer.publicKey)).toBe(true);
}

describe("rotate/start wire shape", () => {
  it("posts {new_public_key} signed with the old key (v2)", async () => {
    const oldKp = sodium.crypto_sign_keypair();
    const p = captureOneSignedPost({
      old_key: "old_pk_b64",
      new_key: "new_pk_b64",
      old_status: "deprecated",
    });
    const api = new PublicApi("http://localhost:4000");
    await api.post(
      "/api/keys/rotate/start",
      { new_public_key: "new_pk_b64" },
      { signWith: { public: oldKp.publicKey, secret: oldKp.privateKey } }
    );
    const captured = await p;
    expect(captured.body).toEqual({ new_public_key: "new_pk_b64" });
    expectV2Signed(captured, oldKp, "/api/keys/rotate/start");
  });
});

describe("rotate/complete wire shape", () => {
  it("posts {old_public_key} signed with the new key (v2)", async () => {
    const newKp = sodium.crypto_sign_keypair();
    const p = captureOneSignedPost({ status: "completed", revoked_key: "old_pk" });
    const api = new PublicApi("http://localhost:4000");
    await api.post(
      "/api/keys/rotate/complete",
      { old_public_key: "old_pk" },
      { signWith: { public: newKp.publicKey, secret: newKp.privateKey } }
    );
    const captured = await p;
    expect(captured.body).toEqual({ old_public_key: "old_pk" });
    expectV2Signed(captured, newKp, "/api/keys/rotate/complete");
  });
});

describe("revoke wire shape", () => {
  it("posts {target_public_key} signed with caller's key (v2)", async () => {
    const kp = sodium.crypto_sign_keypair();
    const p = captureOneSignedPost({ status: "revoked", public_key: "peer_pk" });
    const api = new PublicApi("http://localhost:4000");
    await api.post(
      "/api/keys/revoke",
      { target_public_key: "peer_pk" },
      { signWith: { public: kp.publicKey, secret: kp.privateKey } }
    );
    const captured = await p;
    expect(captured.body).toEqual({ target_public_key: "peer_pk" });
    expectV2Signed(captured, kp, "/api/keys/revoke");
  });
});

describe("delete-account wire shape", () => {
  it("posts to /api/account/delete signed with caller's key (v2)", async () => {
    const kp = sodium.crypto_sign_keypair();
    const p = captureOneSignedPost({
      status: "deleted",
      account_id: "01HVCACCT",
    });
    const api = new PublicApi("http://localhost:4000");
    const res = await api.post<{ status: string; account_id: string }>(
      "/api/account/delete",
      {},
      { signWith: { public: kp.publicKey, secret: kp.privateKey } }
    );
    expect(res.status).toBe("deleted");
    const captured = await p;
    // Empty business body; auth rides in the URL.
    expect(captured.body).toEqual({});
    expectV2Signed(captured, kp, "/api/account/delete");
  });
});

describe("add-email wire shape", () => {
  it("step 1 posts {email} signed; step 2 posts {request_id, code} unsigned (v2)", async () => {
    const kp = sodium.crypto_sign_keypair();
    const captures: Array<{ url: URL; body: any; bodyRaw: string }> = [];
    let nth = 0;
    globalThis.fetch = (async (input, init) => {
      const url = new URL(typeof input === "string" ? input : input.toString());
      const bodyRaw = (init?.body as string) ?? "";
      const body = bodyRaw ? JSON.parse(bodyRaw) : null;
      captures.push({ url, body, bodyRaw });
      const n = nth++;
      if (n === 0) {
        return new Response(JSON.stringify({ request_id: "req_x" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(
        JSON.stringify({ status: "verified", email: "x@y.com" }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }) as typeof fetch;

    const api = new PublicApi("http://localhost:4000");
    const first = await api.post<{ request_id: string }>(
      "/api/account/add-email",
      { email: "x@y.com" },
      { signWith: { public: kp.publicKey, secret: kp.privateKey } }
    );
    await api.post("/api/account/verify-email", {
      request_id: first.request_id,
      code: "123456",
    });

    // Step 1: signed — body is just {email}, auth triple in URL.
    expect(captures[0].body).toEqual({ email: "x@y.com" });
    expectV2Signed(captures[0], kp, "/api/account/add-email");

    // Step 2: unsigned — no auth triple at all, body carries both fields.
    expect(captures[1].body).toEqual({
      request_id: "req_x",
      code: "123456",
    });
    expect(captures[1].url.searchParams.get("payload")).toBeNull();
    expect(captures[1].url.searchParams.get("sig")).toBeNull();
  });
});
