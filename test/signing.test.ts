import { describe, it, expect, beforeAll } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import {
  buildV2Payload,
  parseV2Payload,
  canonicalQuery,
  sha256Hex,
  createAuthParams,
  verifySignature,
  isPayloadFresh,
} from "../src/crypto/signing.ts";

beforeAll(async () => {
  await sodium.ready;
});

/**
 * v2 canonical signing — the contract is byte-for-byte compatible
 * with the Elixir reference. These tests pin the exact wire format:
 *   - canonicalQuery: key ordering, encoding rules, auth-triple exclusion
 *   - buildV2Payload: 6-line UTF-8, "v2" version tag, no trailing \n
 *   - createAuthParams: produces a signature the other side can verify
 *
 * If any of these break, the relay will start rejecting us. So these
 * tests are the first line of defense against silent drift.
 */

describe("canonicalQuery", () => {
  it("sorts keys ascending and url-encodes values", () => {
    const out = canonicalQuery({ zzz: "b", aaa: "a", mmm: "c" });
    expect(out).toBe("aaa=a&mmm=c&zzz=b");
  });

  it("url-encodes spaces + punctuation", () => {
    const out = canonicalQuery({ q: "hello world", plus: "a+b", slash: "a/b" });
    // encodeURIComponent: space → %20, + → %2B, / → %2F
    expect(out).toBe("plus=a%2Bb&q=hello%20world&slash=a%2Fb");
  });

  it("excludes the auth triple from the canonical representation", () => {
    const out = canonicalQuery({
      role: "daemon",
      public_key: "SHOULD_BE_EXCLUDED",
      payload: "SHOULD_BE_EXCLUDED",
      sig: "SHOULD_BE_EXCLUDED",
      label: "laptop",
    });
    expect(out).toBe("label=laptop&role=daemon");
  });

  it("returns the empty string for zero non-auth params", () => {
    expect(canonicalQuery({})).toBe("");
    expect(canonicalQuery({ public_key: "x", payload: "y", sig: "z" })).toBe("");
  });
});

describe("buildV2Payload", () => {
  it("emits six UTF-8 lines with no trailing newline", () => {
    const payload = buildV2Payload({
      method: "POST",
      path: "/api/keys/revoke",
      hash: "deadbeef",
      ts: 1_700_000_000,
      uuid: "01936000-0000-0000-0000-000000000000",
    });
    expect(payload).toBe(
      "v2\nPOST\n/api/keys/revoke\ndeadbeef\n1700000000\n01936000-0000-0000-0000-000000000000"
    );
    // No trailing newline — signing bytes exactly.
    expect(payload.endsWith("\n")).toBe(false);
  });

  it("defaults ts to now and generates a fresh uuid", () => {
    const a = buildV2Payload({
      method: "GET",
      path: "/x",
      hash: sha256Hex(""),
    });
    const b = buildV2Payload({
      method: "GET",
      path: "/x",
      hash: sha256Hex(""),
    });
    expect(a).not.toBe(b); // different uuid
    expect(isPayloadFresh(a)).toBe(true);
  });
});

describe("parseV2Payload", () => {
  it("round-trips buildV2Payload", () => {
    const payload = buildV2Payload({
      method: "POST",
      path: "/p",
      hash: "h",
      ts: 12345,
      uuid: "u",
    });
    const parsed = parseV2Payload(payload);
    expect(parsed).toEqual({
      version: "v2",
      method: "POST",
      path: "/p",
      hash: "h",
      ts: 12345,
      uuid: "u",
    });
  });

  it("rejects v1-style `ts.uuid` payloads", () => {
    expect(parseV2Payload("1700000000.abc-def")).toBeNull();
    expect(isPayloadFresh("1700000000.abc-def")).toBe(false);
  });

  it("rejects wrong version tag", () => {
    expect(parseV2Payload("v3\nPOST\n/x\nh\n1\nu")).toBeNull();
  });

  it("rejects wrong line count", () => {
    expect(parseV2Payload("v2\nPOST\n/x\nh\n1")).toBeNull();
    expect(parseV2Payload("v2\nPOST\n/x\nh\n1\nu\nextra")).toBeNull();
  });

  it("rejects non-numeric timestamp", () => {
    expect(parseV2Payload("v2\nPOST\n/x\nh\nnot-a-number\nu")).toBeNull();
  });
});

describe("createAuthParams + verifySignature", () => {
  it("signature verifies against the signer's public key", () => {
    const kp = sodium.crypto_sign_keypair();
    const auth = createAuthParams(kp.publicKey, kp.privateKey, {
      method: "POST",
      path: "/api/keys/revoke",
      hash: sha256Hex('{"target_public_key":"peer"}'),
    });
    const sig = sodium.from_base64(
      auth.sig,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    expect(verifySignature(auth.payload, sig, kp.publicKey)).toBe(true);
  });

  it("signature is specific to the binding — different hash doesn't verify", () => {
    const kp = sodium.crypto_sign_keypair();
    const auth = createAuthParams(kp.publicKey, kp.privateKey, {
      method: "POST",
      path: "/api/keys/revoke",
      hash: "aaaa",
    });
    // Swap in a different hash: signature over the original payload
    // obviously won't match.
    const tamperedPayload = buildV2Payload({
      method: "POST",
      path: "/api/keys/revoke",
      hash: "bbbb",
      ts: parseV2Payload(auth.payload)!.ts,
      uuid: parseV2Payload(auth.payload)!.uuid,
    });
    const sig = sodium.from_base64(
      auth.sig,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    expect(verifySignature(tamperedPayload, sig, kp.publicKey)).toBe(false);
  });
});
