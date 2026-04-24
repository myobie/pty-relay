import { describe, it, expect } from "vitest";
import {
  canonicalize,
  canonicalizeBytes,
  preauthSigningPayload,
} from "../src/crypto/canonical-json.ts";

describe("canonicalize", () => {
  it("sorts object keys alphabetically", () => {
    expect(canonicalize({ z: 1, a: 2, m: 3 })).toBe(`{"a":2,"m":3,"z":1}`);
  });

  it("sorts keys by byte-wise order, not length", () => {
    // Differs from e.g. 'shortlex' ordering. account_id (10 chars) must
    // come before exp (3 chars) since 'a' < 'e' byte-wise.
    const input = {
      preauth_hash_id: "p",
      exp: 0,
      public_key: "k",
      account_id: "a",
      nonce: "n",
    };
    expect(canonicalize(input)).toBe(
      `{"account_id":"a","exp":0,"nonce":"n","preauth_hash_id":"p","public_key":"k"}`
    );
  });

  it("sorts keys in nested objects too", () => {
    expect(canonicalize({ outer: { z: 1, a: 2 } })).toBe(
      `{"outer":{"a":2,"z":1}}`
    );
  });

  it("preserves array order", () => {
    expect(canonicalize([3, 1, 2])).toBe(`[3,1,2]`);
  });

  it("emits no whitespace", () => {
    expect(canonicalize({ a: 1, b: [2, 3], c: { d: 4 } })).toBe(
      `{"a":1,"b":[2,3],"c":{"d":4}}`
    );
  });
});

// Fixtures captured from Elixir:
//
//   mix run -e 'IO.puts(Relay.Accounts.preauth_signing_payload(...))'
//
// These are byte-for-byte compares. A failure here means the TS side has
// drifted from the Elixir side; /api/enroll signature verification will
// fail until they match again.
describe("preauthSigningPayload (Elixir byte-compare fixtures)", () => {
  it("matches fixture 1: basic ascii", () => {
    const out = preauthSigningPayload({
      publicKey: "pk_abc",
      accountId: "01HVC000",
      preauthHashId: "01HVCPH",
      nonce: "nonce_xyz",
      exp: 1700000000,
    });
    expect(out).toBe(
      `{"account_id":"01HVC000","exp":1700000000,"nonce":"nonce_xyz","preauth_hash_id":"01HVCPH","public_key":"pk_abc"}`
    );
  });

  it("matches fixture 2: empty strings + zero exp", () => {
    const out = preauthSigningPayload({
      publicKey: "",
      accountId: "",
      preauthHashId: "",
      nonce: "",
      exp: 0,
    });
    expect(out).toBe(
      `{"account_id":"","exp":0,"nonce":"","preauth_hash_id":"","public_key":""}`
    );
  });

  it("matches fixture 3: special characters in values", () => {
    const out = preauthSigningPayload({
      publicKey: `has"quote`,
      accountId: `has\\back`,
      preauthHashId: `has\nnl`,
      nonce: `has\ttab`,
      exp: 42,
    });
    expect(out).toBe(
      `{"account_id":"has\\\\back","exp":42,"nonce":"has\\ttab","preauth_hash_id":"has\\nnl","public_key":"has\\"quote"}`
    );
  });

  it("matches fixture 4: unicode + forward slash (not escaped)", () => {
    const out = preauthSigningPayload({
      publicKey: "héllo/world",
      accountId: "café",
      preauthHashId: "naïve",
      nonce: "日本",
      exp: -1,
    });
    expect(out).toBe(
      `{"account_id":"café","exp":-1,"nonce":"日本","preauth_hash_id":"naïve","public_key":"héllo/world"}`
    );
  });

  it("matches fixture 5: control characters escape as \\u00XX lowercase", () => {
    const out = preauthSigningPayload({
      publicKey: "\u0001\u0002\u0003",
      accountId: "x",
      preauthHashId: "x",
      nonce: "x",
      exp: 1,
    });
    expect(out).toBe(
      `{"account_id":"x","exp":1,"nonce":"x","preauth_hash_id":"x","public_key":"\\u0001\\u0002\\u0003"}`
    );
  });

  it("matches fixture 6: large integer exp", () => {
    const out = preauthSigningPayload({
      publicKey: "k",
      accountId: "a",
      preauthHashId: "p",
      nonce: "n",
      exp: 9999999999999,
    });
    expect(out).toBe(
      `{"account_id":"a","exp":9999999999999,"nonce":"n","preauth_hash_id":"p","public_key":"k"}`
    );
  });
});

describe("canonicalizeBytes", () => {
  it("produces UTF-8 bytes of the canonical string", () => {
    const bytes = canonicalizeBytes({ a: "héllo" });
    const decoded = new TextDecoder().decode(bytes);
    expect(decoded).toBe(`{"a":"héllo"}`);
  });
});
