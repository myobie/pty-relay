import { describe, it, expect, beforeAll } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import {
  signMinterPayload,
  buildMintBody,
  newMintNonce,
  type MintRequest,
  type MintReady,
} from "../src/commands/server/mint-protocol.ts";
import { preauthSigningPayload } from "../src/crypto/canonical-json.ts";
import { verifySignature } from "../src/crypto/signing.ts";

beforeAll(async () => {
  await sodium.ready;
});

describe("mint-protocol", () => {
  it("signMinterPayload produces a signature that verifies against the canonical payload", async () => {
    const kp = sodium.crypto_sign_keypair();
    const fields = {
      minterSecretKey: kp.privateKey,
      accountId: "01HVC000ACCOUNT0000000000",
      joinerPublicKeyB64: "joiner_pk_b64url",
      preauthHashId: "01HVCPH000000000000000000",
      nonce: "nonce_b64url",
      exp: 1_700_000_300,
    };

    const sigB64 = await signMinterPayload(fields);

    const expectedPayload = preauthSigningPayload({
      accountId: fields.accountId,
      exp: fields.exp,
      nonce: fields.nonce,
      preauthHashId: fields.preauthHashId,
      publicKey: fields.joinerPublicKeyB64,
    });
    const sigBytes = sodium.from_base64(
      sigB64,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    expect(verifySignature(expectedPayload, sigBytes, kp.publicKey)).toBe(true);
  });

  it("buildMintBody mirrors the POST fields the relay test client uses", () => {
    const req: MintRequest = {
      type: "mint_request",
      public_key: "pub_b64",
      label: "new-laptop",
      role: "client",
      nonce: "nnn",
      exp: 1_700_000_300,
    };
    const ready: MintReady = {
      type: "mint_ready",
      minter_signature: "sig_b64",
      preauth_hash_id: "01HVCPH",
      account_id: "01HVCACCT",
    };
    const body = buildMintBody(req, ready);
    expect(body).toEqual({
      public_key: "pub_b64",
      label: "new-laptop",
      role: "client",
      preauth_hash_id: "01HVCPH",
      nonce: "nnn",
      exp: 1_700_000_300,
      minter_signature: "sig_b64",
    });
  });

  it("newMintNonce returns a fresh 16-byte value each call", async () => {
    const a = await newMintNonce();
    const b = await newMintNonce();
    expect(a).not.toBe(b);
    // 16 bytes → 22 base64url chars (no padding)
    expect(a.length).toBe(22);
    expect(b.length).toBe(22);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/u);
  });
});
