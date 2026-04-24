import { describe, it, expect, beforeAll } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import { handleMintRequest } from "../src/commands/server/start.ts";
import { preauthSigningPayload } from "../src/crypto/canonical-json.ts";
import { verifySignature } from "../src/crypto/signing.ts";

beforeAll(async () => {
  await sodium.ready;
});

describe("handleMintRequest (minter side of the preauth-claim flow)", () => {
  it("signs a valid payload using the pairing_hash_id from the paired frame", async () => {
    const kp = sodium.crypto_sign_keypair();
    const replies: Array<Record<string, unknown>> = [];
    const reply = (p: Record<string, unknown>) => { replies.push(p); };

    await handleMintRequest(
      {
        type: "mint_request",
        public_key: "joiner_pk_b64",
        label: "new-laptop",
        role: "client",
        nonce: "nnn",
        exp: 1_700_000_300,
      },
      kp.privateKey,
      "01HVCACCT0000000000000000",
      "01HVCPH00000000000000000",
      reply
    );

    expect(replies).toHaveLength(1);
    const reply0 = replies[0] as any;
    expect(reply0.type).toBe("mint_ready");
    expect(reply0.preauth_hash_id).toBe("01HVCPH00000000000000000");
    expect(reply0.account_id).toBe("01HVCACCT0000000000000000");
    expect(typeof reply0.minter_signature).toBe("string");

    // Sig verifies against the canonical preauth signing payload
    const expected = preauthSigningPayload({
      accountId: "01HVCACCT0000000000000000",
      exp: 1_700_000_300,
      nonce: "nnn",
      preauthHashId: "01HVCPH00000000000000000",
      publicKey: "joiner_pk_b64",
    });
    const sig = sodium.from_base64(
      reply0.minter_signature,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    expect(verifySignature(expected, sig, kp.publicKey)).toBe(true);
  });

  it("rejects when pairing_hash_id is missing from the paired frame", async () => {
    const kp = sodium.crypto_sign_keypair();
    const replies: any[] = [];

    await handleMintRequest(
      {
        type: "mint_request",
        public_key: "joiner",
        label: "new",
        role: "client",
        nonce: "n",
        exp: 1_700_000_300,
      },
      kp.privateKey,
      "01HVCACCT",
      undefined,
      (p) => replies.push(p)
    );

    expect(replies).toHaveLength(1);
    expect(replies[0].type).toBe("error");
    expect(replies[0].message).toMatch(/pairing_hash_id missing/);
  });

  it("rejects a malformed request (missing role)", async () => {
    const kp = sodium.crypto_sign_keypair();
    const replies: any[] = [];
    await handleMintRequest(
      {
        type: "mint_request",
        public_key: "p",
        label: "l",
        nonce: "n",
        exp: 1,
      },
      kp.privateKey,
      "acct",
      "ph",
      (p) => replies.push(p)
    );
    expect(replies[0].type).toBe("error");
    expect(replies[0].message).toMatch(/malformed/);
  });

  it("rejects role=daemon — preauth claims are client-only now", async () => {
    const kp = sodium.crypto_sign_keypair();
    const replies: any[] = [];
    await handleMintRequest(
      {
        type: "mint_request",
        public_key: "p",
        label: "l",
        role: "daemon",
        nonce: "n",
        exp: 1_700_000_300,
      },
      kp.privateKey,
      "acct",
      "ph",
      (p) => replies.push(p)
    );
    expect(replies[0].type).toBe("error");
    expect(replies[0].message).toMatch(/role must be client/);
  });
});
