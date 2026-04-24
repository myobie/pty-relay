import { describe, it, expect, beforeAll } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import {
  runJoin,
  buildMintWsUrl,
} from "../src/commands/client/join.ts";
import { PublicApi } from "../src/relay/public-api.ts";
import { signMinterPayload } from "../src/commands/server/mint-protocol.ts";
import { Handshake, NK, Transport } from "../src/crypto/index.ts";
import {
  ed25519PkToCurve25519,
  ed25519SkToCurve25519,
} from "../src/crypto/key-conversion.ts";
import { computeSecretHash } from "../src/crypto/index.ts";

beforeAll(async () => {
  await sodium.ready;
});

/**
 * Fake WebSocket that plays the minting daemon's side of the preauth-
 * claim handshake locally. Not a full spec-compliant WS — enough to
 * exercise the join flow deterministically.
 *
 * Flow mirrors what the real relay + minting daemon do:
 *   1. "paired" text frame to announce the pair.
 *   2. Noise NK responder reads the joiner's hello, writes welcome.
 *   3. Decrypts the MintRequest, signs a valid MintReady, sends it back.
 */
class FakeMinterWs {
  binaryType: "arraybuffer" | "nodebuffer" = "arraybuffer";
  onmessage: ((e: { data: any }) => void) | null = null;
  onerror: ((e: { message: string }) => void) | null = null;
  onclose: (() => void) | null = null;

  private transport: Transport | null = null;
  private responder: Handshake | null = null;
  private closed = false;

  constructor(
    private minterCurvePk: Uint8Array,
    private minterCurveSk: Uint8Array,
    private minterEdSk: Uint8Array,
    private accountId: string,
    private preauthHashId: string,
    private onRequestReceived?: (req: Record<string, unknown>) => void
  ) {
    // Emit "paired" on the next tick so the joiner has installed its handlers.
    queueMicrotask(() => {
      this.onmessage?.({ data: JSON.stringify({ type: "paired" }) });
    });
  }

  send(payload: any): void {
    if (this.closed) return;
    try {
      if (typeof payload === "string") {
        // joiner shouldn't send strings after handshake, but ignore gracefully
        return;
      }

      const bytes = new Uint8Array(payload);

      if (!this.responder && !this.transport) {
        // First binary frame = joiner's e,es hello. Build the welcome.
        // Mint peers use NK (joiner has no registered key yet).
        this.responder = new Handshake({
          pattern: NK,
          initiator: false,
          staticKeys: {
            publicKey: this.minterCurvePk,
            privateKey: this.minterCurveSk,
          },
        });
        this.responder.readMessage(bytes);
        const welcome = this.responder.writeMessage();
        this.transport = new Transport(this.responder.split());
        this.responder = null;
        queueMicrotask(() => this.onmessage?.({ data: Buffer.from(welcome) }));
        return;
      }

      if (!this.transport) return;
      const plaintext = this.transport.decrypt(bytes);
      const msg = JSON.parse(new TextDecoder().decode(plaintext));
      if (msg.type !== "mint_request") return;
      this.onRequestReceived?.(msg);

      (async () => {
        const sig = await signMinterPayload({
          minterSecretKey: this.minterEdSk,
          accountId: this.accountId,
          joinerPublicKeyB64: String(msg.public_key),
          preauthHashId: this.preauthHashId,
          nonce: String(msg.nonce),
          exp: Number(msg.exp),
        });
        const reply = {
          type: "mint_ready",
          minter_signature: sig,
          preauth_hash_id: this.preauthHashId,
          account_id: this.accountId,
        };
        const ct = this.transport!.encrypt(
          new TextEncoder().encode(JSON.stringify(reply))
        );
        queueMicrotask(() => this.onmessage?.({ data: Buffer.from(ct) }));
      })();
    } catch (err: any) {
      this.onerror?.({ message: err?.message ?? String(err) });
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    queueMicrotask(() => this.onclose?.());
  }
}

/** Mint a keypair and expose it as Ed25519 + derived Curve25519. */
async function minterKeys(seedByte: number) {
  await sodium.ready;
  const seed = new Uint8Array(32).fill(seedByte);
  const ed = sodium.crypto_sign_seed_keypair(seed);
  const curvePk = await ed25519PkToCurve25519(ed.publicKey);
  const curveSk = await ed25519SkToCurve25519(ed.privateKey);
  return { ed, curvePk, curveSk };
}

describe("buildMintWsUrl", () => {
  it("constructs the client_mint URL with secret_hash and totp_code", () => {
    const raw = new Uint8Array(32).fill(5);
    const url = buildMintWsUrl(
      "http://localhost:4000/#pk.secret",
      raw,
      "123456"
    );
    const parsed = new URL(url);
    expect(parsed.protocol).toBe("ws:");
    expect(parsed.host).toBe("localhost:4000");
    expect(parsed.pathname).toBe("/ws");
    expect(parsed.searchParams.get("role")).toBe("client_mint");
    expect(parsed.searchParams.get("secret_hash")).toBe(computeSecretHash(raw));
    expect(parsed.searchParams.get("totp_code")).toBe("123456");
  });

  it("upgrades to wss: for https origins", () => {
    const url = buildMintWsUrl(
      "https://relay.example.com/#pk.secret",
      new Uint8Array(32),
      "111222"
    );
    expect(new URL(url).protocol).toBe("wss:");
  });
});

describe("runJoin — end-to-end with a fake minter WS", () => {
  it("produces a PublicAccount and /api/enroll body accepted by the relay", async () => {
    const minter = await minterKeys(1);
    const accountId = "01HVCACCT000000000000000000";
    const preauthHashId = "01HVCPH0000000000000000000";

    const pkB64 = sodium.to_base64(
      minter.curvePk,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    const rawSecret = new Uint8Array(32);
    for (let i = 0; i < 32; i++) rawSecret[i] = (i * 5 + 11) & 0xff;
    const secretB64 = sodium.to_base64(
      rawSecret,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    const preauthUrl = `http://localhost:4000/#${pkB64}.${secretB64}`;

    let receivedRequest: Record<string, unknown> | null = null;
    let postBody: any = null;

    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      postBody = JSON.parse(init?.body as string);
      return new Response(
        JSON.stringify({
          public_key: postBody.public_key,
          key_id: "01HVCKEY00000000000000000",
          role: postBody.role,
          label: postBody.label,
          minter_key_id: "01HVCMINTER000000000000000",
          pinned_daemon_identity_id: "01HVCIDENTITY000000000000",
          pinned_daemon_label: "minting-daemon",
          pinned_daemon_public_key: sodium.to_base64(
            minter.ed.publicKey,
            sodium.base64_variants.URLSAFE_NO_PADDING
          ),
        }),
        { status: 201, headers: { "content-type": "application/json" } }
      );
    }) as typeof fetch;

    const api = new PublicApi("http://localhost:4000");

    const result = await runJoin(
      {
        preauthUrl,
        label: "new-laptop",
        totpCode: "123456",
      },
      {
        api,
        openWebSocket: (url) => {
          expect(url).toContain("role=client_mint");
          expect(url).toContain("totp_code=123456");
          return new FakeMinterWs(
            minter.curvePk,
            minter.curveSk,
            minter.ed.privateKey,
            accountId,
            preauthHashId,
            (r) => {
              receivedRequest = r;
            }
          ) as any;
        },
        now: () => 1_700_000_000,
      }
    );

    // The minter saw our MintRequest — preauth claims are always
    // role=client now.
    expect(receivedRequest).not.toBeNull();
    expect(receivedRequest!.type).toBe("mint_request");
    expect(receivedRequest!.label).toBe("new-laptop");
    expect(receivedRequest!.role).toBe("client");
    // nonce is base64url, exp is now + 300
    expect(typeof receivedRequest!.nonce).toBe("string");
    expect(receivedRequest!.exp).toBe(1_700_000_000 + 300);

    // POST body contains every field the /api/enroll controller expects.
    expect(postBody.public_key).toBe(receivedRequest!.public_key);
    expect(postBody.label).toBe("new-laptop");
    expect(postBody.role).toBe("client");
    expect(postBody.preauth_hash_id).toBe(preauthHashId);
    expect(postBody.nonce).toBe(receivedRequest!.nonce);
    expect(postBody.exp).toBe(receivedRequest!.exp);
    expect(typeof postBody.minter_signature).toBe("string");

    // runJoin now returns a KeyIdentity + metadata for the joiner to
    // merge into its PublicAccount (joinCommand does the merge). We
    // don't assert on a PublicAccount here because join can either
    // create fresh or add a second role to an existing account.
    expect(result.role).toBe("client");
    expect(result.label).toBe("new-laptop");
    expect(result.accountId).toBe(accountId);
    expect(result.relayUrl).toBe("http://localhost:4000");
    expect(typeof result.key.signingKeys.public).toBe("string");
    expect(typeof result.key.signingKeys.secret).toBe("string");
    // The claimed key carries the daemon pin — enforced server-side.
    expect(result.key.pin).toBeDefined();
    expect(result.key.pin!.daemonIdentityId).toBe("01HVCIDENTITY000000000000");
    expect(result.key.pin!.daemonLabel).toBe("minting-daemon");
    expect(typeof result.key.pin!.daemonPublicKey).toBe("string");
    expect(result.key.registeredKeyId).toBe(result.key.signingKeys.public);
    expect(result.enroll.key_id).toBe("01HVCKEY00000000000000000");
  });
});
