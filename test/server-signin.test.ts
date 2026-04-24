import { describe, it, expect, beforeEach } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import { runSignin, type SigninDeps } from "../src/commands/server/signin.ts";
import { PublicApi } from "../src/relay/public-api.ts";
import {
  generateTotpCode,
  base32Encode,
} from "../src/crypto/totp.ts";

/**
 * These tests drive the signin wizard with fully stubbed HTTP, stdin, and
 * clock. They verify:
 *   - the exact wire shapes sent to /api/signin, /api/verify, /api/verify/totp
 *   - both "totp_setup" (first daemon) and "totp_required" (subsequent
 *     daemon on the same email) branches
 *   - the persisted PublicAccount has the right fields
 *
 * End-to-end against a deployed relay is covered separately.
 */

interface Call {
  path: string;
  body: Record<string, unknown>;
}

function makeHarness() {
  const calls: Call[] = [];
  const responses: Array<(body: Record<string, unknown>) => unknown> = [];
  const prompts: string[] = [];
  const logs: string[] = [];
  const promptInputs: string[] = [];

  // Drive PublicApi with a hand-rolled fetch mock so we can assert on
  // the signed payload before (not just through) the public-api layer.
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const path = new URL(url).pathname;
    const body = JSON.parse((init?.body as string) || "{}");
    calls.push({ path, body });
    const handler = responses.shift();
    if (!handler) {
      return new Response(
        JSON.stringify({ error: `unexpected call ${path}` }),
        { status: 500, headers: { "content-type": "application/json" } }
      );
    }
    const payload = handler(body);
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;

  const deps: SigninDeps = {
    api: new PublicApi("http://localhost:4000"),
    generateSigningKeypair() {
      // Deterministic keypair for reproducible tests.
      const seed = new Uint8Array(32);
      for (let i = 0; i < 32; i++) seed[i] = i + 1;
      const kp = sodium.crypto_sign_seed_keypair(seed);
      return { publicKey: kp.publicKey, secretKey: kp.privateKey };
    },
    generateTotpSecret() {
      const out = new Uint8Array(20);
      for (let i = 0; i < 20; i++) out[i] = (i * 7 + 3) & 0xff;
      return out;
    },
    now: () => 1_700_000_000, // Freeze TOTP at a known window so assertions are stable
    promptLine: async (label) => {
      prompts.push(label);
      const input = promptInputs.shift();
      if (input === undefined) {
        throw new Error(`no scripted input for prompt "${label}"`);
      }
      return input;
    },
    log: (line) => {
      logs.push(line);
    },
  };

  return {
    deps,
    calls,
    logs,
    prompts,
    pushResponse: (h: (body: Record<string, unknown>) => unknown) =>
      responses.push(h),
    pushPromptInput: (s: string) => promptInputs.push(s),
  };
}

describe("runSignin — first daemon (totp_setup)", () => {
  beforeEach(() => sodium.ready);

  it("registers daemon + auto-enrolls companion client key, persists both", async () => {
    const h = makeHarness();

    // /api/signin → request_id
    h.pushResponse((body) => {
      expect(body.email).toBe("me@example.com");
      expect(body.role).toBe("daemon");
      expect(body.label).toBe("laptop");
      expect(typeof body.public_key).toBe("string");
      expect(typeof body.totp_secret).toBe("string");
      return { request_id: "req_abc" };
    });

    // /api/verify → totp_setup (first daemon)
    h.pushResponse((body) => {
      expect(body.request_id).toBe("req_abc");
      expect(body.code).toBe("123456");
      return {
        status: "totp_setup",
        totp_url: "otpauth://totp/test",
        totp_secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        request_id: "req_abc",
      };
    });

    // /api/verify/totp → verified, with two consecutive codes deterministic
    // from our stubbed TOTP secret and clock.
    const stubSecret = new Uint8Array(20);
    for (let i = 0; i < 20; i++) stubSecret[i] = (i * 7 + 3) & 0xff;
    const stubSecretB32 = base32Encode(stubSecret);
    const expected1 = generateTotpCode(stubSecretB32, 1_700_000_000);
    const expected2 = generateTotpCode(stubSecretB32, 1_700_000_030);

    h.pushResponse((body) => {
      expect(body.request_id).toBe("req_abc");
      expect(body.code1).toBe(expected1);
      expect(body.code2).toBe(expected2);
      expect(body.code1).not.toBe(body.code2);
      return {
        status: "verified",
        public_key: "pk_b64",
        account_id: "01HVC000000000000000000000",
        totp_secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      };
    });

    h.pushPromptInput("123456");

    const { account, freshTotp } = await runSignin(
      { email: "me@example.com", relayUrl: "http://localhost:4000", label: "laptop" },
      h.deps
    );

    expect(freshTotp).toBe(true);
    expect(account.email).toBe("me@example.com");
    expect(account.label).toBe("laptop");
    expect(account.accountId).toBe("01HVC000000000000000000000");
    expect(account.daemonKey).toBeDefined();
    expect(account.daemonKey!.signingKeys.public).toMatch(/^[A-Za-z0-9_-]+$/u);
    expect(account.daemonKey!.signingKeys.secret).toMatch(/^[A-Za-z0-9_-]+$/u);
    // Server signin registers a daemon key only. The machine only also
    // gets a client key if the user runs `pty-relay client signin`.
    expect(account.clientKey).toBeUndefined();
    expect(account.totpSecretB32).toBeDefined();
    expect(account.relayUrl).toBe("http://localhost:4000");

    // Call sequence: signin → verify → verify/totp. Nothing else.
    expect(h.calls.map((c) => c.path)).toEqual([
      "/api/signin",
      "/api/verify",
      "/api/verify/totp",
    ]);

    // Emitted the otpauth URL for the authenticator app.
    expect(h.logs.some((l) => l.startsWith("otpauth://totp/"))).toBe(true);
  });
});

describe("runSignin — subsequent daemon (totp_required)", () => {
  beforeEach(() => sodium.ready);

  it("prompts for a single code from the existing authenticator", async () => {
    const h = makeHarness();

    h.pushResponse(() => ({ request_id: "req_xyz" }));
    h.pushResponse(() => ({ status: "totp_required", request_id: "req_xyz" }));
    h.pushResponse((body) => {
      expect(body.code).toBe("987654");
      expect(body.code1).toBeUndefined();
      expect(body.code2).toBeUndefined();
      return {
        status: "verified",
        public_key: "pk",
        account_id: "01HVCEXISTING000000000000",
        totp_secret: "existing",
      };
    });

    h.pushPromptInput("111111"); // email code
    h.pushPromptInput("987654"); // totp code

    const { account, freshTotp } = await runSignin(
      {
        email: "shared@example.com",
        relayUrl: "http://localhost:4000",
        label: "second-laptop",
      },
      h.deps
    );

    expect(freshTotp).toBe(false);
    // Every daemon persists the account's TOTP secret (the relay echoes
    // it back on the verify/totp response for this exact reason — so
    // adding a daemon doesn't lose the "any daemon can mint" property).
    expect(account.totpSecretB32).toBe("existing");
    expect(account.daemonKey).toBeDefined();
    expect(account.clientKey).toBeUndefined();
    expect(h.prompts).toEqual(["Email code (6 digits): ", "TOTP code: "]);
    // No QR on this path — the secret is already on some other daemon
    // and was handed to the operator when THAT daemon did totp_setup.
    expect(h.logs.some((l) => l.startsWith("otpauth://totp/"))).toBe(false);
  });

  it("honors overrideTotpCode so automation can skip the prompt", async () => {
    const h = makeHarness();
    h.pushResponse(() => ({ request_id: "r" }));
    h.pushResponse(() => ({ status: "totp_required", request_id: "r" }));
    h.pushResponse((body) => {
      expect(body.code).toBe("555111");
      return {
        status: "verified",
        public_key: "p",
        account_id: "01HVCOVERRIDE0000000000000",
        totp_secret: "x",
      };
    });
    h.pushPromptInput("000000"); // email code

    await runSignin(
      {
        email: "a@b.com",
        relayUrl: "http://localhost:4000",
        label: "ci",
        overrideTotpCode: "555111",
      },
      h.deps
    );
    expect(h.prompts).toEqual(["Email code (6 digits): "]);
  });
});

describe("runSignin — error surface", () => {
  beforeEach(() => sodium.ready);

  it("propagates the relay's error message on /api/signin failure", async () => {
    const h = makeHarness();
    // Non-2xx path: our mock fetch sends 500 when no response queued; simulate
    // a 422 explicitly.
    globalThis.fetch = (async () => {
      return new Response(JSON.stringify({ error: "invalid email" }), {
        status: 422,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    await expect(
      runSignin(
        { email: "not-an-email", relayUrl: "http://localhost:4000", label: "x" },
        h.deps
      )
    ).rejects.toThrow(/invalid email/);
  });
});
