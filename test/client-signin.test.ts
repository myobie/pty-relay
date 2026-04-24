import { describe, it, expect, beforeEach } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import {
  runClientSignin,
  type ClientSigninDeps,
} from "../src/commands/client/signin.ts";
import { PublicApi } from "../src/relay/public-api.ts";

/**
 * Drives `runClientSignin` with a stubbed PublicApi + prompts. Asserts:
 *   - POST /api/signin body carries role=client, no totp_secret.
 *   - verify → totp_required branch (account must exist).
 *   - verify/totp → verified; no TOTP secret persisted on the resulting
 *     PublicAccount because clients don't own the shared secret.
 *   - The resulting clientKey has no pin (signed-in = account-wide).
 *   - totp_setup on this path is a hard error (client signin cannot
 *     create an account).
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

  const deps: ClientSigninDeps = {
    api: new PublicApi("http://localhost:4000"),
    generateSigningKeypair() {
      const seed = new Uint8Array(32);
      for (let i = 0; i < 32; i++) seed[i] = 0x40 + i;
      const kp = sodium.crypto_sign_seed_keypair(seed);
      return { publicKey: kp.publicKey, secretKey: kp.privateKey };
    },
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

describe("runClientSignin", () => {
  beforeEach(() => sodium.ready);

  it("registers a role=client key and does not persist a TOTP secret", async () => {
    const h = makeHarness();

    h.pushResponse((body) => {
      expect(body.role).toBe("client");
      expect(body.email).toBe("me@example.com");
      expect(typeof body.public_key).toBe("string");
      // Client signin never sends a TOTP secret — the account already
      // has one from the daemon signin.
      expect(body.totp_secret).toBeUndefined();
      return { request_id: "req_client" };
    });

    h.pushResponse((body) => {
      expect(body.request_id).toBe("req_client");
      expect(body.code).toBe("123456");
      return { status: "totp_required", request_id: "req_client" };
    });

    h.pushResponse((body) => {
      expect(body.request_id).toBe("req_client");
      expect(body.code).toBe("987654");
      // No code1/code2 on this path.
      expect(body.code1).toBeUndefined();
      expect(body.code2).toBeUndefined();
      // Relay does NOT return totp_secret on client signin.
      return {
        status: "verified",
        public_key: "pk_client",
        account_id: "01HVCACCOUNT00000000000000",
      };
    });

    h.pushPromptInput("123456"); // email code
    h.pushPromptInput("987654"); // totp code

    const { account } = await runClientSignin(
      {
        email: "me@example.com",
        relayUrl: "http://localhost:4000",
        label: "phone",
      },
      h.deps
    );

    expect(account.email).toBe("me@example.com");
    expect(account.label).toBe("phone");
    expect(account.accountId).toBe("01HVCACCOUNT00000000000000");
    expect(account.totpSecretB32).toBeUndefined();
    expect(account.daemonKey).toBeUndefined();
    expect(account.clientKey).toBeDefined();
    expect(account.clientKey!.signingKeys.public).toMatch(/^[A-Za-z0-9_-]+$/u);
    // Signed-in clients are account-wide; no pin.
    expect(account.clientKey!.pin).toBeUndefined();

    expect(h.calls.map((c) => c.path)).toEqual([
      "/api/signin",
      "/api/verify",
      "/api/verify/totp",
    ]);
  });

  it("treats totp_setup on the client path as a hard error", async () => {
    const h = makeHarness();
    h.pushResponse(() => ({ request_id: "req_x" }));
    h.pushResponse(() => ({
      status: "totp_setup",
      totp_url: "otpauth://totp/unexpected",
      totp_secret: "SECRET",
      request_id: "req_x",
    }));
    h.pushPromptInput("111111");

    await expect(
      runClientSignin(
        {
          email: "never@example.com",
          relayUrl: "http://localhost:4000",
          label: "x",
        },
        h.deps
      )
    ).rejects.toThrow(/cannot create accounts/);
  });
});
