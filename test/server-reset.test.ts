import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { resetCommand } from "../src/commands/server/reset.ts";

/**
 * Exercises the `pty-relay server reset` command against a stubbed
 * `fetch`. Reset is intentionally simple — unauthenticated POST to
 * `/api/account/reset` — but we still want to lock down:
 *   - the wire shape (path + body)
 *   - that it is unsigned (no `payload`/`sig` query params)
 *   - that 429 maps to a non-zero exit with a friendly message
 *   - that other 4xx exits non-zero
 *   - that 200 prints next-steps without exiting
 */

interface Call {
  path: string;
  query: Record<string, string>;
  body: Record<string, unknown>;
}

function installFetchStub(handler: (call: Call) => { status: number; body: unknown }) {
  const calls: Call[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const u = new URL(url);
    const query: Record<string, string> = {};
    for (const [k, v] of u.searchParams.entries()) query[k] = v;
    const body = JSON.parse((init?.body as string) || "{}");
    const call: Call = { path: u.pathname, query, body };
    calls.push(call);
    const { status, body: respBody } = handler(call);
    return new Response(JSON.stringify(respBody), {
      status,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return calls;
}

describe("server reset", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`__exit__:${code ?? 0}`);
    }) as never);
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    logSpy.mockRestore();
    errSpy.mockRestore();
  });

  it("posts the email unsigned to /api/account/reset and prints next-steps on 200", async () => {
    const calls = installFetchStub(() => ({
      status: 200,
      body: { status: "maybe_sent" },
    }));

    await resetCommand({
      email: "alice@example.com",
      relayUrl: "http://localhost:4000",
    });

    expect(calls).toHaveLength(1);
    const call = calls[0]!;
    expect(call.path).toBe("/api/account/reset");
    expect(call.body).toEqual({ email: "alice@example.com" });
    // Reset is intentionally unauthenticated — no Ed25519 triple.
    expect(call.query).not.toHaveProperty("payload");
    expect(call.query).not.toHaveProperty("sig");
    expect(call.query).not.toHaveProperty("public_key");

    // Next-steps should explicitly point the user at the signin command
    // so they can re-enroll once the email confirmation revokes keys.
    const printed = logSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(printed).toContain("alice@example.com");
    expect(printed).toContain("pty-relay server signin");
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("treats 429 as a friendly rate-limit error and exits non-zero", async () => {
    installFetchStub(() => ({
      status: 429,
      body: { error: "too many reset attempts" },
    }));

    await expect(
      resetCommand({
        email: "alice@example.com",
        relayUrl: "http://localhost:4000",
      })
    ).rejects.toThrow("__exit__:1");

    const errs = errSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(errs.toLowerCase()).toContain("rate limited");
    expect(errs).toContain("too many reset attempts");
  });

  it("surfaces other 4xx errors and exits non-zero", async () => {
    installFetchStub(() => ({
      status: 400,
      body: { error: "invalid email" },
    }));

    await expect(
      resetCommand({
        email: "not-an-email",
        relayUrl: "http://localhost:4000",
      })
    ).rejects.toThrow("__exit__:1");

    const errs = errSpy.mock.calls.map((c) => c[0]).join("\n");
    expect(errs).toContain("invalid email");
    expect(errs).toContain("HTTP 400");
  });
});
