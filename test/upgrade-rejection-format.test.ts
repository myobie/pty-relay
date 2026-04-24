import { describe, it, expect } from "vitest";
import { formatUpgradeRejection } from "../src/relay/relay-connection.ts";

/**
 * formatUpgradeRejection turns a rejected WS upgrade (status + body)
 * into a human-readable error string. Important enough to test because
 * the 403 reason text is the user's only signal about why pairing
 * failed — a bare "HTTP 403" is useless, especially for the pin /
 * ACL cases where the action ("check your pin", "ask for an ACL row")
 * depends on the reason.
 */

describe("formatUpgradeRejection", () => {
  it("surfaces JSON `error` field when present", () => {
    const msg = formatUpgradeRejection(
      403,
      JSON.stringify({ error: "client is pinned to a different daemon" })
    );
    expect(msg).toMatch(/HTTP 403/);
    expect(msg).toMatch(/pinned to a different daemon/);
    // The extra hint points the user at `server status` for the pin.
    expect(msg).toMatch(/server status/);
  });

  it("surfaces JSON `reason` field when `error` is absent", () => {
    const msg = formatUpgradeRejection(
      403,
      JSON.stringify({ reason: "client is not permitted to pair with this daemon" })
    );
    expect(msg).toMatch(/not permitted/);
    // The ACL hint points at `server acls allow`.
    expect(msg).toMatch(/acls allow/);
  });

  it("falls back to raw body when not JSON", () => {
    const msg = formatUpgradeRejection(500, "proxy unreachable");
    expect(msg).toMatch(/HTTP 500/);
    expect(msg).toMatch(/proxy unreachable/);
  });

  it("caps very long raw bodies at 256 chars", () => {
    const long = "x".repeat(5000);
    const msg = formatUpgradeRejection(502, long);
    // 256 + ellipsis + framing text — nowhere near the original length.
    expect(msg.length).toBeLessThan(500);
    expect(msg).toMatch(/…/);
  });

  it("handles empty body cleanly", () => {
    const msg = formatUpgradeRejection(401, "");
    expect(msg).toBe("WS upgrade rejected with HTTP 401");
  });

  it("does not crash on malformed JSON", () => {
    const msg = formatUpgradeRejection(403, "{not json");
    expect(msg).toMatch(/HTTP 403/);
    expect(msg).toMatch(/\{not json/);
  });
});
