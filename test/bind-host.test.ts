import { describe, it, expect } from "vitest";
import { resolveBindHost } from "../src/serve/bind-host.ts";

/**
 * Issue #1 — `--bind <addr>` for the self-hosted relay; default to
 * loopback when `--tailscale` is set.
 *
 * The runtime listening behavior is covered by test/serve-bind.test.ts
 * (which actually boots `createRelayServer` and probes interfaces).
 * This file just nails down the precedence rules for the bind value
 * the CLI hands to that function.
 */
describe("resolveBindHost", () => {
  it("--tailscale without --bind defaults to 127.0.0.1", () => {
    expect(resolveBindHost({ explicit: null, tailscale: true })).toBe(
      "127.0.0.1"
    );
  });

  it("--tailscale --bind 0.0.0.0 opts back in to all interfaces", () => {
    // Returning the explicit "0.0.0.0" — rather than undefined — is
    // significant: it means the operator made an active choice. The
    // server passes it to httpServer.listen verbatim, which binds to
    // every IPv4 interface.
    expect(
      resolveBindHost({ explicit: "0.0.0.0", tailscale: true })
    ).toBe("0.0.0.0");
  });

  it("no --tailscale preserves the historical all-interfaces default", () => {
    // undefined → start.ts falls through to the no-host listen() call,
    // which is Node's default (binds 0.0.0.0). We want this UNCHANGED
    // for non-tailscale users so anyone deliberately running on a LAN
    // doesn't silently get cut off after the upgrade.
    expect(resolveBindHost({ explicit: null, tailscale: false })).toBeUndefined();
  });

  it("explicit --bind always wins, even without --tailscale", () => {
    expect(
      resolveBindHost({ explicit: "192.168.1.5", tailscale: false })
    ).toBe("192.168.1.5");
  });

  it("explicit --bind overrides the tailscale loopback default", () => {
    expect(
      resolveBindHost({ explicit: "10.0.0.1", tailscale: true })
    ).toBe("10.0.0.1");
  });
});
