import { describe, it, expect } from "vitest";
import { SessionBridge } from "../src/relay/session-bridge.ts";
import type { ChannelHandler } from "../src/relay/channel-registry.ts";

/**
 * Surface-level contract tests for the v2 SessionBridge port. The
 * happy-path attach + bridging flow is covered by the integration suite
 * (it needs a real `@myobie/pty` Unix socket); these tests pin the
 * channel-mux interface so a future refactor doesn't drift the shape.
 */

describe("SessionBridge — ChannelHandler shape", () => {
  it("implements the ChannelHandler interface", () => {
    const bridge = new SessionBridge(() => {});
    const asHandler: ChannelHandler = bridge; // type-level check
    expect(asHandler.mode).toBe("pty");
    expect(typeof asHandler.onFrame).toBe("function");
    expect(typeof asHandler.close).toBe("function");
  });

  it("close() is idempotent (registry cascade-close safety)", () => {
    const bridge = new SessionBridge(() => {});
    expect(() => bridge.close("first")).not.toThrow();
    expect(() => bridge.close("second")).not.toThrow();
    expect(bridge.isConnected()).toBe(false);
  });

  it("onFrame() before attach is a no-op (socket is null)", () => {
    const bridge = new SessionBridge(() => {});
    // Should drop on the floor rather than crash if a frame arrives
    // before/after the pty socket is up.
    expect(() =>
      bridge.onFrame(0, new Uint8Array([1, 2, 3])),
    ).not.toThrow();
  });

  it("getSessionName() is null before attach", () => {
    const bridge = new SessionBridge(() => {});
    expect(bridge.getSessionName()).toBeNull();
  });

  it("isConnected() is false before attach", () => {
    const bridge = new SessionBridge(() => {});
    expect(bridge.isConnected()).toBe(false);
  });
});
