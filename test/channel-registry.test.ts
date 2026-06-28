import { describe, it, expect, vi } from "vitest";
import {
  ChannelRegistry,
  ChannelOpenError,
  MAX_CHANNELS,
  type ChannelHandler,
} from "../src/relay/channel-registry.ts";

/** Tiny fake handler that records the close reason it received. */
function makeFakeHandler(mode: ChannelHandler["mode"] = "pty"): ChannelHandler & {
  closeCalls: string[];
  onFrameCalls: Array<{ type: number; payload: Uint8Array }>;
} {
  const closeCalls: string[] = [];
  const onFrameCalls: Array<{ type: number; payload: Uint8Array }> = [];
  return {
    mode,
    onFrame(type, payload) {
      onFrameCalls.push({ type, payload });
    },
    close(reason) {
      closeCalls.push(reason);
    },
    closeCalls,
    onFrameCalls,
  };
}

describe("ChannelRegistry — open / close / lookup", () => {
  it("starts empty", () => {
    const r = new ChannelRegistry();
    expect(r.size()).toBe(0);
    expect(r.ids()).toEqual([]);
    expect(r.has(1)).toBe(false);
    expect(r.get(1)).toBeUndefined();
  });

  it("registers a handler under an id", () => {
    const r = new ChannelRegistry();
    const h = makeFakeHandler();
    r.open(1, h);
    expect(r.size()).toBe(1);
    expect(r.has(1)).toBe(true);
    expect(r.get(1)).toBe(h);
    expect(r.ids()).toEqual([1]);
  });

  it("throws ChannelOpenError(id_collision) on a duplicate id", () => {
    const r = new ChannelRegistry();
    r.open(1, makeFakeHandler());
    expect(() => r.open(1, makeFakeHandler())).toThrow(ChannelOpenError);
    try {
      r.open(1, makeFakeHandler());
    } catch (err) {
      expect(err).toBeInstanceOf(ChannelOpenError);
      expect((err as ChannelOpenError).code).toBe("id_collision");
    }
    expect(r.size()).toBe(1); // original survives
  });

  it("throws ChannelOpenError(channel_limit) at MAX_CHANNELS", () => {
    const r = new ChannelRegistry();
    for (let i = 1; i <= MAX_CHANNELS; i++) {
      r.open(i, makeFakeHandler());
    }
    expect(() => r.open(MAX_CHANNELS + 1, makeFakeHandler())).toThrow(
      ChannelOpenError,
    );
    try {
      r.open(MAX_CHANNELS + 1, makeFakeHandler());
    } catch (err) {
      expect((err as ChannelOpenError).code).toBe("channel_limit");
    }
    expect(r.size()).toBe(MAX_CHANNELS);
  });

  it("close() returns false for an unknown id and is idempotent", () => {
    const r = new ChannelRegistry();
    expect(r.close(99, "x")).toBe(false);
    const h = makeFakeHandler();
    r.open(1, h);
    expect(r.close(1, "exit")).toBe(true);
    expect(r.close(1, "exit-again")).toBe(false);
    expect(h.closeCalls).toEqual(["exit"]);
  });

  it("close() removes the id BEFORE calling handler.close (no half-state visible from handler)", () => {
    const r = new ChannelRegistry();
    let observedSize = -1;
    const h: ChannelHandler = {
      mode: "pty",
      onFrame() {},
      close() {
        observedSize = r.size();
      },
    };
    r.open(1, h);
    r.close(1, "exit");
    expect(observedSize).toBe(0);
  });

  it("close() swallows a handler that throws", () => {
    const r = new ChannelRegistry();
    const h: ChannelHandler = {
      mode: "pty",
      onFrame() {},
      close() {
        throw new Error("buggy handler");
      },
    };
    r.open(1, h);
    // Should not propagate.
    expect(() => r.close(1, "exit")).not.toThrow();
    expect(r.has(1)).toBe(false);
  });
});

describe("ChannelRegistry — closeAll cascade", () => {
  it("calls close() on every registered handler exactly once", () => {
    const r = new ChannelRegistry();
    const handlers = [makeFakeHandler(), makeFakeHandler(), makeFakeHandler()];
    handlers.forEach((h, i) => r.open(i + 1, h));
    r.closeAll("peer_lost");
    expect(handlers.every((h) => h.closeCalls.length === 1)).toBe(true);
    expect(handlers.every((h) => h.closeCalls[0] === "peer_lost")).toBe(true);
    expect(r.size()).toBe(0);
  });

  it("closeAll keeps going even if individual handlers throw", () => {
    const r = new ChannelRegistry();
    const goodA = makeFakeHandler();
    const bad: ChannelHandler = {
      mode: "pty",
      onFrame() {},
      close() { throw new Error("nope"); },
    };
    const goodB = makeFakeHandler();
    r.open(1, goodA);
    r.open(2, bad);
    r.open(3, goodB);
    r.closeAll("peer_lost");
    expect(goodA.closeCalls).toEqual(["peer_lost"]);
    expect(goodB.closeCalls).toEqual(["peer_lost"]);
    expect(r.size()).toBe(0);
  });

  it("closeAll on an empty registry is a no-op", () => {
    const r = new ChannelRegistry();
    expect(() => r.closeAll("peer_lost")).not.toThrow();
    expect(r.size()).toBe(0);
  });
});

describe("ChannelRegistry — handlers receive frames", () => {
  it("forwards onFrame to the registered handler (registry isn't called here, but the contract matters)", () => {
    const h = makeFakeHandler();
    h.onFrame(0x00, new Uint8Array([1, 2, 3]));
    expect(h.onFrameCalls.length).toBe(1);
    expect(h.onFrameCalls[0].type).toBe(0x00);
    expect(Array.from(h.onFrameCalls[0].payload)).toEqual([1, 2, 3]);
  });

  it("a vi.fn handler works through the registry contract", () => {
    const r = new ChannelRegistry();
    const onFrame = vi.fn();
    const close = vi.fn();
    r.open(7, { mode: "exec", onFrame, close });
    r.get(7)?.onFrame(0x01, new Uint8Array([0xff]));
    r.close(7, "exit");
    expect(onFrame).toHaveBeenCalledWith(0x01, expect.any(Uint8Array));
    expect(close).toHaveBeenCalledWith("exit");
  });
});
