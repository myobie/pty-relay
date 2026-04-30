// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  notify,
  registerOscHandlers,
  _resetForTesting,
  type OscTerminalLike,
} from "../browser/src/notifications.ts";

interface FakeTerm extends OscTerminalLike {
  fireOsc(ident: number, data: string): boolean;
}

function makeFakeTerm(): FakeTerm {
  const handlers = new Map<number, (data: string) => boolean>();
  return {
    parser: {
      registerOscHandler(ident, cb) {
        handlers.set(ident, cb);
        return { dispose() { handlers.delete(ident); } };
      },
    },
    fireOsc(ident, data) {
      const cb = handlers.get(ident);
      return cb ? cb(data) : false;
    },
  };
}

/** Replace the global Notification with a controllable spy. Returns
 *  cleanup + the spy's recorded calls. */
function stubNotification(opts: {
  permission: NotificationPermission;
  request?: () => Promise<NotificationPermission>;
  throwOnConstruct?: boolean;
}) {
  const calls: Array<{ title: string; body: string }> = [];
  class FakeNotification {
    static permission: NotificationPermission = opts.permission;
    static requestPermission = opts.request ?? (async () => "granted" as NotificationPermission);
    constructor(title: string, init?: NotificationOptions) {
      if (opts.throwOnConstruct) {
        throw new TypeError("Failed to construct 'Notification': Illegal constructor.");
      }
      calls.push({ title, body: init?.body ?? "" });
    }
  }
  Object.defineProperty(window, "Notification", {
    configurable: true,
    value: FakeNotification,
  });
  return { calls };
}

beforeEach(() => {
  document.body.replaceChildren();
  _resetForTesting();
});

afterEach(() => {
  // Best-effort: leave Notification as whatever happy-dom had originally.
  delete (window as any).Notification;
});

describe("notify", () => {
  it("uses the system Notification when permission is granted and constructor works", async () => {
    const { calls } = stubNotification({ permission: "granted" });
    const channel = await notify("Build", "Done");
    expect(channel).toBe("system");
    expect(calls).toEqual([{ title: "Build", body: "Done" }]);
  });

  it("falls back to a toast when constructor throws (Android Chrome / iOS)", async () => {
    stubNotification({ permission: "granted", throwOnConstruct: true });
    const channel = await notify("Build", "Done");
    expect(channel).toBe("toast");
    const toast = document.querySelector(".pty-toast")!;
    expect(toast.querySelector(".pty-toast-title")?.textContent).toBe("Build");
    expect(toast.querySelector(".pty-toast-body")?.textContent).toBe("Done");
  });

  it("falls back to a toast when permission is denied", async () => {
    stubNotification({ permission: "denied" });
    const channel = await notify("Build", "Done");
    expect(channel).toBe("toast");
  });

  it("requests permission once when permission is default", async () => {
    const request = vi.fn().mockResolvedValue("granted" as NotificationPermission);
    const { calls } = stubNotification({ permission: "default", request });
    await notify("a", "b");
    await notify("c", "d");
    expect(request).toHaveBeenCalledTimes(1);
    // At least one call landed; second may have been throttled.
    expect(calls.length).toBeGreaterThan(0);
  });

  it("throttles back-to-back notifications within the cooldown", async () => {
    const { calls } = stubNotification({ permission: "granted" });
    const a = await notify("a", "1");
    const b = await notify("b", "2");
    expect(a).toBe("system");
    expect(b).toBe("throttled");
    expect(calls).toEqual([{ title: "a", body: "1" }]);
  });
});

describe("registerOscHandlers", () => {
  it("OSC 9 routes to notify with the supplied fallback title", async () => {
    const { calls } = stubNotification({ permission: "granted" });
    const term = makeFakeTerm();
    registerOscHandlers(term, () => "shell-1");
    const handled = term.fireOsc(9, "Build complete");
    // Wait for the async notify to resolve.
    await Promise.resolve();
    expect(handled).toBe(true);
    expect(calls).toEqual([{ title: "shell-1", body: "Build complete" }]);
  });

  it("OSC 777 with notify;TITLE;BODY parses into title + body", async () => {
    const { calls } = stubNotification({ permission: "granted" });
    const term = makeFakeTerm();
    registerOscHandlers(term, () => "fallback");
    const handled = term.fireOsc(777, "notify;Custom Title;Custom Body");
    await Promise.resolve();
    expect(handled).toBe(true);
    expect(calls).toEqual([{ title: "Custom Title", body: "Custom Body" }]);
  });

  it("OSC 777 with body containing semicolons preserves them", async () => {
    const { calls } = stubNotification({ permission: "granted" });
    const term = makeFakeTerm();
    registerOscHandlers(term, () => "fallback");
    term.fireOsc(777, "notify;T;a;b;c");
    await Promise.resolve();
    expect(calls).toEqual([{ title: "T", body: "a;b;c" }]);
  });

  it("OSC 777 without 'notify;' prefix returns false (lets other handlers take it)", () => {
    stubNotification({ permission: "granted" });
    const term = makeFakeTerm();
    registerOscHandlers(term, () => "fallback");
    const handled = term.fireOsc(777, "something_else;data");
    expect(handled).toBe(false);
  });

  it("disposer removes both handlers", async () => {
    stubNotification({ permission: "granted" });
    const term = makeFakeTerm();
    const reg = registerOscHandlers(term, () => "fallback");
    reg.dispose();
    const h9 = term.fireOsc(9, "x");
    const h777 = term.fireOsc(777, "notify;a;b");
    expect(h9).toBe(false);
    expect(h777).toBe(false);
  });
});
