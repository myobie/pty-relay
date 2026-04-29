// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  startTentativeTyping,
  tentativeEnabled,
  type TermLike,
  type TentativeController,
} from "../browser/src/tentative-typing.ts";

interface FakeTerm extends TermLike {
  emitData(s: string): void;
  emitParsed(): void;
  written: string[];
}

function makeFakeTerm(): FakeTerm {
  let onDataCb: ((s: string) => void) | null = null;
  let onParsedCb: (() => void) | null = null;
  const written: string[] = [];
  return {
    write(s) { written.push(s); },
    onData(cb) {
      onDataCb = cb;
      return { dispose() { onDataCb = null; } };
    },
    onWriteParsed(cb) {
      onParsedCb = cb;
      return { dispose() { onParsedCb = null; } };
    },
    emitData(s) { onDataCb?.(s); },
    emitParsed() { onParsedCb?.(); },
    written,
  };
}

let controller: TentativeController | null = null;

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  controller?.destroy();
  controller = null;
  vi.useRealTimers();
});

describe("startTentativeTyping", () => {
  it("renders a dim char + cursor-back when a printable char is typed", () => {
    const term = makeFakeTerm();
    controller = startTentativeTyping(term);
    term.emitData("a");
    expect(term.written).toEqual(["\x1b[2ma\x1b[22m\x1b[D"]);
  });

  it("does not tentative-render Enter / arrows / Ctrl+chars / multi-byte", () => {
    const term = makeFakeTerm();
    controller = startTentativeTyping(term);
    for (const s of ["\r", "\n", "\x1b[A", "\x03", "ab", "\x7f"]) {
      term.emitData(s);
    }
    expect(term.written).toEqual([]);
  });

  it("erases the tentative after the timeout if no echo arrives", () => {
    const term = makeFakeTerm();
    controller = startTentativeTyping(term);
    term.emitData("a");
    expect(term.written).toHaveLength(1);
    vi.advanceTimersByTime(199);
    expect(term.written).toHaveLength(1); // not yet
    vi.advanceTimersByTime(2);
    expect(term.written).toHaveLength(2);
    expect(term.written[1]).toBe(" \x1b[D"); // space + cursor-back
  });

  it("an incoming onWriteParsed cancels the pending eraser", () => {
    const term = makeFakeTerm();
    controller = startTentativeTyping(term);
    term.emitData("a");
    // Simulate the echo arriving — xterm's parser fires after.
    term.emitParsed();
    vi.advanceTimersByTime(500);
    // Only the original dim write — no erase ran.
    expect(term.written).toHaveLength(1);
  });

  it("a second keystroke supersedes the first tentative", () => {
    const term = makeFakeTerm();
    controller = startTentativeTyping(term);
    term.emitData("a");
    vi.advanceTimersByTime(50);
    term.emitData("b");
    // First's eraser is canceled, b's tentative is rendered.
    expect(term.written).toEqual([
      "\x1b[2ma\x1b[22m\x1b[D",
      "\x1b[2mb\x1b[22m\x1b[D",
    ]);
    // Wait long enough for any timer that should fire.
    vi.advanceTimersByTime(300);
    // b's eraser fired (no echo), but a's was canceled. Total writes
    // = 2 dim + 1 erase.
    expect(term.written).toHaveLength(3);
    expect(term.written[2]).toBe(" \x1b[D");
  });

  it("destroy() removes listeners and cancels pending timers", () => {
    const term = makeFakeTerm();
    controller = startTentativeTyping(term);
    term.emitData("a");
    controller.destroy();
    controller = null;
    vi.advanceTimersByTime(500);
    // No erase fired after destroy.
    expect(term.written).toHaveLength(1);
  });
});

describe("tentativeEnabled", () => {
  // happy-dom's localStorage is read-only (returns null + ignores
  // sets). Stub a minimal Storage shim so tentativeEnabled() can
  // observe what we set.
  const stubLocalStorage = (value: string | null) => {
    const store = new Map<string, string>();
    if (value !== null) store.set("pty-relay:tentative", value);
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => store.set(k, v),
        removeItem: (k: string) => store.delete(k),
        clear: () => store.clear(),
        key: () => null,
        length: 0,
      } as Storage,
    });
  };

  it("returns false by default", () => {
    stubLocalStorage(null);
    expect(tentativeEnabled()).toBe(false);
  });

  it("returns true when localStorage flag is '1'", () => {
    stubLocalStorage("1");
    expect(tentativeEnabled()).toBe(true);
  });

  it("returns false for any other value", () => {
    stubLocalStorage("true");
    expect(tentativeEnabled()).toBe(false);
  });
});
