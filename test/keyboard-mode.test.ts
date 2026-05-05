// @vitest-environment happy-dom
import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  loadKeyboardMode,
  saveKeyboardMode,
  applyKeyboardMode,
  createKeyboardModeController,
  type KeyboardMode,
} from "../browser/src/keyboard-mode.ts";

function stubLocalStorage(seed?: KeyboardMode) {
  const store = new Map<string, string>();
  if (seed) store.set("pty-relay:keyboard-mode", seed);
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
}

function makeTextarea(): HTMLTextAreaElement {
  const t = document.createElement("textarea");
  document.body.appendChild(t);
  return t;
}

beforeEach(() => {
  stubLocalStorage();
  document.body.replaceChildren();
});

describe("loadKeyboardMode", () => {
  it("returns 'assisted' by default", () => {
    expect(loadKeyboardMode()).toBe("assisted");
  });

  it("returns the stored value when it's one of the valid modes", () => {
    stubLocalStorage("raw");
    expect(loadKeyboardMode()).toBe("raw");
    stubLocalStorage("assisted");
    expect(loadKeyboardMode()).toBe("assisted");
  });

  it("falls back to default for an unknown stored value", () => {
    // Arbitrary string a future version of pty-relay might have
    // saved before adding validation.
    stubLocalStorage("vim" as unknown as KeyboardMode);
    expect(loadKeyboardMode()).toBe("assisted");
  });
});

describe("applyKeyboardMode", () => {
  it("raw mode disables every assist attribute", () => {
    const t = makeTextarea();
    applyKeyboardMode(t, "raw");
    expect(t.getAttribute("autocorrect")).toBe("off");
    expect(t.getAttribute("autocapitalize")).toBe("off");
    expect(t.getAttribute("autocomplete")).toBe("off");
    expect(t.getAttribute("spellcheck")).toBe("false");
  });

  it("assisted mode enables every assist attribute", () => {
    const t = makeTextarea();
    applyKeyboardMode(t, "assisted");
    expect(t.getAttribute("autocorrect")).toBe("on");
    expect(t.getAttribute("autocapitalize")).toBe("sentences");
    expect(t.getAttribute("autocomplete")).toBe("on");
    expect(t.getAttribute("spellcheck")).toBe("true");
  });

  it("switching from assisted to raw flips every attribute", () => {
    const t = makeTextarea();
    applyKeyboardMode(t, "assisted");
    applyKeyboardMode(t, "raw");
    expect(t.getAttribute("autocorrect")).toBe("off");
    expect(t.getAttribute("autocapitalize")).toBe("off");
    expect(t.getAttribute("spellcheck")).toBe("false");
  });
});

describe("createKeyboardModeController", () => {
  it("starts in the saved mode (assisted by default)", () => {
    const t = makeTextarea();
    const ctl = createKeyboardModeController(t);
    expect(ctl.current()).toBe("assisted");
    expect(t.getAttribute("autocorrect")).toBe("on");
  });

  it("starts in raw when that's what was saved", () => {
    stubLocalStorage("raw");
    const t = makeTextarea();
    const ctl = createKeyboardModeController(t);
    expect(ctl.current()).toBe("raw");
    expect(t.getAttribute("autocorrect")).toBe("off");
  });

  it("toggle swaps modes and persists", () => {
    const t = makeTextarea();
    const ctl = createKeyboardModeController(t);
    ctl.toggle();
    expect(ctl.current()).toBe("raw");
    expect(localStorage.getItem("pty-relay:keyboard-mode")).toBe("raw");
    ctl.toggle();
    expect(ctl.current()).toBe("assisted");
  });

  it("set() to the same mode is a no-op (no save, no callback)", () => {
    const t = makeTextarea();
    const onChange = vi.fn();
    const ctl = createKeyboardModeController(t, onChange);
    expect(onChange).toHaveBeenCalledTimes(1); // initial sync call
    ctl.set("assisted"); // same as current
    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it("calls onChange initially and on each change", () => {
    const t = makeTextarea();
    const onChange = vi.fn();
    const ctl = createKeyboardModeController(t, onChange);
    expect(onChange).toHaveBeenLastCalledWith("assisted");
    ctl.toggle();
    expect(onChange).toHaveBeenLastCalledWith("raw");
  });
});

describe("saveKeyboardMode", () => {
  it("writes to localStorage", () => {
    saveKeyboardMode("raw");
    expect(localStorage.getItem("pty-relay:keyboard-mode")).toBe("raw");
  });
});
