// @vitest-environment happy-dom
import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  loadFontSize,
  saveFontSize,
  applyFontSize,
  createFontSizeController,
  FONT_SIZE_LIMITS,
} from "../browser/src/font-size.ts";

interface FakeTerm {
  options: { fontSize?: number };
}
interface FakeFit {
  fits: number;
  fit(): void;
}

function fakes(): { term: FakeTerm; fit: FakeFit } {
  const term: FakeTerm = { options: {} };
  const fit: FakeFit = {
    fits: 0,
    fit() { this.fits++; },
  };
  return { term, fit };
}

/** happy-dom's localStorage is read-only by default — getItem returns
 *  null and setItem is a no-op. Replace the binding for each test
 *  with a real in-memory Storage shim so save/load round-trip
 *  faithfully. */
function stubLocalStorage(seed?: string) {
  const store = new Map<string, string>();
  if (seed !== undefined) store.set("pty-relay:font-size", seed);
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

beforeEach(() => {
  stubLocalStorage();
});

describe("loadFontSize", () => {
  it("returns the default when no value is stored", () => {
    expect(loadFontSize()).toBe(FONT_SIZE_LIMITS.default);
  });

  it("returns the stored value when valid", () => {
    localStorage.setItem("pty-relay:font-size", "18");
    expect(loadFontSize()).toBe(18);
  });

  it("clamps a too-small stored value up to the minimum", () => {
    localStorage.setItem("pty-relay:font-size", "2");
    expect(loadFontSize()).toBe(FONT_SIZE_LIMITS.min);
  });

  it("clamps a too-large stored value down to the maximum", () => {
    localStorage.setItem("pty-relay:font-size", "999");
    expect(loadFontSize()).toBe(FONT_SIZE_LIMITS.max);
  });

  it("falls back to the default for non-numeric junk", () => {
    localStorage.setItem("pty-relay:font-size", "huge");
    expect(loadFontSize()).toBe(FONT_SIZE_LIMITS.default);
  });
});

describe("saveFontSize", () => {
  it("persists the supplied value", () => {
    saveFontSize(20);
    expect(localStorage.getItem("pty-relay:font-size")).toBe("20");
  });

  it("clamps before persisting", () => {
    saveFontSize(1);
    expect(localStorage.getItem("pty-relay:font-size")).toBe(String(FONT_SIZE_LIMITS.min));
    saveFontSize(1000);
    expect(localStorage.getItem("pty-relay:font-size")).toBe(String(FONT_SIZE_LIMITS.max));
  });
});

describe("applyFontSize", () => {
  it("sets term.options.fontSize and re-fits", () => {
    const { term, fit } = fakes();
    applyFontSize(term as any, fit as any, 17);
    expect(term.options.fontSize).toBe(17);
    expect(fit.fits).toBe(1);
  });

  it("clamps the supplied value", () => {
    const { term, fit } = fakes();
    applyFontSize(term as any, fit as any, 2);
    expect(term.options.fontSize).toBe(FONT_SIZE_LIMITS.min);
  });

  it("ignores fit() throwing (e.g. canvas not yet measurable)", () => {
    const { term } = fakes();
    const fit = {
      fit: () => { throw new Error("not measurable"); },
    };
    // Must not propagate.
    expect(() => applyFontSize(term as any, fit as any, 16)).not.toThrow();
    expect(term.options.fontSize).toBe(16);
  });
});

describe("createFontSizeController", () => {
  it("applies the saved size on construction", () => {
    localStorage.setItem("pty-relay:font-size", "20");
    const { term, fit } = fakes();
    const ctl = createFontSizeController(term as any, fit as any);
    expect(term.options.fontSize).toBe(20);
    expect(ctl.current()).toBe(20);
  });

  it("bump(+1) increases by one and persists", () => {
    const { term, fit } = fakes();
    const ctl = createFontSizeController(term as any, fit as any, 14);
    ctl.bump(+1);
    expect(ctl.current()).toBe(15);
    expect(term.options.fontSize).toBe(15);
    expect(localStorage.getItem("pty-relay:font-size")).toBe("15");
  });

  it("bump(-1) decreases by one and persists", () => {
    const { term, fit } = fakes();
    const ctl = createFontSizeController(term as any, fit as any, 14);
    ctl.bump(-1);
    expect(ctl.current()).toBe(13);
  });

  it("does not bump past the maximum", () => {
    const { term, fit } = fakes();
    const ctl = createFontSizeController(term as any, fit as any, FONT_SIZE_LIMITS.max);
    ctl.bump(+1);
    expect(ctl.current()).toBe(FONT_SIZE_LIMITS.max);
  });

  it("does not bump past the minimum", () => {
    const { term, fit } = fakes();
    const ctl = createFontSizeController(term as any, fit as any, FONT_SIZE_LIMITS.min);
    ctl.bump(-1);
    expect(ctl.current()).toBe(FONT_SIZE_LIMITS.min);
  });

  it("reset goes back to the default", () => {
    const { term, fit } = fakes();
    const ctl = createFontSizeController(term as any, fit as any, 22);
    ctl.reset();
    expect(ctl.current()).toBe(FONT_SIZE_LIMITS.default);
  });

  it("doesn't refit when the size doesn't actually change", () => {
    const { term, fit } = fakes();
    const initial = fit.fits; // applyFontSize at construction fits once
    const ctl = createFontSizeController(term as any, fit as any, FONT_SIZE_LIMITS.max);
    const afterCtor = fit.fits;
    expect(afterCtor).toBe(initial + 1);
    ctl.bump(+1); // already at max — should be a no-op
    expect(fit.fits).toBe(afterCtor);
  });
});
