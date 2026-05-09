// @vitest-environment happy-dom
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { openTextSelectOverlay } from "../browser/src/text-select-overlay.ts";

/**
 * The overlay is a thin DOM widget around a buffer snapshot. We
 * verify:
 *   - the snapshot is taken once at open time (later writes don't
 *     shift the rendered text — important so an in-progress
 *     selection isn't yanked out from under the user)
 *   - the Copy All button writes the snapshot to the clipboard
 *   - Close removes the overlay
 *   - opening twice in a row replaces the stale instance instead of
 *     stacking
 *   - trailing blank rows are trimmed (xterm's buffer is allocated
 *     to the configured rows; without trimming we'd render dozens
 *     of empty lines at the bottom of every overlay)
 */

interface FakeBufferLine {
  translateToString(trim?: boolean): string;
}
interface FakeBuffer {
  length: number;
  getLine(i: number): FakeBufferLine | null;
}

function makeFakeTerm(lines: string[]) {
  const buffer: FakeBuffer = {
    length: lines.length,
    getLine(i: number) {
      const line = lines[i];
      if (line === undefined) return null;
      return { translateToString: () => line };
    },
  };
  return {
    buffer: { active: buffer },
  } as unknown as import("@xterm/xterm").Terminal;
}

beforeEach(() => {
  document.body.innerHTML = "";
});

afterEach(() => {
  document.getElementById("text-select-overlay")?.remove();
  vi.restoreAllMocks();
});

describe("openTextSelectOverlay", () => {
  it("appends an overlay element to the body with the buffer text", () => {
    const term = makeFakeTerm(["hello", "world"]);
    openTextSelectOverlay(term);

    const overlay = document.getElementById("text-select-overlay");
    expect(overlay).toBeTruthy();
    const pre = overlay!.querySelector(".tso-text");
    expect(pre?.textContent).toBe("hello\nworld");
  });

  it("trims trailing blank rows so an under-filled buffer doesn't render a tail of empty lines", () => {
    // 24-row buffer with content only in the first two — this is the
    // common case immediately after attach, before the program has
    // written enough output to fill the viewport.
    const lines = ["line1", "line2", ...new Array(22).fill("")];
    const term = makeFakeTerm(lines);
    openTextSelectOverlay(term);
    const pre = document.querySelector("#text-select-overlay .tso-text");
    expect(pre?.textContent).toBe("line1\nline2");
  });

  it("close() removes the overlay from the DOM", () => {
    const term = makeFakeTerm(["x"]);
    const handle = openTextSelectOverlay(term);
    expect(document.getElementById("text-select-overlay")).toBeTruthy();
    handle.close();
    expect(document.getElementById("text-select-overlay")).toBeNull();
  });

  it("calling open twice replaces the previous overlay instead of stacking", () => {
    openTextSelectOverlay(makeFakeTerm(["first snapshot"]));
    openTextSelectOverlay(makeFakeTerm(["second snapshot"]));
    const overlays = document.querySelectorAll("#text-select-overlay");
    expect(overlays).toHaveLength(1);
    expect(overlays[0].querySelector(".tso-text")?.textContent).toBe(
      "second snapshot"
    );
  });

  it("Close button removes the overlay", () => {
    openTextSelectOverlay(makeFakeTerm(["abc"]));
    const closeBtn = document.querySelector(
      "#text-select-overlay .tso-close"
    ) as HTMLButtonElement;
    expect(closeBtn).toBeTruthy();
    closeBtn.click();
    expect(document.getElementById("text-select-overlay")).toBeNull();
  });

  it("Copy All writes the buffer text to the clipboard", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });

    openTextSelectOverlay(makeFakeTerm(["alpha", "beta"]));
    const buttons = document.querySelectorAll<HTMLButtonElement>(
      "#text-select-overlay .tso-btn"
    );
    const copyBtn = Array.from(buttons).find((b) => b.textContent === "Copy All")!;
    expect(copyBtn).toBeTruthy();

    copyBtn.click();
    // The async clipboard call resolves on the next microtask.
    await Promise.resolve();
    await Promise.resolve();

    expect(writeText).toHaveBeenCalledTimes(1);
    expect(writeText).toHaveBeenCalledWith("alpha\nbeta");
  });

  it("clicking the dim backdrop (overlay container) closes — clicking inside the panel does not", () => {
    openTextSelectOverlay(makeFakeTerm(["x"]));
    const overlay = document.getElementById("text-select-overlay")!;

    // Click on the pre (inside the panel) — should NOT close.
    const pre = overlay.querySelector(".tso-text") as HTMLElement;
    pre.click();
    expect(document.getElementById("text-select-overlay")).toBeTruthy();

    // Click on the overlay itself (the dim backdrop) — should close.
    overlay.click();
    expect(document.getElementById("text-select-overlay")).toBeNull();
  });
});
