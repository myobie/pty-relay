// @vitest-environment happy-dom
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { showToast, _clearAllToastsForTesting } from "../browser/src/toast.ts";

beforeEach(() => {
  document.body.replaceChildren();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  _clearAllToastsForTesting();
});

describe("showToast", () => {
  it("creates the stack on first call and appends a toast with title + body", () => {
    showToast("Build complete", "21 tests passed");
    const stack = document.getElementById("pty-toast-stack")!;
    expect(stack).toBeTruthy();
    const toast = stack.querySelector(".pty-toast")!;
    expect(toast.querySelector(".pty-toast-title")?.textContent).toBe(
      "Build complete"
    );
    expect(toast.querySelector(".pty-toast-body")?.textContent).toBe(
      "21 tests passed"
    );
  });

  it("renders no body div when body is empty", () => {
    showToast("Quick alert", "");
    const stack = document.getElementById("pty-toast-stack")!;
    expect(stack.querySelector(".pty-toast-body")).toBeNull();
  });

  it("does not interpret HTML in title or body (XSS safe)", () => {
    showToast("<img src=x onerror=alert(1)>", "<script>alert(2)</script>");
    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("script")).toBeNull();
    expect(
      document.querySelector(".pty-toast-title")?.textContent
    ).toBe("<img src=x onerror=alert(1)>");
  });

  it("auto-dismisses after the default duration (~6s + animation)", () => {
    showToast("a", "b");
    const stack = document.getElementById("pty-toast-stack")!;
    expect(stack.children).toHaveLength(1);
    vi.advanceTimersByTime(6000);
    // The dismiss-fire happens at 6s; actual removal is animation-delayed.
    vi.advanceTimersByTime(200);
    expect(stack.children).toHaveLength(0);
  });

  it("durationMs: 0 means no auto-dismiss (stays until clicked)", () => {
    showToast("sticky", "stays", { durationMs: 0 });
    vi.advanceTimersByTime(60_000);
    const stack = document.getElementById("pty-toast-stack")!;
    expect(stack.children).toHaveLength(1);
  });

  it("clicking a toast dismisses it", () => {
    showToast("a", "b");
    const stack = document.getElementById("pty-toast-stack")!;
    const toast = stack.querySelector(".pty-toast") as HTMLElement;
    toast.click();
    vi.advanceTimersByTime(200); // animation duration
    expect(stack.children).toHaveLength(0);
  });

  it("multiple calls stack toasts", () => {
    showToast("a", "");
    showToast("b", "");
    showToast("c", "");
    const stack = document.getElementById("pty-toast-stack")!;
    expect(stack.children).toHaveLength(3);
    const titles = Array.from(
      stack.querySelectorAll(".pty-toast-title")
    ).map((el) => el.textContent);
    expect(titles).toEqual(["a", "b", "c"]);
  });
});
