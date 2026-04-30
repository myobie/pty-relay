/**
 * Minimal in-page toast stack. Used as the fallback when system
 * notifications aren't available (Android Chrome, iOS Safari without
 * an installed PWA, denied browser permission, etc.).
 *
 * One stack mounted to <body>, toasts appended top-down, each
 * auto-dismissed after TOAST_DURATION_MS or by click. Pure DOM —
 * testable in jsdom/happy-dom without a renderer.
 */

const STACK_ID = "pty-toast-stack";
const TOAST_DURATION_MS = 6000;
const ANIM_MS = 200;

function ensureStack(): HTMLElement {
  let stack = document.getElementById(STACK_ID);
  if (!stack) {
    stack = document.createElement("div");
    stack.id = STACK_ID;
    document.body.appendChild(stack);
  }
  return stack;
}

export interface ToastOptions {
  /** Override the default 6 second auto-dismiss. Pass 0 to keep
   *  the toast until the user clicks it. */
  durationMs?: number;
}

/** Show a toast in the bottom-right stack. Title bold, body below.
 *  Click to dismiss. Empty body is fine — the toast will just
 *  show the title. */
export function showToast(
  title: string,
  body: string,
  opts: ToastOptions = {}
): void {
  const stack = ensureStack();
  const el = document.createElement("div");
  el.className = "pty-toast";

  const titleEl = document.createElement("div");
  titleEl.className = "pty-toast-title";
  titleEl.textContent = title;
  el.appendChild(titleEl);

  if (body) {
    const bodyEl = document.createElement("div");
    bodyEl.className = "pty-toast-body";
    bodyEl.textContent = body;
    el.appendChild(bodyEl);
  }

  let dismissed = false;
  function dismiss(): void {
    if (dismissed) return;
    dismissed = true;
    el.classList.add("pty-toast-dismissing");
    setTimeout(() => el.remove(), ANIM_MS);
  }
  el.addEventListener("click", dismiss);

  const duration = opts.durationMs ?? TOAST_DURATION_MS;
  if (duration > 0) {
    setTimeout(dismiss, duration);
  }

  stack.appendChild(el);
}

/** Test helper: clear all live toasts immediately (skip the
 *  dismiss animation). Not exported as a public API; only used
 *  by happy-dom tests to reset state between cases. */
export function _clearAllToastsForTesting(): void {
  const stack = document.getElementById(STACK_ID);
  if (stack) stack.replaceChildren();
}
