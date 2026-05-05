/**
 * Persistent terminal font-size control.
 *
 * Saves the user's chosen pixel size to localStorage so it survives
 * reloads, and applies it on attach. Bounded to a sane range so a
 * stuck "+" key (or a recovered too-small / too-large persisted
 * value) can't render the terminal unusable.
 *
 * The terminal *must* be re-fitted after a font-size change — the
 * cell metrics are recomputed lazily by xterm, and FitAddon reads
 * cell metrics to size the terminal. Without a fit, you end up with
 * stale rows/cols and a half-painted screen until the next resize.
 */

import type { Terminal } from "@xterm/xterm";
import type { FitAddon } from "@xterm/addon-fit";

const STORAGE_KEY = "pty-relay:font-size";
const DEFAULT_SIZE = 14;
const MIN_SIZE = 10;
const MAX_SIZE = 32;
const STEP = 1;

function clamp(n: number): number {
  if (!Number.isFinite(n)) return DEFAULT_SIZE;
  if (n < MIN_SIZE) return MIN_SIZE;
  if (n > MAX_SIZE) return MAX_SIZE;
  return Math.round(n);
}

/** Read the saved size, falling back to the default. Bad / out-of-
 *  range values are silently clamped — we never want a saved value
 *  to lock someone out of using the app. */
export function loadFontSize(): number {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_SIZE;
    const n = parseInt(raw, 10);
    return clamp(n);
  } catch {
    return DEFAULT_SIZE;
  }
}

export function saveFontSize(size: number): void {
  try {
    localStorage.setItem(STORAGE_KEY, String(clamp(size)));
  } catch {
    // localStorage can throw in private mode / when full. Best-
    // effort persistence; the in-memory size still applies for the
    // current session.
  }
}

/** Apply a size to xterm and re-fit. Caller passes the FitAddon (it's
 *  the one already attached to the terminal). The fit is wrapped in
 *  a try/catch because xterm throws if a measure happens before the
 *  canvas has a non-zero size — fine, the next resize event will
 *  catch up. */
export function applyFontSize(
  term: Terminal,
  fit: FitAddon,
  size: number
): void {
  const next = clamp(size);
  term.options.fontSize = next;
  try {
    fit.fit();
  } catch {
    // Ignore — caller's normal resize path will fix it on the next
    // observed dimension change.
  }
}

export interface FontSizeController {
  current(): number;
  bump(delta: number): void;
  reset(): void;
}

/** Wire +/- handlers around a terminal that's already mounted.
 *  Returns a controller exposing the current size + bump/reset so
 *  the caller can rebind the same controller after teardown. */
export function createFontSizeController(
  term: Terminal,
  fit: FitAddon,
  initial: number = loadFontSize()
): FontSizeController {
  let size = clamp(initial);
  // Apply once up-front so the saved value takes effect on attach,
  // not just after the user bumps.
  applyFontSize(term, fit, size);

  function set(next: number): void {
    const clamped = clamp(next);
    if (clamped === size) return;
    size = clamped;
    applyFontSize(term, fit, size);
    saveFontSize(size);
  }

  return {
    current: () => size,
    bump: (delta) => set(size + delta * STEP),
    reset: () => set(DEFAULT_SIZE),
  };
}

export const FONT_SIZE_LIMITS = { min: MIN_SIZE, max: MAX_SIZE, default: DEFAULT_SIZE };
