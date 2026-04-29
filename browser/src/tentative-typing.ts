/**
 * Experimental "tentative typing" UI: render the keystroke locally
 * with dim styling before the echo arrives, so the user sees their
 * input immediately. This is NOT predictive echo (mosh-style) — we
 * don't claim the byte is on screen, we just render it visibly-
 * unconfirmed and let the daemon's echo overwrite when it arrives.
 *
 * Honest about state:
 *   - tentative chars use SGR 2 (dim) so they're visually distinct
 *     from confirmed echoes
 *   - if no echo arrives within TENTATIVE_TIMEOUT_MS (e.g. vim
 *     command-mode 'a'), the tentative is erased — no false text
 *     left on screen
 *
 * Limits (call out so we know what we shipped):
 *   1. Only single printable ASCII keystrokes get tentative-rendered.
 *      Enter / arrows / Ctrl+anything are forwarded normally without
 *      a tentative ghost.
 *   2. Multi-char-in-flight isn't handled cleanly: each tentative
 *      writes-and-backs-up, clobbering its predecessor. Fast typing
 *      (faster than echo RTT) shows only the latest char in dim.
 *   3. Tentatives don't survive scrolls / large redraws. If the
 *      daemon emits a scroll-causing frame between our tentative
 *      write and the echo, the tentative is gone. Acceptable —
 *      the echo would have overwritten it anyway.
 *
 * Off by default. Enable via:
 *   localStorage.setItem('pty-relay:tentative', '1')
 * then hard-refresh.
 */

/** Minimal subset of xterm.js Terminal that we touch. Mirrors the
 *  pattern used by latency-stats.ts so tests can fake without pulling
 *  the full Terminal type. */
export interface TermLike {
  write(data: string): void;
  onData(cb: (data: string) => void): { dispose(): void };
  onWriteParsed(cb: () => void): { dispose(): void };
}

export interface TentativeController {
  destroy(): void;
}

const TENTATIVE_TIMEOUT_MS = 200;

const SGR_DIM = "\x1b[2m";
const SGR_RESET = "\x1b[22m";
const CURSOR_LEFT = "\x1b[D";

/** Is this onData payload a single printable ASCII char that we
 *  should tentative-render? Filters out everything else (Enter,
 *  arrows, Ctrl+anything, paste). */
function isTentativeable(data: string): boolean {
  if (data.length !== 1) return false;
  const code = data.charCodeAt(0);
  return code >= 0x20 && code <= 0x7e;
}

export function startTentativeTyping(term: TermLike): TentativeController {
  // We track only the most recent tentative character. If a second
  // char is typed before the first echoes, the first's eraser is
  // canceled and the second supersedes it. This is a deliberate
  // simplification — multi-char queues add a lot of code for cases
  // that only matter when typing speed exceeds echo RTT.
  let activeTimer: ReturnType<typeof setTimeout> | null = null;
  let activeChar: string | null = null;

  const onDataDisposer = term.onData((data) => {
    if (!isTentativeable(data)) return;
    // Cancel any pending erase — a new keystroke supersedes the prior
    // tentative. The prior char's actual echo will still arrive and
    // be written normally; ours just doesn't get explicitly erased.
    if (activeTimer) clearTimeout(activeTimer);
    activeChar = data;
    // Render the dim char + cursor-back so the daemon's echo lands
    // exactly on top.
    term.write(SGR_DIM + data + SGR_RESET + CURSOR_LEFT);
    // Eraser: if no echo writes over this within the timeout, paint
    // a space over our tentative so we don't leave a ghost char on
    // screen for vim-style no-echo keystrokes.
    activeTimer = setTimeout(() => {
      activeTimer = null;
      activeChar = null;
      term.write(" " + CURSOR_LEFT);
    }, TENTATIVE_TIMEOUT_MS);
  });

  // Any incoming write from the daemon means an echo (or something
  // else) is being parsed. The simplest model: assume our tentative
  // is now overwritten. Cancel the eraser. We can't tell if the echo
  // actually wrote at our cursor position or somewhere else; trust
  // the FIFO-ish ordering and move on. If the assumption is wrong,
  // the worst case is a leftover dim char that the next echo or
  // typed key will paint over.
  const onWriteParsedDisposer = term.onWriteParsed(() => {
    if (activeTimer) {
      clearTimeout(activeTimer);
      activeTimer = null;
      activeChar = null;
    }
  });

  return {
    destroy(): void {
      onDataDisposer.dispose();
      onWriteParsedDisposer.dispose();
      if (activeTimer) {
        clearTimeout(activeTimer);
        activeTimer = null;
      }
    },
  };
}

/** Read the localStorage opt-in flag. Default off. */
export function tentativeEnabled(): boolean {
  try {
    return localStorage.getItem("pty-relay:tentative") === "1";
  } catch {
    return false;
  }
}
