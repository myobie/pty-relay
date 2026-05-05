/**
 * Mosh-style local input prediction for the web terminal (v1).
 *
 * The user-perceived latency in the web UI is dominated by the
 * round-trip between the local browser and the remote daemon. For
 * shell-style typing where the program echoes back what the user
 * typed, we can hide that latency by writing the predicted character
 * to the terminal IMMEDIATELY and then reconciling when the actual
 * server output arrives.
 *
 * The model in v1:
 *
 *   - On user input, every printable ASCII char is "predicted":
 *     written into xterm right away AND sent to the server as
 *     usual. A queue tracks each prediction (row, col, char).
 *
 *   - On server output, we walk the bytes and try to match them
 *     against the head of the queue. Each matching byte is
 *     CONSUMED — the prediction is already on screen, so writing
 *     the byte to xterm again would double-print. A non-match
 *     triggers a rollback: erase from the oldest prediction's
 *     position to the current cursor, then write the rest of the
 *     server's bytes verbatim from there.
 *
 *   - In alternate-screen mode (vim, htop, anything full-screen),
 *     prediction is unsafe — keystrokes don't echo, and the cursor
 *     is driven programmatically. We disable prediction completely
 *     in that mode and pass user input through untouched.
 *
 * Out of scope for v1 (per issue #12):
 *   - Cursor-motion prediction (arrow keys, deletes, etc.)
 *   - Multi-byte / wide-char predictions
 *   - Mosh's full SSP wire protocol
 *
 * The module is opt-in via the daemon's `--mosh` flag, surfaced to
 * the browser through `<meta name="pty-relay-config">`. Default off.
 * Direct TS callers can pass `enabled: true` in PredictorOptions to
 * bypass the daemon-flag plumbing.
 */

import type { Terminal } from "@xterm/xterm";

/** Cap on pending predictions — beyond this we stop predicting and
 *  let user input pass through. Without this, a server that's
 *  silent (password prompt, REPL hang) would let the queue grow
 *  unbounded as the user keeps typing. */
const MAX_QUEUE = 32;

interface Prediction {
  row: number;
  col: number;
  char: string;
}

export interface InputPredictor {
  /** Hook user input. The predictor writes the predicted char to
   *  the terminal and forwards `data` verbatim to the server via
   *  the supplied `sendToServer` callback. */
  onUserData(data: string): void;
  /** Hook server output BEFORE term.write. The predictor reconciles
   *  the queue and writes only the bytes that should reach the
   *  terminal (mismatches roll the predictions back; matches are
   *  silently consumed). */
  onServerData(data: string | Uint8Array): void;
  /** Toggle prediction at runtime. Disabling rolls back any
   *  outstanding predictions immediately. */
  setEnabled(enabled: boolean): void;
  /** Outstanding prediction count — exposed for UI/diagnostics. */
  pendingCount(): number;
  destroy(): void;
}

export interface PredictorOptions {
  term: Terminal;
  /** Forward user input to the server. Caller wires this to the
   *  same path that previously handled term.onData. */
  sendToServer: (data: string) => void;
  /** Default false. setEnabled(true) at runtime to turn on. */
  enabled?: boolean;
}

export function createInputPredictor(opts: PredictorOptions): InputPredictor {
  const { term, sendToServer } = opts;
  let enabled = !!opts.enabled;
  const queue: Prediction[] = [];

  function isAltScreen(): boolean {
    // xterm's "alternate" buffer is the typical full-screen TUI
    // mode (vim, htop, less +F). type === "normal" is the scrollback
    // buffer where echo-style typing happens. If we ever encounter
    // a third value we treat it conservatively as "don't predict."
    try {
      return term.buffer.active.type !== "normal";
    } catch {
      return true;
    }
  }

  /** Erase predictions from the screen by moving cursor to the
   *  oldest prediction's position and clearing to end of line.
   *  Multi-line predictions aren't fully restored — we only span
   *  the first prediction's row. v1 trade-off: typing rarely
   *  wraps mid-input, and the next server frame usually redraws
   *  anyway. */
  function rollback(): void {
    if (queue.length === 0) return;
    const first = queue[0];
    // CSI Ps;Ps H — move cursor to row;col (1-indexed)
    // CSI K       — erase from cursor to end of line
    term.write(`\x1b[${first.row + 1};${first.col + 1}H\x1b[K`);
    queue.length = 0;
  }

  function onUserData(data: string): void {
    if (!enabled || isAltScreen()) {
      sendToServer(data);
      return;
    }
    if (queue.length >= MAX_QUEUE) {
      // Don't add more predictions; just forward.
      sendToServer(data);
      return;
    }

    // If the batch contains any control byte (ESC sequences for arrow
    // keys, backspace, Enter, Ctrl+anything, etc.), don't predict any
    // of it — the whole batch is "not a plain typed character." This
    // avoids predicting the `[A` portion of `\x1b[A` (arrow up).
    if (!/^[\x20-\x7e]+$/.test(data)) {
      sendToServer(data);
      return;
    }

    for (const c of data) {
      if (queue.length >= MAX_QUEUE) break;
      const col = term.buffer.active.cursorX;
      const row = term.buffer.active.cursorY;
      queue.push({ row, col, char: c });
      term.write(c);
    }

    sendToServer(data);
  }

  function byteAt(data: string | Uint8Array, i: number): number {
    return typeof data === "string" ? data.charCodeAt(i) : data[i];
  }

  function sliceFrom(data: string | Uint8Array, i: number): string | Uint8Array {
    return typeof data === "string" ? data.slice(i) : data.subarray(i);
  }

  function onServerData(data: string | Uint8Array): void {
    if (!enabled || queue.length === 0) {
      term.write(data);
      return;
    }

    const len = data.length;
    let i = 0;
    while (i < len && queue.length > 0) {
      const head = queue[0];
      if (byteAt(data, i) === head.char.charCodeAt(0)) {
        // Predicted byte arrived intact — already on screen,
        // silently consume.
        queue.shift();
        i++;
      } else {
        // Mismatch — wipe pending predictions, then write the
        // remainder of the server bytes from the rollback point.
        rollback();
        term.write(sliceFrom(data, i));
        return;
      }
    }

    if (i < len) {
      term.write(sliceFrom(data, i));
    }
  }

  return {
    onUserData,
    onServerData,
    setEnabled(e) {
      if (!e && enabled) rollback();
      enabled = e;
    },
    pendingCount: () => queue.length,
    destroy() {
      rollback();
      enabled = false;
    },
  };
}

