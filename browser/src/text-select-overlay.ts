import type { Terminal } from "@xterm/xterm";

/**
 * Mobile-friendly text-selection overlay for the terminal buffer.
 *
 * Why this exists: xterm.js renders text into a WebGL canvas, so
 * there's no DOM text for iOS Safari's native long-press selection
 * UI to attach to. Mouse-drag selection (xterm's built-in) works
 * with a desktop mouse, but iOS doesn't deliver mousemove during a
 * touch gesture — synthetic mouse events fire only on touchend —
 * so canvas selection is effectively impossible there.
 *
 * Workaround: at the moment the user taps "Select", grab the buffer
 * (visible viewport + scrollback) as plain text, drop it into a
 * scrollable `<pre>` rendered as a full-screen overlay, and let the
 * system selection UI do its job. iOS users get long-press handles +
 * the system Copy / Look Up / Share menu they already know. Desktop
 * users can drag-select with the mouse and Cmd/Ctrl+C as usual.
 *
 * The buffer snapshot is frozen at open time. Subsequent terminal
 * output doesn't re-render the overlay — that would interrupt an
 * in-progress selection. Closing and re-opening grabs a fresh
 * snapshot.
 */

export interface OverlayHandle {
  /** Remove the overlay from the DOM. Idempotent. */
  close(): void;
}

export function openTextSelectOverlay(term: Terminal): OverlayHandle {
  const text = extractBufferText(term);

  // Single instance — if one is already open, close it first so we
  // re-snapshot rather than stack two overlays.
  document.getElementById("text-select-overlay")?.remove();

  const overlay = document.createElement("div");
  overlay.id = "text-select-overlay";

  const header = document.createElement("div");
  header.className = "tso-header";

  const title = document.createElement("span");
  title.className = "tso-title";
  title.textContent = "Long-press to select";

  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.className = "tso-btn";
  copyBtn.textContent = "Copy All";

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "tso-btn tso-close";
  closeBtn.textContent = "Close";

  const pre = document.createElement("pre");
  pre.className = "tso-text";
  pre.textContent = text;

  copyBtn.addEventListener("click", async () => {
    // Prefer the Clipboard API (one-shot, no UI). Falls back to a
    // programmatic selection of the whole `<pre>` so the user can
    // hit Copy from the system menu — covers older iOS Safari /
    // non-secure contexts where clipboard.writeText is denied.
    try {
      await navigator.clipboard.writeText(text);
      flashCopied(copyBtn);
      return;
    } catch {
      // fall through to selection-based copy
    }
    selectAll(pre);
  });

  closeBtn.addEventListener("click", () => {
    overlay.remove();
  });

  // Tap the dim backdrop area outside the panel to close. The pre
  // and the header buttons are real targets and won't bubble back
  // to the overlay container thanks to event.target check.
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) overlay.remove();
  });

  header.appendChild(title);
  header.appendChild(copyBtn);
  header.appendChild(closeBtn);
  overlay.appendChild(header);
  overlay.appendChild(pre);
  document.body.appendChild(overlay);

  return {
    close() {
      overlay.remove();
    },
  };
}

/** Extract the full active buffer (scrollback + visible) as plain
 *  text, trimming trailing blank lines so the overlay doesn't show
 *  an empty tail of unused rows. */
function extractBufferText(term: Terminal): string {
  const buf = term.buffer.active;
  const len = buf.length;
  const lines: string[] = [];
  for (let i = 0; i < len; i++) {
    const line = buf.getLine(i);
    if (!line) continue;
    // translateToString(true) trims trailing whitespace per row.
    lines.push(line.translateToString(true));
  }
  while (lines.length > 0 && lines[lines.length - 1] === "") {
    lines.pop();
  }
  return lines.join("\n");
}

function selectAll(el: Node): void {
  const range = document.createRange();
  range.selectNodeContents(el);
  const sel = window.getSelection();
  if (!sel) return;
  sel.removeAllRanges();
  sel.addRange(range);
}

function flashCopied(btn: HTMLButtonElement): void {
  const prev = btn.textContent;
  btn.textContent = "Copied";
  btn.classList.add("tso-copied");
  setTimeout(() => {
    btn.textContent = prev;
    btn.classList.remove("tso-copied");
  }, 800);
}
