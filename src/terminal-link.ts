/**
 * OSC 8 hyperlink helper for terminal output.
 *
 * Wraps a URL in the OSC 8 escape sequence so terminals that support
 * the protocol (iTerm2, kitty, modern Gnome Terminal, WezTerm, recent
 * VS Code, recent Windows Terminal, recent macOS Terminal) render it
 * as a clickable link without exposing the raw escape codes when
 * printed to a non-TTY (a pipe, file redirect, CI log).
 *
 * If the destination differs from the visible label we emit the full
 * sequence; if not, we still emit it so terminals can detect the URL
 * boundary cleanly. When stdout isn't a TTY (NO_COLOR / piped /
 * redirected), we fall back to the plain URL.
 *
 * Spec: https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda
 */

/** Honour NO_COLOR (https://no-color.org) and FORCE_COLOR overrides
 *  the same way most CLI tooling does. NO_COLOR wins. */
function shouldEmitEscapes(): boolean {
  if (process.env.NO_COLOR) return false;
  if (process.env.FORCE_COLOR === "0") return false;
  if (process.env.FORCE_COLOR && process.env.FORCE_COLOR !== "0") return true;
  return !!process.stdout.isTTY;
}

/** Wrap `url` (and optional visible label) in an OSC 8 hyperlink.
 *  Returns the bare URL when the terminal isn't capable so log files
 *  and pipes stay clean. */
export function osc8Link(url: string, label?: string): string {
  const visible = label ?? url;
  if (!shouldEmitEscapes()) return visible === url ? url : `${visible} (${url})`;
  // ESC ] 8 ; ; URL ST  →  text  →  ESC ] 8 ; ; ST
  // ST is BEL (\x07) for compatibility with terminals that don't speak ESC \.
  const ST = "\x07";
  return `\x1b]8;;${url}${ST}${visible}\x1b]8;;${ST}`;
}
