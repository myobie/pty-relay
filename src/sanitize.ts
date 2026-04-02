/**
 * Strip characters that would let a remote-supplied string forge output in
 * the operator's terminal when logged, or poison the approval TUI when a
 * label/user_agent/origin is rendered.
 *
 * Removes:
 *   • C0 controls (0x00–0x1F) except TAB (0x09)
 *   • DEL (0x7F)
 *   • C1 controls (0x80–0x9F)
 *   • Any lingering ESC-initiated sequence start bytes we might've missed
 *
 * Also truncates to `maxLen` code points so a client can't bloat logs by
 * sending a 1 MB "label".
 */
export function sanitizeRemoteString(input: unknown, maxLen = 256): string {
  if (typeof input !== "string") return "";

  let out = "";
  for (const ch of input) {
    const cp = ch.codePointAt(0) ?? 0;
    // Drop C0 (except TAB) and DEL
    if (cp < 0x20 && cp !== 0x09) continue;
    if (cp === 0x7f) continue;
    // Drop C1
    if (cp >= 0x80 && cp <= 0x9f) continue;
    out += ch;
    if (out.length >= maxLen) break;
  }
  return out;
}
