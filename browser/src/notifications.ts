/**
 * Terminal -> browser notification bridge.
 *
 * Listens for several common notification escape-sequence dialects:
 *
 *   OSC 9   — iTerm2-style: `\e]9;<message>\a`
 *   OSC 99  — Kitty's protocol, supports chunked title/body keyed by
 *             id, base64-encoded payloads, etc. This is what Claude
 *             Code and Kitty-aware tools emit.
 *   OSC 777 — urxvt-style: `\e]777;notify;<title>;<body>\a`
 *
 * Each one routes to:
 *   1. `new Notification()` if the browser supports it AND the user
 *      has granted permission, OR
 *   2. `showToast()` as a graceful fallback (Android Chrome and iOS
 *      Safari throw on the constructor; muted-system-notifications
 *      similarly fail; the toast covers all of that).
 *
 * In-app cooldown caps notifications at 1/sec/session so a misbehaving
 * program can't drown the user.
 */

import type { Terminal } from "@xterm/xterm";
import { showToast } from "./toast.ts";

const COOLDOWN_MS = 1000;

let lastNotificationAt = 0;
let permissionEnsured = false;

async function ensurePermission(): Promise<boolean> {
  if (permissionEnsured) return Notification.permission === "granted";
  if (typeof Notification === "undefined") return false;
  if (Notification.permission === "denied") {
    permissionEnsured = true;
    return false;
  }
  if (Notification.permission === "granted") {
    permissionEnsured = true;
    return true;
  }
  // Request — only fires once per page (browsers remember the choice).
  try {
    const result = await Notification.requestPermission();
    permissionEnsured = true;
    return result === "granted";
  } catch {
    return false;
  }
}

/** Display a notification. Tries the system path first, falls back
 *  to an in-page toast. Returns the channel that handled it (or
 *  "throttled" if the cooldown blocked it). */
export async function notify(
  title: string,
  body: string
): Promise<"system" | "toast" | "throttled"> {
  const now = Date.now();
  if (now - lastNotificationAt < COOLDOWN_MS) return "throttled";
  lastNotificationAt = now;

  const granted = await ensurePermission();
  if (granted) {
    try {
      const n = new Notification(title, { body });
      // Tapping/clicking the notification focuses our tab — the
      // click counts as a user gesture so window.focus() is allowed
      // even when the tab is in the background. Close after focusing
      // so the notification doesn't linger; user already saw it.
      n.onclick = () => {
        window.focus();
        n.close();
      };
      return "system";
    } catch {
      // Constructor throws on Android Chrome / iOS — fall through.
    }
  }
  showToast(title, body);
  return "toast";
}

/** Minimal subset of xterm's Terminal we need (parser + osc handler). */
export interface OscTerminalLike {
  parser: {
    registerOscHandler(
      ident: number,
      cb: (data: string) => boolean
    ): { dispose(): void };
  };
}

/** Register OSC 9 + OSC 777 handlers on the given terminal. Returns
 *  a disposer that can be called to remove both. The fallbackTitle()
 *  is invoked at notification time to capture the latest session
 *  name / document title (which itself updates from OSC 0/2). */
export function registerOscHandlers(
  term: OscTerminalLike,
  fallbackTitle: () => string
): { dispose(): void } {
  // OSC 9: just a body. iTerm2's convention. Use the current
  // session/document title for the notification title.
  const osc9 = term.parser.registerOscHandler(9, (data: string) => {
    notify(fallbackTitle() || "Notification", data);
    return true;
  });

  // OSC 99 — Kitty's notification protocol. Format:
  //   ESC ] 99 ; <metadata> ; <payload> ESC \    (or BEL terminator)
  // Metadata is a colon-separated list of key=value pairs:
  //   i=<id>   — identifier; chunks with the same id combine into
  //              one notification
  //   p=<type> — payload kind: "title" / "body" / "icon" / "close"
  //              / etc. Default is "body".
  //   d=0|1    — done flag. d=0 means more chunks coming; d=1 (or
  //              absent for title/body) means this is the last chunk
  //              and we should display now.
  //   e=0|1    — encoding. 0 = utf8 plain (default), 1 = base64.
  //
  // Most of Kitty's protocol is opt-in fanciness (icons, buttons,
  // urgency hints, etc.). The subset that matters for "Claude Code
  // wants to tell me a thing" is:
  //   - empty metadata + payload = anonymous single-chunk notification
  //   - p=title and p=body chunks with shared id
  // We handle those; less common payload types (icon/alive/query/
  // close/etc) are silently ignored for now — no exceptions, no log
  // noise. Spec: https://sw.kovidgoyal.net/kitty/desktop-notifications/
  const oscPending = new Map<string, { title: string; body: string }>();
  const osc99 = term.parser.registerOscHandler(99, (data: string) => {
    const firstSemi = data.indexOf(";");
    if (firstSemi === -1) {
      // No metadata separator at all — treat the whole thing as a
      // body for an anonymous, complete notification.
      notify(fallbackTitle() || "Notification", data);
      return true;
    }
    const meta = data.slice(0, firstSemi);
    const payload = data.slice(firstSemi + 1);

    const fields = new Map<string, string>();
    if (meta) {
      for (const pair of meta.split(":")) {
        const eq = pair.indexOf("=");
        if (eq === -1) continue;
        fields.set(pair.slice(0, eq), pair.slice(eq + 1));
      }
    }

    const ptype = fields.get("p") ?? "body";
    // Skip payload types we don't render. icon / alive / close /
    // query / buttons all live here. Not having them is graceful
    // degradation — Kitty would render fancier; we render the body
    // (when it eventually arrives) plain.
    if (ptype !== "title" && ptype !== "body") {
      return true;
    }

    // Decode if base64. Bad base64 is treated as plain — no point
    // failing visibly when a notification is already best-effort.
    const encoding = fields.get("e") ?? "0";
    let decoded = payload;
    if (encoding === "1") {
      try {
        decoded = atob(payload);
      } catch {
        // Use as-is.
      }
    }

    // Default-id for chunks that don't supply one. Each gets its own
    // anonymous record so they don't accidentally combine across
    // unrelated notifications.
    const id = fields.get("i") ?? `__anon_${Math.random()}`;
    // Per spec: d defaults to 1 (single chunk done) for title/body.
    // Only d=0 explicitly means "more coming."
    const done = fields.get("d") !== "0";

    let pending = oscPending.get(id);
    if (!pending) {
      pending = { title: "", body: "" };
      oscPending.set(id, pending);
    }
    if (ptype === "title") pending.title += decoded;
    else pending.body += decoded;

    if (done) {
      oscPending.delete(id);
      const title = pending.title || fallbackTitle() || "Notification";
      notify(title, pending.body);
    }
    return true;
  });

  // OSC 777 — urxvt-style. Format: `notify;<title>;<body>`.
  // Anything else under 777 isn't ours; return false to let other
  // handlers (or the default) take it.
  const osc777 = term.parser.registerOscHandler(777, (data: string) => {
    const semi = data.indexOf(";");
    if (semi === -1) return false;
    const subtype = data.slice(0, semi);
    if (subtype !== "notify") return false;
    const rest = data.slice(semi + 1);
    const semi2 = rest.indexOf(";");
    if (semi2 === -1) {
      // No body — title only.
      notify(rest || fallbackTitle() || "Notification", "");
    } else {
      const title = rest.slice(0, semi2);
      const body = rest.slice(semi2 + 1);
      notify(title || fallbackTitle() || "Notification", body);
    }
    return true;
  });

  return {
    dispose() {
      osc9.dispose();
      osc99.dispose();
      osc777.dispose();
      oscPending.clear();
    },
  };
}

/** Test hook: reset cooldown + permission cache so each test starts
 *  clean. Not exported as a public API. */
export function _resetForTesting(): void {
  lastNotificationAt = 0;
  permissionEnsured = false;
}
