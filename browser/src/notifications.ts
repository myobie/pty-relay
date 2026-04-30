/**
 * Terminal -> browser notification bridge.
 *
 * Listens for OSC 9 (iTerm2-style: `\e]9;<message>\a`) and OSC 777
 * (urxvt-style: `\e]777;notify;<title>;<body>\a`) emitted by remote
 * programs (build tools, CI watchers, claude code itself, etc.) and
 * routes each one to:
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
      new Notification(title, { body });
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
      osc777.dispose();
    },
  };
}

/** Test hook: reset cooldown + permission cache so each test starts
 *  clean. Not exported as a public API. */
export function _resetForTesting(): void {
  lastNotificationAt = 0;
  permissionEnsured = false;
}
