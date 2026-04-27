/**
 * Verbose logger for pty-relay. Gated behind the global `--verbose`
 * flag (set via setVerbose() from cli.ts) or either of the env vars
 * PTY_RELAY_VERBOSE or PTY_RELAY_DEBUG (the latter kept for back-compat
 * with ad-hoc debugging from before verbose mode existed).
 *
 * All output goes to stderr so stdout stays clean for JSON consumers
 * and pipe semantics. Nothing here mutates stdout.
 *
 * Categories convention — short ascii tags in square brackets:
 *
 *   [cli]          top-level command dispatch
 *   [store]        secret store open/load/save
 *   [account]      PublicAccount load/save + per-key summary
 *   [hosts]        known_hosts load/save/merge
 *   [http]         PublicApi requests (method + path + status + ms)
 *   [ws-primary]   primary daemon control socket
 *   [ws-pair]      per-client or client_pair sockets
 *   [ws-oneshot]   one-shot sendOverTunnel (ls / peek / send / tag / events)
 *   [noise]        handshake begin/complete, Transport setup
 *   [sign]         v2 canonical payload construction
 *   [totp]         TOTP code generation
 *   [bridge]       session bridge attach/detach
 *   [serve]        self-hosted relay server
 *   [pairing]      self-hosted PairingRegistry
 *   [terminal]     interactive terminal frame handling
 *   [events]       events-client lifecycle
 *   [reset]        reset / init lifecycle
 *   [exit]         on-exit diagnostics (active handles, etc.)
 *
 * Timing convention — every "interesting" async op logs a start + end
 * with an elapsed milliseconds count. Use `timed()` for wrapping a
 * promise; use `now()` + `sinceMs()` for manual start/stop.
 */

import { performance } from "node:perf_hooks";

let verboseEnabled = false;

/** Called once from cli.ts after --verbose is parsed. Also picks up
 *  env-var opt-in so libraries / tests can enable verbose without
 *  going through the CLI. */
export function initVerbose(flagSet: boolean): void {
  verboseEnabled =
    flagSet ||
    !!process.env.PTY_RELAY_VERBOSE ||
    !!process.env.PTY_RELAY_DEBUG;
}

export function isVerbose(): boolean {
  return verboseEnabled;
}

/** High-resolution monotonic timestamp in milliseconds. */
export function now(): number {
  return performance.now();
}

/** Elapsed ms since `start`, rounded to 0.1 ms. */
export function sinceMs(start: number): number {
  return Math.round((performance.now() - start) * 10) / 10;
}

/** Timestamp prefix: HH:MM:SS.mmm local-time for quick eyeballing. */
function ts(): string {
  const d = new Date();
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

/** Format a data object as `key=value key=value …`. Skips undefined
 *  values. Quotes strings with whitespace or `=`. Truncates very long
 *  strings to keep log lines one-terminal-line-ish. */
function formatData(data?: Record<string, unknown>): string {
  if (!data) return "";
  const parts: string[] = [];
  for (const [k, v] of Object.entries(data)) {
    if (v === undefined) continue;
    let s: string;
    if (typeof v === "string") {
      const trimmed = v.length > 160 ? `${v.slice(0, 160)}…` : v;
      s = /[\s=]/.test(trimmed) ? JSON.stringify(trimmed) : trimmed;
    } else if (v instanceof Error) {
      s = JSON.stringify(v.message);
    } else {
      try { s = JSON.stringify(v); } catch { s = String(v); }
      if (s.length > 160) s = `${s.slice(0, 160)}…`;
    }
    parts.push(`${k}=${s}`);
  }
  return parts.length > 0 ? ` ${parts.join(" ")}` : "";
}

/** Emit a verbose line to stderr. No-op when verbose mode is off. */
export function log(
  category: string,
  message: string,
  data?: Record<string, unknown>
): void {
  if (!verboseEnabled) return;
  process.stderr.write(`[${ts()}] [${category}] ${message}${formatData(data)}\n`);
}

/** Wrap an async (or sync) operation; log begin + end with elapsed ms.
 *  On throw, logs the error + elapsed and re-throws. */
export async function timed<T>(
  category: string,
  label: string,
  fn: () => Promise<T> | T,
  extra?: Record<string, unknown>
): Promise<T> {
  if (!verboseEnabled) return await fn();
  const start = now();
  log(category, `${label} …`, extra);
  try {
    const result = await fn();
    log(category, `${label} ok`, { ms: sinceMs(start) });
    return result;
  } catch (err: any) {
    log(category, `${label} err`, {
      ms: sinceMs(start),
      error: err?.message ?? String(err),
    });
    throw err;
  }
}

/** Redact auth-triple params from a URL query string so verbose URLs
 *  don't leak `public_key` / `payload` / `sig`. Preserves the path +
 *  non-auth query for quick debugging. */
export function redactAuthQuery(url: string): string {
  try {
    const u = new URL(url);
    for (const k of ["public_key", "payload", "sig", "totp_code", "secret_hash"]) {
      if (u.searchParams.has(k)) u.searchParams.set(k, "REDACTED");
    }
    return u.toString();
  } catch {
    return url;
  }
}

/** One-time hook: when the process is about to exit in verbose mode,
 *  print what's keeping the event loop alive (active handles +
 *  resources). Call once from cli.ts after the global --verbose
 *  flag is set. No-op when verbose is off. */
export function installExitDiagnostics(): void {
  if (!verboseEnabled) return;
  const startTs = now();
  process.on("beforeExit", () => {
    const resources = process.getActiveResourcesInfo?.() ?? [];
    // @ts-expect-error — private API, but the only way to see handle types
    const handles: Array<unknown> = process._getActiveHandles?.() ?? [];
    // @ts-expect-error — same
    const requests: Array<unknown> = process._getActiveRequests?.() ?? [];
    log("exit", "beforeExit", {
      uptimeMs: sinceMs(startTs),
      resources: resources.length > 0 ? resources.join(",") : "(none)",
      handles: handles.length,
      handleTypes:
        handles.length > 0
          ? handles.map((h) => (h as any)?.constructor?.name ?? "?").join(",")
          : "(none)",
      requests: requests.length,
    });
  });
  process.on("exit", (code) => {
    log("exit", "exit", { code, uptimeMs: sinceMs(startTs) });
  });
}
