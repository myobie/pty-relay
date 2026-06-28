/**
 * Tiny on-disk record of "what hostname/port the running daemon is
 * advertising externally." Written by `pty-relay local start` on
 * boot, read by `pty-relay local status --show-token` so the token
 * URL the user copies from `status` matches the one the daemon
 * printed on boot (Tailscale DNS name, LAN host, …) rather than the
 * conservative `localhost:8099` default.
 *
 * Why a separate file (vs. extending the existing encrypted config
 * store): this is *runtime* state, not a secret. It lives next to
 * `daemon.pid` and is cleared on clean shutdown. The contents are
 * safe to read without unlocking the keyring/passphrase, so
 * `local status` can render the URL even when the operator hasn't
 * provided the passphrase.
 *
 * No secrets in the file. The token URL fragment (`#pk.secret`) is
 * composed by `status` from the encrypted store + this file's
 * hostname/port. If this file is missing or unreadable, callers fall
 * back to `localhost:<default-port>`.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { log } from "../log.ts";

const FILE_NAME = "daemon-runtime.json";

/**
 * What the running daemon advertises as its external endpoint. None of
 * these fields are secret — `tailscale.hostname` and `bind`/`port` are
 * routing metadata the operator already chose at start time.
 */
export interface DaemonRuntime {
  /** TCP port the daemon's HTTP server is bound on. Always set. */
  port: number;
  /** Bind address (`127.0.0.1`, `0.0.0.0`, or an explicit interface).
   *  Used to decide whether to advertise localhost vs. a real IP. */
  bind: string;
  /** Set when `--tailscale` was passed AND tailscale serve registration
   *  succeeded. Otherwise undefined. */
  tailscale?: {
    /** Tailnet hostname, e.g. `silber.pancake-hake.ts.net`. */
    hostname: string;
    /** Almost always 443 for the operator's tailnet serve config; left
     *  explicit so future non-443 setups slot in. */
    port: number;
    /** Almost always `"https"`. */
    scheme: "https" | "http";
  };
  /** Unix-ms timestamp the file was written. Lets `status` warn on
   *  stale records if the file outlives its daemon. */
  startedAt: number;
}

export function runtimePath(configDir: string): string {
  return path.join(configDir, FILE_NAME);
}

/**
 * Write the runtime record. Best-effort: failures (read-only mount,
 * missing parent dir, etc.) are logged and swallowed — the daemon is
 * still healthy without this file.
 */
export function saveDaemonRuntime(
  configDir: string,
  runtime: Omit<DaemonRuntime, "startedAt">,
): void {
  try {
    const filePath = runtimePath(configDir);
    fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
    const payload: DaemonRuntime = { ...runtime, startedAt: Date.now() };
    fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), {
      mode: 0o600,
    });
    log("runtime", "wrote daemon-runtime.json", {
      port: runtime.port,
      tailscale: !!runtime.tailscale,
    });
  } catch (err) {
    log("runtime", "saveDaemonRuntime failed", {
      error: (err as Error)?.message,
    });
  }
}

/**
 * Read the runtime record. Returns `null` when the file is missing,
 * unreadable, or has an unexpected shape — callers fall back to a
 * conservative `localhost`-based URL in those cases.
 */
export function loadDaemonRuntime(configDir: string): DaemonRuntime | null {
  try {
    const filePath = runtimePath(configDir);
    const raw = fs.readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object") return null;
    const obj = parsed as Record<string, unknown>;
    if (typeof obj.port !== "number" || typeof obj.bind !== "string") {
      return null;
    }
    const runtime: DaemonRuntime = {
      port: obj.port,
      bind: obj.bind,
      startedAt:
        typeof obj.startedAt === "number" ? obj.startedAt : Date.now(),
    };
    if (obj.tailscale && typeof obj.tailscale === "object") {
      const ts = obj.tailscale as Record<string, unknown>;
      if (
        typeof ts.hostname === "string" &&
        typeof ts.port === "number" &&
        (ts.scheme === "http" || ts.scheme === "https")
      ) {
        runtime.tailscale = {
          hostname: ts.hostname,
          port: ts.port,
          scheme: ts.scheme,
        };
      }
    }
    return runtime;
  } catch {
    return null;
  }
}

/**
 * Delete the runtime record. Called by the daemon's clean-shutdown
 * hook (alongside the daemon.pid cleanup) so a subsequent
 * `local status` doesn't claim the dead daemon was still up.
 *
 * Best-effort: ENOENT and similar failures are swallowed.
 */
export function clearDaemonRuntime(configDir: string): void {
  try {
    fs.unlinkSync(runtimePath(configDir));
  } catch {
    // ignore
  }
}

/**
 * Compose the external token URL from a runtime record + the public
 * key/secret pulled from the encrypted store. Prefers tailscale when
 * available, falls back to `http://localhost:<port>`.
 *
 * The return value is suitable for `--show-token` output and for the
 * `tokenUrl` field of `--json` status.
 */
export function buildExternalTokenUrl(
  runtime: DaemonRuntime,
  publicKey: Uint8Array,
  secret: Uint8Array,
  createToken: (
    host: string,
    pk: Uint8Array,
    secret: Uint8Array,
    session?: string,
  ) => string,
): string {
  if (runtime.tailscale) {
    const ts = runtime.tailscale;
    // `tailscale serve --https=443 …` is by far the common case;
    // omit the port from the URL when it matches the scheme default.
    const isDefault =
      (ts.scheme === "https" && ts.port === 443) ||
      (ts.scheme === "http" && ts.port === 80);
    const host = isDefault ? ts.hostname : `${ts.hostname}:${ts.port}`;
    return createToken(host, publicKey, secret);
  }

  // Non-tailscale: the daemon's own port + a localhost host. We could
  // try to detect a LAN IP when bind === "0.0.0.0" but the operator
  // already saw the right URL on boot — falling back to localhost is
  // the safe option for `--show-token` (it Just Works on the same
  // machine; for cross-machine the operator uses the boot output).
  return createToken(`localhost:${runtime.port}`, publicKey, secret);
}
