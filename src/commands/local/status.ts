import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import * as net from "node:net";
import { log } from "../../log.ts";
import { defaultConfigDir, openSecretStore } from "../../storage/bootstrap.ts";
import { loadLabel } from "../../relay/config.ts";
import { loadClients } from "../../relay/clients.ts";
import {
  loadDaemonRuntime,
  buildExternalTokenUrl,
} from "../../relay/daemon-runtime.ts";
import sodium from "libsodium-wrappers-sumo";
import { ready, computeSecretHash, createToken } from "../../crypto/index.ts";
import { osc8Link } from "../../terminal-link.ts";

/**
 * `pty-relay local status [--show-token] [--json]` — show the
 * self-hosted daemon's local state. Symmetric with `server status`.
 *
 * Reads daemon config (keypair + pairing secret), the approval-token
 * list, the custom label if any, and the daemon.pid file to tell the
 * operator whether the daemon is running. The token URL is sensitive
 * (the fragment contains the pairing secret that auth the initial
 * connection), so it's only printed when `--show-token` is passed —
 * status is the kind of command that might end up in a bug report or
 * log, and we don't want the auth material scattered by accident.
 */

export interface LocalStatusOpts {
  json?: boolean;
  showToken?: boolean;
  configDir?: string;
  passphraseFile?: string;
  /** TCP port to probe when checking daemon liveness. Defaults to
   *  8099 (the documented `local start` default). Override when the
   *  operator started the daemon on a non-default port — `status`
   *  doesn't otherwise know which port was passed. */
  port?: number;
}

/** Default port used by `pty-relay local start` and probed by `status`
 *  when no port is supplied. Kept in sync with `cli.ts`'s usage text. */
const DEFAULT_RELAY_PORT = 8099;

export async function localStatusCommand(opts: LocalStatusOpts): Promise<void> {
  await ready();
  log("cli", "local status begin", { json: !!opts.json, showToken: !!opts.showToken });

  const dir = opts.configDir ?? defaultConfigDir();
  if (!fs.existsSync(dir)) {
    if (opts.json) {
      console.log(JSON.stringify({ initialized: false }));
    } else {
      console.log(`No config at ${dir}.`);
      console.log("Run `pty-relay init` then `pty-relay local start`.");
    }
    return;
  }

  const { store } = await openSecretStore(dir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });

  // config.json — daemon's long-lived keypair + pairing secret. If
  // it's absent, the self-hosted daemon has never been started.
  const configBytes = await store.load("config");
  if (!configBytes) {
    if (opts.json) {
      console.log(
        JSON.stringify({ initialized: false, configDir: dir, backend: store.backend })
      );
    } else {
      console.log(`Config dir: ${dir}`);
      console.log(`Backend:    ${store.backend}`);
      console.log("");
      console.log("No self-hosted daemon state in this config dir yet.");
      console.log("Run `pty-relay local start` to initialize.");
    }
    return;
  }

  // config.json uses base64_variants.ORIGINAL (padded `+/=` form) —
  // see src/crypto/keys.ts encodeConfig. Token URLs use URL-safe
  // no-padding, so we decode here with ORIGINAL and let createToken
  // re-encode for the URL.
  let config: {
    publicKey: Uint8Array;
    secret: Uint8Array;
  } | null = null;
  try {
    const parsed = JSON.parse(new TextDecoder().decode(configBytes));
    const publicKey = base64OriginalDecode(parsed.publicKey);
    const secret = base64OriginalDecode(parsed.secret);
    if (publicKey && secret) config = { publicKey, secret };
  } catch {
    // Fall through — corrupted config, surface as "unreadable"
  }

  const label = (await loadLabel(store)) || os.hostname();
  const probePort = opts.port ?? DEFAULT_RELAY_PORT;
  const daemonInfo = await probeDaemon(dir, probePort);
  const clientStats = await loadClientStats(store);
  const pubKeyB64 = config
    ? sodium.to_base64(config.publicKey, sodium.base64_variants.URLSAFE_NO_PADDING)
    : null;
  const secretHash = config ? computeSecretHash(config.secret) : null;

  if (opts.json) {
    const out: Record<string, unknown> = {
      initialized: true,
      configDir: dir,
      backend: store.backend,
      label,
      publicKey: pubKeyB64,
      secretHash, // safe to expose — hash of secret, not the secret itself
      daemon: daemonInfo,
      clients: clientStats,
    };
    if (opts.showToken && config) {
      // Token URL has the pairing secret in the fragment; gated on
      // --show-token like the text path below.
      out.tokenUrl = buildStatusTokenUrl(dir, config.publicKey, config.secret);
    }
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  console.log(`Self-hosted relay`);
  console.log(`  Config dir:  ${dir}`);
  console.log(`  Backend:     ${store.backend}`);
  console.log(`  Label:       ${label}`);
  if (pubKeyB64) {
    console.log(`  Public key:  ${pubKeyB64}`);
  } else {
    console.log(`  Public key:  (config unreadable — try \`pty-relay local reset\`)`);
  }
  if (secretHash) {
    console.log(`  Secret hash: ${secretHash.slice(0, 16)}…`);
  }
  if (daemonInfo.running) {
    console.log(`  Daemon:      running (pid ${daemonInfo.pid})`);
  } else if (daemonInfo.portListening) {
    // The PID file is stale or absent BUT something is listening on
    // the relay port. Common cause: the daemon was respawned by a
    // supervisor (`pty up`, systemd, etc.) without re-running
    // `pty-relay local start`, OR the previous daemon died hard before
    // cleanup. The pid we have (if any) is no longer authoritative.
    const staleNote = daemonInfo.pid !== null ? ` (recorded pid ${daemonInfo.pid} is stale)` : "";
    console.log(`  Daemon:      running on port ${probePort}${staleNote}`);
  } else if (daemonInfo.pid !== null) {
    console.log(`  Daemon:      stale pid ${daemonInfo.pid} (process not found, port ${probePort} not listening)`);
  } else {
    console.log(`  Daemon:      not running`);
  }
  console.log(
    `  Clients:     ${clientStats.active} active, ${clientStats.pending} pending, ${clientStats.revoked} revoked`
  );

  if (opts.showToken && config) {
    console.log("");
    // Printed last so it's trivially easy to copy. The URL prefers the
    // tailscale-advertised hostname when `--tailscale` was set at
    // start time (via daemon-runtime.json), and falls back to
    // localhost when no runtime record is on disk.
    console.log(`  Token URL:   ${osc8Link(buildStatusTokenUrl(dir, config.publicKey, config.secret))}`);
  } else if (!opts.showToken) {
    console.log("");
    console.log(`  (Run \`pty-relay local status --show-token\` to print the token URL.)`);
  }
}

interface DaemonProbe {
  /** PID read from `daemon.pid`, if the file exists and parses. */
  pid: number | null;
  /** True iff `process.kill(pid, 0)` succeeded — the pid points at a
   *  live process. Not authoritative on its own: a supervisor may have
   *  respawned the daemon after a hard crash without rewriting the
   *  pid file, leaving the file stale even though the daemon is up. */
  running: boolean;
  /** True iff a TCP connect to the relay port succeeded — something is
   *  bound there. Use this in combination with `running` to decide
   *  the real liveness state. (`running` true + `portListening` true
   *  = normal. `portListening` true + `running` false = supervised
   *  respawn / stale pid. Both false = down.) */
  portListening: boolean;
}

export async function probeDaemon(configDir: string, port: number): Promise<DaemonProbe> {
  const pid = readDaemonPid(configDir);
  const running = pid !== null && isProcessAlive(pid);
  const portListening = await isPortListening("127.0.0.1", port);
  return { pid, running, portListening };
}

function readDaemonPid(configDir: string): number | null {
  const pidPath = path.join(configDir, "daemon.pid");
  if (!fs.existsSync(pidPath)) return null;
  try {
    const raw = fs.readFileSync(pidPath, "utf-8").trim();
    const pid = parseInt(raw, 10);
    return isFinite(pid) ? pid : null;
  } catch {
    return null;
  }
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Best-effort TCP listen probe. Connects to `host:port` with a tight
 * timeout. Returns true iff the connection completes — anything
 * else (refused, no route, timeout, DNS fail) is treated as "no one
 * listening." We don't try to speak the relay protocol; the goal is
 * just "is something bound here that LOOKS like our daemon."
 *
 * Loopback only — we don't probe external interfaces because we
 * have no idea what's running on the operator's network.
 */
function isPortListening(host: string, port: number): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    let settled = false;
    const settle = (v: boolean): void => {
      if (settled) return;
      settled = true;
      resolve(v);
    };
    try {
      const socket = new net.Socket();
      const timeout = setTimeout(() => {
        try { socket.destroy(); } catch {}
        settle(false);
      }, 500);
      socket.once("connect", () => {
        clearTimeout(timeout);
        try { socket.end(); } catch {}
        settle(true);
      });
      socket.once("error", () => {
        clearTimeout(timeout);
        settle(false);
      });
      socket.connect(port, host);
    } catch {
      settle(false);
    }
  });
}

interface ClientStats {
  active: number;
  pending: number;
  revoked: number;
}

async function loadClientStats(
  store: import("../../storage/secret-store.ts").SecretStore
): Promise<ClientStats> {
  const stats: ClientStats = { active: 0, pending: 0, revoked: 0 };
  const data = await loadClients(store);
  if (!data) return stats;
  for (const t of data.tokens) {
    if (t.status === "active") stats.active++;
    else if (t.status === "pending") stats.pending++;
    else if (t.status === "revoked") stats.revoked++;
  }
  return stats;
}

function base64OriginalDecode(s: unknown): Uint8Array | null {
  if (typeof s !== "string") return null;
  try {
    return sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
  } catch {
    return null;
  }
}

function buildStatusTokenUrl(
  configDir: string,
  publicKey: Uint8Array,
  secret: Uint8Array,
): string {
  // Prefer the daemon-runtime.json record the running daemon wrote on
  // boot (tailscale hostname when --tailscale was set, real port,
  // etc.). Fall back to `localhost:8099` only when there's no record
  // — keeps `--show-token` useful on a never-started config and on
  // older daemons that haven't been restarted since this code shipped.
  const runtime = loadDaemonRuntime(configDir);
  if (runtime) {
    return buildExternalTokenUrl(runtime, publicKey, secret, createToken);
  }
  return createToken("localhost:8099", publicKey, secret);
}
