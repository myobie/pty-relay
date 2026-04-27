import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { log } from "../../log.ts";
import { defaultConfigDir, openSecretStore } from "../../storage/bootstrap.ts";
import { loadLabel } from "../../relay/config.ts";
import { loadClients } from "../../relay/clients.ts";
import sodium from "libsodium-wrappers-sumo";
import { ready, computeSecretHash, createToken } from "../../crypto/index.ts";

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
}

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
  const daemonInfo = probeDaemon(dir);
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
      out.tokenUrl = buildLocalhostTokenUrl(config.publicKey, config.secret);
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
  } else if (daemonInfo.pid !== null) {
    console.log(`  Daemon:      stale pid ${daemonInfo.pid} (process not found)`);
  } else {
    console.log(`  Daemon:      not running`);
  }
  console.log(
    `  Clients:     ${clientStats.active} active, ${clientStats.pending} pending, ${clientStats.revoked} revoked`
  );

  if (opts.showToken && config) {
    console.log("");
    // Printed last so it's trivially easy to copy. The URL uses
    // localhost — no way from here to know which external hostname
    // `local start` was invoked with (Tailscale, LAN, etc.). That's
    // fine for `--show-token` which is mostly for developer sanity
    // checks; the authoritative URL is whatever `local start`
    // prints on boot.
    console.log(`  Token URL:   ${buildLocalhostTokenUrl(config.publicKey, config.secret)}`);
  } else if (!opts.showToken) {
    console.log("");
    console.log(`  (Run \`pty-relay local status --show-token\` to print the token URL.)`);
  }
}

interface DaemonProbe {
  pid: number | null;
  running: boolean;
}

function probeDaemon(configDir: string): DaemonProbe {
  const pidPath = path.join(configDir, "daemon.pid");
  if (!fs.existsSync(pidPath)) return { pid: null, running: false };
  try {
    const pid = parseInt(fs.readFileSync(pidPath, "utf-8").trim(), 10);
    if (!isFinite(pid)) return { pid: null, running: false };
    try {
      process.kill(pid, 0);
      return { pid, running: true };
    } catch {
      return { pid, running: false };
    }
  } catch {
    return { pid: null, running: false };
  }
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

function buildLocalhostTokenUrl(
  publicKey: Uint8Array,
  secret: Uint8Array
): string {
  // Use the same shape the daemon prints on startup so copy/paste
  // works identically. We don't know the port without reading process
  // state, so fall back to 8099 (`local start`'s default). If the
  // operator is running on a different port, the authoritative URL
  // is whatever `local start` printed — status is best-effort.
  return createToken("localhost:8099", publicKey, secret);
}
