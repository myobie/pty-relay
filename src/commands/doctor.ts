import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execFileSync } from "node:child_process";
import { defaultConfigDir, getMarkerPath } from "../storage/bootstrap.ts";

/**
 * `pty-relay doctor` — print diagnostic info to help debug setup issues.
 * Designed to be safe to share: does NOT print secrets, token URLs,
 * or the contents of any encrypted file.
 */
export async function doctorCommand(opts: {
  configDir?: string;
}): Promise<void> {
  const lines: string[] = [];
  const configDir = opts.configDir ?? defaultConfigDir();

  lines.push("pty-relay doctor");
  lines.push("");

  // ── Versions ──
  lines.push("Environment:");
  lines.push(`  pty-relay:   ${await readPackageVersion()}`);
  lines.push(`  node:        ${process.version}`);
  lines.push(`  platform:    ${process.platform} (${process.arch})`);
  lines.push(`  os release:  ${os.release()}`);
  lines.push(`  hostname:    ${os.hostname()}`);
  lines.push("");

  // ── External tools ──
  lines.push("External tools:");
  lines.push(`  pty:         ${checkPty()}`);
  lines.push(`  tailscale:   ${checkTailscale()}`);
  lines.push(`  qrencode:    ${checkCli("qrencode", ["--version"])}`);
  lines.push("");

  // ── Keychain backend ──
  lines.push("Secret storage:");
  const keychainStatus = await checkKeychain();
  lines.push(`  keychain:    ${keychainStatus}`);
  lines.push(`  config dir:  ${configDir}`);
  lines.push(`  exists:      ${fs.existsSync(configDir) ? "yes" : "no"}`);

  // Marker info (non-secret: just the backend kind + salt length)
  const markerPath = getMarkerPath(configDir);
  if (fs.existsSync(markerPath)) {
    try {
      const marker = JSON.parse(fs.readFileSync(markerPath, "utf-8"));
      lines.push(`  backend:     ${marker.backend}`);
      if (marker.backend === "passphrase") {
        lines.push(
          `  salt:        ${marker.salt ? `${marker.salt.length} chars (base64)` : "missing"}`
        );
      }
    } catch {
      lines.push(`  backend:     (marker unreadable)`);
    }
  } else {
    lines.push(`  backend:     (not initialized)`);
  }
  lines.push("");

  // ── Config files ──
  lines.push("Config files:");
  if (fs.existsSync(configDir)) {
    try {
      const entries = fs.readdirSync(configDir);
      if (entries.length === 0) {
        lines.push("  (empty)");
      } else {
        for (const entry of entries.sort()) {
          const full = path.join(configDir, entry);
          try {
            const stat = fs.statSync(full);
            const mode = (stat.mode & 0o777).toString(8).padStart(3, "0");
            const size = stat.size.toString().padStart(6, " ");
            lines.push(`  ${mode}  ${size}  ${entry}`);
          } catch {
            lines.push(`  ???   ??????  ${entry}`);
          }
        }
      }
    } catch {
      lines.push("  (directory not readable)");
    }
  } else {
    lines.push("  (config dir does not exist)");
  }
  lines.push("");

  // ── Env vars (redacted) ──
  lines.push("Environment variables:");
  lines.push(
    `  PTY_RELAY_PASSPHRASE:   ${process.env.PTY_RELAY_PASSPHRASE ? "(set)" : "(unset)"}`
  );
  lines.push(
    `  PTY_RELAY_BACKEND:      ${process.env.PTY_RELAY_BACKEND ?? "(unset)"}`
  );
  lines.push(
    `  PTY_RELAY_KDF_PROFILE:  ${process.env.PTY_RELAY_KDF_PROFILE ?? "(unset)"}`
  );
  lines.push(
    `  PTY_SESSION_DIR:        ${process.env.PTY_SESSION_DIR ?? "(unset)"}`
  );
  lines.push("");

  // ── Daemon PID ──
  const pidPath = path.join(configDir, "daemon.pid");
  lines.push("Daemon:");
  if (fs.existsSync(pidPath)) {
    try {
      const pid = parseInt(fs.readFileSync(pidPath, "utf-8").trim(), 10);
      if (!isNaN(pid)) {
        let alive = false;
        try {
          process.kill(pid, 0);
          alive = true;
        } catch {}
        lines.push(`  pid:         ${pid} (${alive ? "running" : "stale"})`);
      } else {
        lines.push(`  pid:         (malformed pid file)`);
      }
    } catch {
      lines.push(`  pid:         (pid file unreadable)`);
    }
  } else {
    lines.push(`  pid:         (not running)`);
  }
  lines.push("");

  // ── Public-relay enrollment (if any) ──
  // Tries to read the public_account secret via the normal store.
  // Only works if the operator supplied a passphrase (or the keychain
  // backend is in use) — otherwise we'd have to prompt, which doctor
  // shouldn't do. Silent when it can't read; that's fine for a
  // diagnostic tool.
  lines.push("Public relay:");
  try {
    const { openSecretStore } = await import("../storage/bootstrap.ts");
    const { loadPublicAccount } = await import("../storage/public-account.ts");
    const { store } = await openSecretStore(configDir, {
      interactive: false,
    });
    const account = await loadPublicAccount(store);
    if (!account) {
      lines.push("  (not enrolled on any public relay)");
    } else {
      lines.push(`  relay:       ${account.relayUrl}`);
      lines.push(`  email:       ${account.email || "(unknown)"}`);
      lines.push(`  account id:  ${account.accountId || "(unknown)"}`);
      lines.push(`  label:       ${account.label}`);
      lines.push(
        `  TOTP:        ${account.totpSecretB32 ? "owned on this device" : "managed elsewhere"}`
      );
      if (account.daemonKey) {
        lines.push(`  daemon key:  ${account.daemonKey.signingKeys.public}`);
        lines.push(`    enrolled:  ${account.daemonKey.enrolledAt}`);
        if (account.daemonKey.pendingRotation) {
          lines.push(
            `    rotation:  pending since ${account.daemonKey.pendingRotation.startedAt}`
          );
        }
      } else {
        lines.push(`  daemon key:  (none)`);
      }
      if (account.clientKey) {
        lines.push(`  client key:  ${account.clientKey.signingKeys.public}`);
        lines.push(`    enrolled:  ${account.clientKey.enrolledAt}`);
        if (account.clientKey.pendingRotation) {
          lines.push(
            `    rotation:  pending since ${account.clientKey.pendingRotation.startedAt}`
          );
        }
      } else {
        lines.push(`  client key:  (none)`);
      }
    }
  } catch (err: any) {
    // Not an error for doctor's purposes — the encrypted store needs
    // a passphrase, and a read-only diagnostic shouldn't prompt.
    lines.push(
      `  (can't read without a passphrase; try ` +
        `PTY_RELAY_PASSPHRASE=... pty-relay server status)`
    );
  }
  lines.push("");

  console.log(lines.join("\n"));
}

async function readPackageVersion(): Promise<string> {
  try {
    // Read the package.json that lives two levels up from src/commands/
    const pkgPath = path.resolve(
      import.meta.dirname,
      "../../package.json"
    );
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
    return pkg.version ?? "unknown";
  } catch {
    return "unknown";
  }
}

function checkCli(
  cmd: string,
  args: string[] = ["--version"]
): string {
  try {
    const out = execFileSync(cmd, args, {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 2000,
    });
    const firstLine = out.trim().split("\n")[0] || "found";
    return firstLine.length > 50 ? firstLine.slice(0, 50) + "…" : firstLine;
  } catch {
    return "(not found)";
  }
}

/**
 * pty CLI doesn't support --version, so probe with `pty list` which
 * prints "Active sessions:" on success and exits non-zero if pty isn't
 * installed.
 */
function checkPty(): string {
  try {
    execFileSync("pty", ["list"], {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 2000,
    });
    return "found";
  } catch {
    return "(not found)";
  }
}

function checkTailscale(): string {
  // Tailscale CLI can live on PATH or in the macOS app bundle.
  // Try both to match what --tailscale does.
  try {
    const out = execFileSync("tailscale", ["version"], {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 2000,
    });
    return out.trim().split("\n")[0];
  } catch {}
  try {
    const macPath = "/Applications/Tailscale.app/Contents/MacOS/Tailscale";
    const out = execFileSync(macPath, ["version"], {
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 2000,
    });
    return `${out.trim().split("\n")[0]} (${macPath})`;
  } catch {}
  return "(not found)";
}

async function checkKeychain(): Promise<string> {
  // Dynamically import to check availability without forcing a hard dep.
  try {
    const mod = await import("@napi-rs/keyring");
    const Entry = mod.Entry ?? mod.default?.Entry;
    if (typeof Entry !== "function") {
      return "(@napi-rs/keyring installed but unusable)";
    }
    // Probe by writing a throwaway entry to confirm the OS keyring
    // is actually functional (D-Bus running on Linux, etc.).
    const probeService = "pty-relay-doctor-probe";
    const probeAccount = `probe-${process.pid}-${Date.now()}`;
    try {
      const entry = new Entry(probeService, probeAccount);
      entry.setPassword("ok");
      const back = entry.getPassword();
      try {
        entry.deletePassword();
      } catch {}
      if (back === "ok") {
        return "available";
      }
      return "(installed but round-trip failed)";
    } catch (err: any) {
      return `(installed but OS keyring error: ${err?.message ?? "unknown"})`;
    }
  } catch {
    return "(@napi-rs/keyring not installed)";
  }
}
