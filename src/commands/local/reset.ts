import * as fs from "node:fs";
import * as path from "node:path";
import {
  defaultConfigDir,
  getMarkerPath,
  hasMarker,
} from "../../storage/bootstrap.ts";
import { KeychainStore } from "../../storage/keychain-store.ts";
import { secretFilename, type SecretName } from "../../storage/secret-store.ts";
import { log } from "../../log.ts";

/**
 * `pty-relay local reset` — wipe ONLY the self-hosted daemon's local
 * identity state. Preserves:
 *
 *   - `hosts`           — saved known-hosts for outgoing connections
 *                          (still useful as a client even after the
 *                          self-hosted daemon's keys are gone).
 *   - `public_account`  — public-relay account record (daemon + client
 *                          keys, TOTP, account id). A leaked self-
 *                          hosted token URL shouldn't cost you your
 *                          public-relay enrollment.
 *   - storage marker + keychain master key — kept so the operator can
 *                          immediately re-run `pty-relay local start`
 *                          without re-entering the passphrase.
 *
 * Deletes: `config` (daemon keypair + pairing secret), `clients`
 * (approval tokens for this daemon), `auth` (custom label set via
 * `pty-relay set-name`), and `daemon.pid`.
 *
 * Does not need to open the secret store — just removes files and
 * matching keychain entries directly. That way it still works if the
 * operator has forgotten the passphrase (same property the top-level
 * `reset` preserves).
 *
 * Requires a TTY confirmation unless `--force` is passed. The full
 * "nuke everything including public-relay enrollment" sledgehammer
 * is the top-level `pty-relay reset`; use that when you really want
 * a clean slate.
 */

export interface LocalResetOpts {
  configDir?: string;
  force?: boolean;
}

/** Secret names scoped to the self-hosted daemon. Kept together so
 *  the keychain + filesystem paths both iterate the same list. */
const SELF_HOSTED_SECRETS: SecretName[] = ["config", "clients", "auth"];

export async function localResetCommand(opts: LocalResetOpts): Promise<void> {
  log("cli", "local reset begin", { force: !!opts.force });
  const dir = opts.configDir ?? defaultConfigDir();

  if (!fs.existsSync(dir)) {
    console.log(`Nothing to reset at ${dir}.`);
    return;
  }

  // What will actually go away, so the confirmation prompt reflects
  // reality. Don't claim to delete files that aren't there.
  const toDelete: string[] = [];
  for (const n of SELF_HOSTED_SECRETS) {
    const p = path.join(dir, secretFilename(n));
    if (fs.existsSync(p)) toDelete.push(path.basename(p));
  }
  const pidPath = path.join(dir, "daemon.pid");
  if (fs.existsSync(pidPath)) toDelete.push("daemon.pid");

  if (toDelete.length === 0) {
    console.log(`No self-hosted daemon state found in ${dir}.`);
    return;
  }

  if (!opts.force) {
    if (!process.stdin.isTTY) {
      console.error(
        "local reset requires --force when not attached to a TTY (it will delete self-hosted daemon credentials)"
      );
      process.exit(1);
    }
    console.log(`About to delete in ${dir}:`);
    for (const name of toDelete) console.log(`  ${name}`);
    console.log("");
    console.log(
      "Preserved: hosts (known-hosts), public-account.json (public-relay enrollment)."
    );
    const answer = await prompt("Proceed? [y/N] ");
    if (answer.trim().toLowerCase() !== "y") {
      console.log("Aborted.");
      return;
    }
  }

  // Keychain-backed stores need their individual entries deleted in
  // the keychain too; the file-only removal below wouldn't touch them.
  // We only delete the self-hosted names — `hosts` and `public_account`
  // stay intact. The master key stays in place so a subsequent
  // `local start` reuses it (no passphrase re-prompt).
  let backend: "keychain" | "passphrase" | null = null;
  if (hasMarker(dir)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(getMarkerPath(dir), "utf-8"));
      if (parsed.backend === "keychain" || parsed.backend === "passphrase") {
        backend = parsed.backend;
      }
    } catch {}
  }

  if (backend === "keychain") {
    const kc = await KeychainStore.tryOpen(dir);
    if (kc) {
      for (const n of SELF_HOSTED_SECRETS) {
        try {
          await kc.delete(n);
        } catch {}
      }
    }
  }

  // Remove the on-disk files. For keychain backend, these are tiny
  // placeholders; for passphrase backend, they hold the actual
  // encrypted blobs.
  for (const n of SELF_HOSTED_SECRETS) {
    const p = path.join(dir, secretFilename(n));
    try {
      fs.rmSync(p, { force: true });
    } catch {}
  }
  try {
    fs.rmSync(pidPath, { force: true });
  } catch {}

  console.log(`Reset: removed self-hosted daemon state (${toDelete.length} items) in ${dir}.`);
  console.log(
    "Public-relay account and known-hosts entries preserved. Run `pty-relay local start` to re-initialize the daemon identity."
  );
}

function prompt(question: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(question);
    process.stdin.ref();
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    process.stdin.once("data", (data: string) => {
      process.stdin.pause();
      process.stdin.unref();
      resolve(data);
    });
  });
}
