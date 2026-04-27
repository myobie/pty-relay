import * as fs from "node:fs";
import {
  openSecretStore,
  hasMarker,
  getMarkerPath,
  defaultConfigDir,
} from "../storage/bootstrap.ts";
import { log } from "../log.ts";

export interface InitOpts {
  configDir?: string;
  passphraseFile?: string;
  backend?: string;
  force?: boolean;
}

/**
 * `pty-relay init` — explicit first-time setup of the secret store.
 */
export async function initCommand(opts: InitOpts): Promise<void> {
  const dir = opts.configDir ?? defaultConfigDir();
  log("cli", "init begin", { dir, force: !!opts.force, backendHint: opts.backend });

  if (hasMarker(dir)) {
    if (!opts.force) {
      console.error(
        `Storage already initialized at ${dir} (${getMarkerPath(dir)}).\n` +
          "Pass --force to re-initialize (all existing credentials will be lost)."
      );
      process.exit(1);
    }
    // Wipe existing state so bootstrap takes the "new install" path.
    try {
      fs.rmSync(getMarkerPath(dir), { force: true });
    } catch {}
    for (const f of ["config.json", "clients.json", "hosts", "auth.json"]) {
      try {
        fs.rmSync(`${dir}/${f}`, { force: true });
        fs.rmSync(`${dir}/${f}.keychain`, { force: true });
      } catch {}
    }
  }

  let preferred: "keychain" | "passphrase" | undefined;
  if (opts.backend === "keychain" || opts.backend === "passphrase") {
    preferred = opts.backend;
  } else if (opts.backend) {
    console.error(
      `Unknown backend "${opts.backend}". Use "keychain" or "passphrase".`
    );
    process.exit(1);
  }

  const { store } = await openSecretStore(dir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
    preferredBackend: preferred,
  });

  console.log("");
  console.log(`Initialized secret storage at ${dir}`);
  console.log(`Backend: ${store.backend}`);
  console.log("");
  console.log("Next steps — pick a mode:");
  console.log("");
  console.log("  Self-hosted (one process on this machine, no accounts):");
  console.log("    pty-relay local start [port]");
  console.log("");
  console.log("  Public relay (multi-tenant, email + TOTP auth):");
  console.log("    pty-relay server signin --email you@example.com --relay https://relay.pty.computer");
  console.log("    pty-relay server start");
  console.log("");
  console.log("  Or use an existing public-relay account as a client:");
  console.log("    pty-relay client signin --email you@example.com --relay https://relay.pty.computer");
}
