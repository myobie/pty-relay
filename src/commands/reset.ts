import * as fs from "node:fs";
import * as path from "node:path";
import {
  defaultConfigDir,
  getMarkerPath,
  hasMarker,
} from "../storage/bootstrap.ts";
import { KeychainStore } from "../storage/keychain-store.ts";
import { log } from "../log.ts";

export interface ResetOpts {
  configDir?: string;
  force?: boolean;
}

/**
 * `pty-relay reset` — wipe the config directory and any keychain entries.
 *
 * Non-destructive of the process state; just nukes the on-disk files.
 */
export async function resetCommand(opts: ResetOpts): Promise<void> {
  log("cli", "reset begin", { force: !!opts.force });
  const dir = opts.configDir ?? defaultConfigDir();

  if (!fs.existsSync(dir)) {
    console.log(`Nothing to reset at ${dir}.`);
    return;
  }

  if (!opts.force) {
    if (!process.stdin.isTTY) {
      console.error(
        "reset requires --force when not attached to a TTY (it will delete all stored credentials)"
      );
      process.exit(1);
    }
    const answer = await prompt(
      `This will delete all saved credentials in ${dir}. Continue? [y/N] `
    );
    if (answer.trim().toLowerCase() !== "y") {
      console.log("Aborted.");
      return;
    }
  }

  // If the marker says keychain, also wipe the keychain entries.
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
      try {
        await kc.destroyAll();
      } catch {}
    }
  }

  // Delete all files in the directory
  try {
    const entries = fs.readdirSync(dir);
    for (const entry of entries) {
      const p = path.join(dir, entry);
      try {
        fs.rmSync(p, { recursive: true, force: true });
      } catch {}
    }
  } catch {}

  console.log(`Reset: removed all credentials in ${dir}`);
}

function prompt(question: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(question);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    process.stdin.once("data", (data: string) => {
      process.stdin.pause();
      resolve(data);
    });
  });
}
