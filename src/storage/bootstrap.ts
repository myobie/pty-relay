import * as fs from "node:fs";
import * as path from "node:path";
import sodium from "libsodium-wrappers-sumo";
import type { SecretStore } from "./secret-store.ts";
import { PassphraseStore } from "./passphrase-store.ts";
import { KeychainStore } from "./keychain-store.ts";
import { readPassphrase } from "./passphrase-prompt.ts";
import { randomSalt, type KdfProfile } from "../crypto/aead.ts";
import { b64encode, b64decode } from "../crypto/envelope.ts";

import { getSessionDir } from "@myobie/pty/client";

const MARKER_FILENAME = "storage.json";

export interface StorageMarker {
  v: 1;
  backend: "keychain" | "passphrase";
  salt?: string;
}

export interface BootstrapOpts {
  /** True when we're attached to a terminal and can prompt interactively. */
  interactive?: boolean;
  /** Explicit passphrase (highest precedence after env var). */
  passphrase?: string;
  /** Path to a file whose (first line of) contents is the passphrase. */
  passphraseFile?: string;
  /**
   * When creating a new store for the first time, this selects the backend.
   * Defaults to "keychain if available, else passphrase".
   */
  preferredBackend?: "keychain" | "passphrase";
}

/**
 * Result of opening the store. `passphrase` is set only when the backend is
 * passphrase-based and we actually know it — callers like `connect` pass it
 * through the environment to re-exec'd children so they don't reprompt.
 */
export interface OpenedStore {
  store: SecretStore;
  passphrase?: string;
  created: boolean;
}

/** Default config dir — same as the rest of the codebase uses. */
export function defaultConfigDir(): string {
  return path.join(getSessionDir(), "relay");
}

/** Current KDF profile based on env var (tests set this to "interactive"). */
export function currentKdfProfile(): KdfProfile {
  const v = process.env.PTY_RELAY_KDF_PROFILE;
  if (v === "interactive") return "interactive";
  return "moderate";
}

function markerPath(configDir: string): string {
  return path.join(configDir, MARKER_FILENAME);
}

function readMarker(configDir: string): StorageMarker | null {
  try {
    const raw = fs.readFileSync(markerPath(configDir), "utf-8");
    const parsed = JSON.parse(raw);
    if (!parsed || parsed.v !== 1) return null;
    if (parsed.backend !== "keychain" && parsed.backend !== "passphrase") {
      return null;
    }
    return parsed as StorageMarker;
  } catch {
    return null;
  }
}

function writeMarker(configDir: string, marker: StorageMarker): void {
  fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });
  const tmp = `${markerPath(configDir)}.tmp.${process.pid}.${Date.now()}`;
  fs.writeFileSync(tmp, JSON.stringify(marker, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, markerPath(configDir));
}

/**
 * Resolve a passphrase from env/options/file, but do not fall back to
 * prompting. Returns null when no non-interactive source is set.
 */
function resolvePassphraseNonInteractive(opts: BootstrapOpts): string | null {
  const envVar = process.env.PTY_RELAY_PASSPHRASE;
  if (envVar && envVar.length > 0) return envVar;
  if (opts.passphrase && opts.passphrase.length > 0) return opts.passphrase;
  if (opts.passphraseFile) {
    const contents = fs.readFileSync(opts.passphraseFile, "utf-8");
    // Trim trailing newline (trailing whitespace is user's responsibility)
    const first = contents.replace(/\r?\n$/, "");
    if (first.length > 0) return first;
  }
  return null;
}

/**
 * Open (or create) the secret store for `configDir`.
 *
 * Bootstrap sequence:
 *   1. Read storage.json marker if present
 *   2. If marker exists → use that backend, resolve passphrase as needed
 *   3. If marker missing → try keychain, else create a passphrase store
 */
export async function openSecretStore(
  configDir?: string,
  opts: BootstrapOpts = {}
): Promise<OpenedStore> {
  await sodium.ready;

  const dir = configDir ?? defaultConfigDir();
  const marker = readMarker(dir);

  if (marker) {
    return await openExisting(dir, marker, opts);
  }
  return await createNew(dir, opts);
}

async function openExisting(
  configDir: string,
  marker: StorageMarker,
  opts: BootstrapOpts
): Promise<OpenedStore> {
  if (marker.backend === "keychain") {
    const store = await KeychainStore.tryOpen(configDir);
    if (!store) {
      throw new Error(
        "storage.json says backend=keychain but @napi-rs/keyring is not available. " +
          "Install @napi-rs/keyring, or run 'pty-relay reset' to start over."
      );
    }
    return { store, created: false };
  }

  // passphrase backend
  if (!marker.salt) {
    throw new Error(
      "corrupted storage.json: passphrase backend is missing salt. Run 'pty-relay reset'."
    );
  }
  const salt = b64decode(marker.salt);

  const passphrase = await getPassphraseForUnlock(opts);
  const profile = currentKdfProfile();
  const store = await PassphraseStore.open(configDir, passphrase, salt, profile);

  // Validate by attempting to load the config secret, if present. If it
  // fails, the passphrase is wrong — surface a clear error.
  await assertPassphraseWorks(store);
  return { store, passphrase, created: false };
}

async function assertPassphraseWorks(store: PassphraseStore): Promise<void> {
  // "config" is the canonical first file; if nothing is there yet, we have
  // no way to verify, but a wrong passphrase will fail the first real load
  // anyway. If it is there and decryption fails, surface that clearly.
  try {
    await store.load("config");
  } catch (err: any) {
    throw new Error(
      `Failed to decrypt stored credentials: ${err?.message ?? err}. ` +
        "The passphrase may be wrong, or the files may be corrupted. " +
        "Use 'pty-relay reset' to start over."
    );
  }
}

async function createNew(
  configDir: string,
  opts: BootstrapOpts
): Promise<OpenedStore> {
  // Explicit preference wins over env var, which wins over default behavior.
  const envBackend = process.env.PTY_RELAY_BACKEND;
  const preferredBackend =
    opts.preferredBackend ??
    (envBackend === "keychain" || envBackend === "passphrase"
      ? envBackend
      : undefined);

  if (preferredBackend === "passphrase") {
    return await createNewPassphrase(configDir, opts);
  }

  // preferredBackend is "keychain" or undefined — both prefer keychain.
  const kc = await KeychainStore.tryOpen(configDir);
  if (kc) {
    writeMarker(configDir, { v: 1, backend: "keychain" });
    return { store: kc, created: true };
  }
  if (preferredBackend === "keychain") {
    throw new Error(
      "requested --backend keychain but @napi-rs/keyring is not installed. " +
        "Run 'npm install @napi-rs/keyring' or use --backend passphrase."
    );
  }

  return await createNewPassphrase(configDir, opts);
}

async function createNewPassphrase(
  configDir: string,
  opts: BootstrapOpts
): Promise<OpenedStore> {
  const passphrase = await getPassphraseForCreate(opts);
  const salt = randomSalt();
  const profile = currentKdfProfile();

  const store = await PassphraseStore.open(configDir, passphrase, salt, profile);
  writeMarker(configDir, {
    v: 1,
    backend: "passphrase",
    salt: b64encode(salt),
  });

  return { store, passphrase, created: true };
}

async function getPassphraseForUnlock(opts: BootstrapOpts): Promise<string> {
  const nonInteractive = resolvePassphraseNonInteractive(opts);
  if (nonInteractive) return nonInteractive;

  if (opts.interactive && process.stdin.isTTY) {
    return await readPassphrase({
      prompt: "Passphrase to unlock pty-relay credentials: ",
    });
  }
  throw new Error(
    "No keychain available and no passphrase provided. " +
      "Set PTY_RELAY_PASSPHRASE, use --passphrase-file, or run from a TTY."
  );
}

async function getPassphraseForCreate(opts: BootstrapOpts): Promise<string> {
  const nonInteractive = resolvePassphraseNonInteractive(opts);
  if (nonInteractive) return nonInteractive;

  if (opts.interactive && process.stdin.isTTY) {
    process.stderr.write(
      "\n" +
        "pty-relay needs to encrypt the credentials it will store on this\n" +
        "machine (daemon keys, saved host URLs, client approval tokens).\n" +
        "Your OS keychain isn't available, so we'll use a passphrase you\n" +
        "choose now. You'll be prompted for it each time you run pty-relay\n" +
        "on this machine. There is no recovery if you forget it — you can\n" +
        "start over with 'pty-relay reset'.\n" +
        "\n"
    );
    return await readPassphrase({
      prompt: "New passphrase: ",
      confirm: true,
    });
  }
  throw new Error(
    "No keychain available and no passphrase provided. " +
      "Set PTY_RELAY_PASSPHRASE, use --passphrase-file, or run from a TTY."
  );
}

/**
 * Does a marker file exist in this dir?
 */
export function hasMarker(configDir?: string): boolean {
  const dir = configDir ?? defaultConfigDir();
  return readMarker(dir) !== null;
}

export function getMarkerPath(configDir?: string): string {
  return markerPath(configDir ?? defaultConfigDir());
}
