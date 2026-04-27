import * as fs from "node:fs";
import * as path from "node:path";
import sodium from "libsodium-wrappers-sumo";
import {
  type SecretName,
  type SecretStore,
  secretFilename,
} from "./secret-store.ts";
import { deriveKey, type KdfProfile, zeroize } from "../crypto/aead.ts";
import { encode, decode, b64encode } from "../crypto/envelope.ts";
import { log, now, sinceMs } from "../log.ts";

/**
 * File-backed SecretStore that encrypts each secret with a key derived from a
 * user passphrase via Argon2id.
 *
 * Uses the same salt and profile for every stored secret (one master key per
 * install). Different nonces per file.
 */
export class PassphraseStore implements SecretStore {
  readonly backend = "passphrase" as const;

  readonly configDir: string;
  readonly salt: Uint8Array;
  readonly profile: KdfProfile;
  private key: Uint8Array;

  private constructor(
    configDir: string,
    salt: Uint8Array,
    profile: KdfProfile,
    key: Uint8Array
  ) {
    this.configDir = configDir;
    this.salt = salt;
    this.profile = profile;
    this.key = key;
  }

  /**
   * Open (or create) a passphrase-backed store. Ensures libsodium is ready
   * and derives the master key.
   */
  static async open(
    configDir: string,
    passphrase: string,
    salt: Uint8Array,
    profile: KdfProfile
  ): Promise<PassphraseStore> {
    const start = now();
    await sodium.ready;
    const key = deriveKey(passphrase, salt, profile);
    log("store", "passphrase deriveKey", { profile, ms: sinceMs(start) });
    return new PassphraseStore(configDir, salt, profile, key);
  }

  /** Filesystem path where this secret's envelope is stored. */
  private filePath(name: SecretName): string {
    return path.join(this.configDir, secretFilename(name));
  }

  async load(name: SecretName): Promise<Uint8Array | null> {
    const start = now();
    const p = this.filePath(name);
    let json: string;
    try {
      json = fs.readFileSync(p, "utf-8");
    } catch (err: any) {
      if (err?.code === "ENOENT") {
        log("store", `passphrase load ${name}`, { found: false, ms: sinceMs(start) });
        return null;
      }
      throw err;
    }

    const bytes = await decode(json, () => this.key);
    log("store", `passphrase load ${name}`, { bytes: bytes.length, ms: sinceMs(start) });
    return bytes;
  }

  async save(name: SecretName, plaintext: Uint8Array): Promise<void> {
    const start = now();
    fs.mkdirSync(this.configDir, { recursive: true, mode: 0o700 });

    const json = encode(plaintext, this.key, {
      salt: b64encode(this.salt),
      profile: this.profile,
    });

    const p = this.filePath(name);
    const tmpPath = `${p}.tmp.${process.pid}.${Date.now()}`;

    try {
      fs.writeFileSync(tmpPath, json, { mode: 0o600 });
      fs.renameSync(tmpPath, p);
    } catch (err) {
      try {
        fs.unlinkSync(tmpPath);
      } catch {}
      throw err;
    }
    log("store", `passphrase save ${name}`, { bytes: plaintext.length, ms: sinceMs(start) });
  }

  async delete(name: SecretName): Promise<void> {
    const start = now();
    const p = this.filePath(name);
    try {
      fs.unlinkSync(p);
    } catch (err: any) {
      if (err?.code === "ENOENT") {
        log("store", `passphrase delete ${name}`, { found: false, ms: sinceMs(start) });
        return;
      }
      throw err;
    }
    log("store", `passphrase delete ${name}`, { ms: sinceMs(start) });
  }

  /**
   * Best-effort cleanup of the derived key. Call when the process is shutting
   * down if you want to reduce the window the key is resident in memory.
   */
  dispose(): void {
    zeroize(this.key);
  }
}
