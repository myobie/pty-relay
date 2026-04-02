import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import sodium from "libsodium-wrappers-sumo";
import {
  type SecretName,
  type SecretStore,
  secretFilename,
} from "./secret-store.ts";
import { randomKey, zeroize } from "../crypto/aead.ts";
import { encode, decode, b64encode, b64decode } from "../crypto/envelope.ts";

const SERVICE = "pty-relay";
const MASTER_ACCOUNT_SUFFIX = ":__master__";

/**
 * Minimal surface of @napi-rs/keyring that we use. We load the module
 * dynamically so it can be an optional dependency.
 */
interface KeyringEntry {
  getPassword(): string | null;
  setPassword(value: string): void;
  deletePassword(): boolean;
}
interface KeyringModule {
  Entry: new (service: string, account: string) => KeyringEntry;
}

/**
 * Keychain-backed SecretStore. Stores a random 32-byte master key in the
 * system keychain; each secret is encrypted under that master key and the
 * encrypted envelope is itself stored as a separate keychain entry keyed by
 * `sha256(configDir):<name>`.
 *
 * On-disk marker files (`${configDir}/${filename}.keychain`) record which
 * names currently have data in the keychain, so the bootstrap can detect
 * state at startup without having to poke at the keychain.
 */
export class KeychainStore implements SecretStore {
  readonly backend = "keychain" as const;

  readonly configDir: string;
  private readonly keyring: KeyringModule;
  private readonly dirHash: string;
  private masterKey: Uint8Array | null;

  private constructor(
    configDir: string,
    keyring: KeyringModule,
    dirHash: string,
    masterKey: Uint8Array | null
  ) {
    this.configDir = configDir;
    this.keyring = keyring;
    this.dirHash = dirHash;
    this.masterKey = masterKey;
  }

  /**
   * Try to construct a KeychainStore. Returns null if `@napi-rs/keyring` is
   * not installed or is not functional on this platform.
   *
   * Does NOT materialize a master key by itself; that happens lazily on the
   * first save() call (or on load() if a master already exists).
   */
  static async tryOpen(configDir: string): Promise<KeychainStore | null> {
    let keyring: KeyringModule;
    try {
      // Use string concat to keep TypeScript from demanding a type for the
      // optional dependency at type-check time.
      const specifier = "@napi-rs/keyring";
      const mod: any = await import(/* @vite-ignore */ specifier);
      const Entry = mod.Entry ?? mod.default?.Entry;
      if (typeof Entry !== "function") return null;
      keyring = { Entry };
    } catch {
      return null;
    }

    const abs = path.resolve(configDir);
    const dirHash = crypto
      .createHash("sha256")
      .update(abs)
      .digest("hex")
      .slice(0, 16);

    // Try to load an existing master key if one is present.
    let masterKey: Uint8Array | null = null;
    try {
      const entry = new keyring.Entry(SERVICE, dirHash + MASTER_ACCOUNT_SUFFIX);
      const val = entry.getPassword();
      if (val) {
        masterKey = b64decode(val);
      }
    } catch {
      // If even the probe fails, keychain is not usable.
      return null;
    }

    return new KeychainStore(configDir, keyring, dirHash, masterKey);
  }

  private markerPath(name: SecretName): string {
    return path.join(this.configDir, `${secretFilename(name)}.keychain`);
  }

  private account(name: SecretName): string {
    return `${this.dirHash}:${name}`;
  }

  private async ensureMasterKey(): Promise<Uint8Array> {
    if (this.masterKey) return this.masterKey;
    await sodium.ready;

    const entry = new this.keyring.Entry(
      SERVICE,
      this.dirHash + MASTER_ACCOUNT_SUFFIX
    );
    const existing = entry.getPassword();
    if (existing) {
      this.masterKey = b64decode(existing);
      return this.masterKey;
    }

    // Race: another process may create the master key between our
    // getPassword() and our setPassword(). On macOS, setPassword throws
    // "item already exists" in that case. Handle by re-reading and
    // using whichever key was saved first.
    const fresh = randomKey();
    try {
      entry.setPassword(b64encode(fresh));
      this.masterKey = fresh;
    } catch (err: any) {
      const msg = String(err?.message ?? err);
      if (/already exists/i.test(msg)) {
        const raced = entry.getPassword();
        if (raced) {
          this.masterKey = b64decode(raced);
          zeroize(fresh);
          return this.masterKey;
        }
      }
      throw err;
    }
    return this.masterKey;
  }

  async load(name: SecretName): Promise<Uint8Array | null> {
    const marker = this.markerPath(name);
    if (!fs.existsSync(marker)) return null;

    const entry = new this.keyring.Entry(SERVICE, this.account(name));
    const json = entry.getPassword();
    if (!json) return null;

    const key = await this.ensureMasterKey();
    return await decode(json, () => key);
  }

  async save(name: SecretName, plaintext: Uint8Array): Promise<void> {
    fs.mkdirSync(this.configDir, { recursive: true, mode: 0o700 });

    const key = await this.ensureMasterKey();
    const json = encode(plaintext, key, null);

    const entry = new this.keyring.Entry(SERVICE, this.account(name));
    try {
      entry.setPassword(json);
    } catch (err: any) {
      // On macOS, setPassword can throw "item already exists" if a
      // concurrent update happened. Delete and retry once.
      const msg = String(err?.message ?? err);
      if (/already exists/i.test(msg)) {
        try {
          entry.deletePassword();
        } catch {}
        entry.setPassword(json);
      } else {
        throw err;
      }
    }

    // Atomic marker write. Content is irrelevant (contains the account name
    // as a debug hint) — the file's existence is the only thing that matters.
    const marker = this.markerPath(name);
    const tmp = `${marker}.tmp.${process.pid}.${Date.now()}`;
    fs.writeFileSync(tmp, this.account(name), { mode: 0o600 });
    fs.renameSync(tmp, marker);
  }

  async delete(name: SecretName): Promise<void> {
    try {
      const entry = new this.keyring.Entry(SERVICE, this.account(name));
      entry.deletePassword();
    } catch {}
    try {
      fs.unlinkSync(this.markerPath(name));
    } catch {}
  }

  /** Remove the master key from this process's memory. */
  dispose(): void {
    if (this.masterKey) zeroize(this.masterKey);
    this.masterKey = null;
  }

  /**
   * Delete the master key (and per-name entries) from the keychain. Used by
   * `pty-relay reset`.
   */
  async destroyAll(): Promise<void> {
    const names: SecretName[] = ["config", "clients", "hosts", "auth"];
    for (const n of names) {
      await this.delete(n);
    }
    try {
      const entry = new this.keyring.Entry(
        SERVICE,
        this.dirHash + MASTER_ACCOUNT_SUFFIX
      );
      entry.deletePassword();
    } catch {}
    this.masterKey = null;
  }
}
