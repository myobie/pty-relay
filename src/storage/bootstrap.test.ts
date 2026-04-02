import {
  describe,
  it,
  expect,
  beforeAll,
  beforeEach,
  afterEach,
} from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import sodium from "libsodium-wrappers-sumo";
import { openSecretStore, hasMarker } from "./bootstrap.ts";
import { KeychainStore } from "./keychain-store.ts";

// Probe the OS keyring at module load time so `describe.skipIf` gets the
// right value (it's evaluated during test collection, before beforeAll).
async function probeKeychain(): Promise<boolean> {
  await sodium.ready;
  const probeDir = fs.mkdtempSync(path.join("/tmp", "bootstrap-kc-probe-"));
  try {
    const store = await KeychainStore.tryOpen(probeDir);
    if (!store) return false;
    try {
      await store.save("config", new TextEncoder().encode("probe"));
      const out = await store.load("config");
      const ok = !!out && new TextDecoder().decode(out) === "probe";
      await store.destroyAll();
      return ok;
    } catch {
      return false;
    }
  } catch {
    return false;
  } finally {
    fs.rmSync(probeDir, { recursive: true, force: true });
  }
}

const keychainAvailable = await probeKeychain();

beforeAll(async () => {
  await sodium.ready;
  process.env.PTY_RELAY_KDF_PROFILE = "interactive";
});

let tmpDir: string;
let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join("/tmp", "bootstrap-test-"));
  savedEnv = {
    PTY_RELAY_PASSPHRASE: process.env.PTY_RELAY_PASSPHRASE,
  };
  // Tests in this file fully control the env var for their scenarios.
  delete process.env.PTY_RELAY_PASSPHRASE;
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
  if (savedEnv.PTY_RELAY_PASSPHRASE !== undefined) {
    process.env.PTY_RELAY_PASSPHRASE = savedEnv.PTY_RELAY_PASSPHRASE;
  } else {
    delete process.env.PTY_RELAY_PASSPHRASE;
  }
});

describe("openSecretStore bootstrap", () => {
  it("first run with PTY_RELAY_PASSPHRASE creates marker + passphrase store", async () => {
    process.env.PTY_RELAY_PASSPHRASE = "test-passphrase";

    const { store, created } = await openSecretStore(tmpDir, {
      preferredBackend: "passphrase",
    });
    expect(created).toBe(true);
    expect(store.backend).toBe("passphrase");
    expect(hasMarker(tmpDir)).toBe(true);

    const marker = JSON.parse(
      fs.readFileSync(path.join(tmpDir, "storage.json"), "utf-8")
    );
    expect(marker.v).toBe(1);
    expect(marker.backend).toBe("passphrase");
    expect(typeof marker.salt).toBe("string");

    // Round-trip a value through the store
    await store.save("config", new TextEncoder().encode("hello"));
    const out = await store.load("config");
    expect(out).not.toBeNull();
    expect(new TextDecoder().decode(out!)).toBe("hello");
  });

  it("second run reads marker and uses saved salt", async () => {
    process.env.PTY_RELAY_PASSPHRASE = "test-passphrase";

    const first = await openSecretStore(tmpDir, { preferredBackend: "passphrase" });
    await first.store.save(
      "config",
      new TextEncoder().encode("persisted-bytes")
    );

    // Second open — should still be able to decrypt
    const second = await openSecretStore(tmpDir);
    expect(second.created).toBe(false);
    expect(second.store.backend).toBe("passphrase");

    const loaded = await second.store.load("config");
    expect(loaded).not.toBeNull();
    expect(new TextDecoder().decode(loaded!)).toBe("persisted-bytes");
  });

  it("PTY_RELAY_PASSPHRASE takes precedence over passphraseFile", async () => {
    process.env.PTY_RELAY_PASSPHRASE = "env-wins";
    const pfile = path.join(tmpDir, "pw.txt");
    fs.writeFileSync(pfile, "file-loses\n");

    const { store } = await openSecretStore(tmpDir, {
      preferredBackend: "passphrase",
      passphraseFile: pfile,
    });
    await store.save("config", new TextEncoder().encode("x"));

    // Now reopen with only the env var (matching) — should work.
    const reopened = await openSecretStore(tmpDir);
    const out = await reopened.store.load("config");
    expect(new TextDecoder().decode(out!)).toBe("x");

    // Reopen with wrong env var — should fail.
    process.env.PTY_RELAY_PASSPHRASE = "not-the-right-one";
    await expect(openSecretStore(tmpDir)).rejects.toThrow(
      /decrypt stored credentials|decryption failed/i
    );
  });

  it("non-TTY + no env var + non-interactive fails clearly", async () => {
    // Ensure no env var / file is set
    delete process.env.PTY_RELAY_PASSPHRASE;

    await expect(
      openSecretStore(tmpDir, { interactive: false, preferredBackend: "passphrase" })
    ).rejects.toThrow(/No keychain available|passphrase/i);
  });

  it("wrong passphrase on reopen fails", async () => {
    process.env.PTY_RELAY_PASSPHRASE = "right";
    const first = await openSecretStore(tmpDir, { preferredBackend: "passphrase" });
    await first.store.save("config", new TextEncoder().encode("data"));

    process.env.PTY_RELAY_PASSPHRASE = "wrong";
    await expect(openSecretStore(tmpDir)).rejects.toThrow(
      /decrypt stored credentials|decryption failed/i
    );
  });

  it("changing PTY_RELAY_PASSPHRASE between runs fails", async () => {
    process.env.PTY_RELAY_PASSPHRASE = "first-pass";
    const a = await openSecretStore(tmpDir, { preferredBackend: "passphrase" });
    await a.store.save("config", new TextEncoder().encode("body"));

    process.env.PTY_RELAY_PASSPHRASE = "second-pass";
    await expect(openSecretStore(tmpDir)).rejects.toThrow(
      /decrypt stored credentials|decryption failed/i
    );
  });

  it("supports a passphrase file without env var", async () => {
    const pfile = path.join(tmpDir, "pw.txt");
    fs.writeFileSync(pfile, "file-pass\n");

    const { store, created } = await openSecretStore(tmpDir, {
      passphraseFile: pfile,
      preferredBackend: "passphrase",
    });
    expect(created).toBe(true);
    await store.save("config", new TextEncoder().encode("val"));

    // Reopen with the same file
    const reopened = await openSecretStore(tmpDir, { passphraseFile: pfile });
    const out = await reopened.store.load("config");
    expect(new TextDecoder().decode(out!)).toBe("val");
  });
});

describe.skipIf(!keychainAvailable)("openSecretStore with keychain backend", () => {
  // Track keychain stores created in tests so we can clean up after.
  let createdStores: KeychainStore[] = [];

  beforeEach(() => {
    createdStores = [];
  });

  afterEach(async () => {
    for (const store of createdStores) {
      try {
        await store.destroyAll();
      } catch {}
    }
  });

  function rememberKeychain(store: unknown): void {
    if (store instanceof KeychainStore) createdStores.push(store);
  }

  it("first run with no preference picks keychain when available", async () => {
    const { store, created } = await openSecretStore(tmpDir);
    rememberKeychain(store);

    expect(created).toBe(true);
    expect(store.backend).toBe("keychain");
    expect(hasMarker(tmpDir)).toBe(true);

    const marker = JSON.parse(
      fs.readFileSync(path.join(tmpDir, "storage.json"), "utf-8")
    );
    expect(marker.backend).toBe("keychain");
  });

  it("first run with preferredBackend=keychain succeeds", async () => {
    const { store } = await openSecretStore(tmpDir, {
      preferredBackend: "keychain",
    });
    rememberKeychain(store);

    expect(store.backend).toBe("keychain");
  });

  it("round-trips data through a keychain-backed store", async () => {
    const { store } = await openSecretStore(tmpDir);
    rememberKeychain(store);

    await store.save(
      "config",
      new TextEncoder().encode("keychain-round-trip")
    );
    const out = await store.load("config");
    expect(out).not.toBeNull();
    expect(new TextDecoder().decode(out!)).toBe("keychain-round-trip");
  });

  it("second run reads existing keychain marker and reuses the same store", async () => {
    const first = await openSecretStore(tmpDir);
    rememberKeychain(first.store);
    await first.store.save("config", new TextEncoder().encode("persistent"));

    const second = await openSecretStore(tmpDir);
    rememberKeychain(second.store);

    expect(second.created).toBe(false);
    expect(second.store.backend).toBe("keychain");

    const loaded = await second.store.load("config");
    expect(loaded).not.toBeNull();
    expect(new TextDecoder().decode(loaded!)).toBe("persistent");
  });

  it("does not write plaintext secrets to the config dir", async () => {
    const { store } = await openSecretStore(tmpDir);
    rememberKeychain(store);

    const secretMarker = "ultra-secret-needle-for-grep";
    await store.save(
      "config",
      new TextEncoder().encode(secretMarker)
    );

    // Scan every file in the config dir; none should contain the plaintext.
    for (const entry of fs.readdirSync(tmpDir)) {
      const full = path.join(tmpDir, entry);
      const stat = fs.statSync(full);
      if (!stat.isFile()) continue;
      const contents = fs.readFileSync(full, "utf-8");
      expect(
        contents,
        `file ${entry} should not contain plaintext secret`
      ).not.toContain(secretMarker);
    }
  });

  it("keychain does not prompt for a passphrase", async () => {
    // If the keychain path prompted for a passphrase, this test would hang
    // forever because there is no TTY and no PTY_RELAY_PASSPHRASE env var.
    // We explicitly delete the env var and set a short Promise.race
    // timeout to fail fast on regression.
    delete process.env.PTY_RELAY_PASSPHRASE;

    const openPromise = openSecretStore(tmpDir, { interactive: false });
    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error("TIMEOUT: store open blocked")), 3000)
    );

    const result = (await Promise.race([openPromise, timeout])) as Awaited<
      ReturnType<typeof openSecretStore>
    >;
    rememberKeychain(result.store);

    expect(result.store.backend).toBe("keychain");
    expect(result.passphrase).toBeUndefined();
  });
});
