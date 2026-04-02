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
import { KeychainStore } from "./keychain-store.ts";

// Only run these tests if @napi-rs/keyring is actually installed and
// the OS has a working keyring backend. On macOS the keyring is always
// available. On Linux in CI there may not be a running Secret Service.
//
// We probe once synchronously before vitest collects tests so that
// `describe.skipIf` sees the correct value. The trick: await the probe
// at module load time via a top-level await.

async function probeKeychain(): Promise<boolean> {
  await sodium.ready;
  const probeDir = fs.mkdtempSync(path.join("/tmp", "kc-probe-"));
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

// Top-level await: by the time vitest finishes collecting this file,
// `keychainAvailable` is already set to the right value.
const keychainAvailable = await probeKeychain();

beforeAll(() => {
  process.env.PTY_RELAY_KDF_PROFILE = "interactive";
});

// Helper: each test gets its own config dir so keychain entries don't collide.
let tmpDir: string;
let stores: KeychainStore[] = [];

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join("/tmp", "keychain-store-test-"));
  stores = [];
});

afterEach(async () => {
  // Destroy any keychain entries these tests created so we don't leave
  // garbage in the user's keychain.
  for (const store of stores) {
    try {
      await store.destroyAll();
    } catch {}
  }
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function track(store: KeychainStore): KeychainStore {
  stores.push(store);
  return store;
}

describe.skipIf(!keychainAvailable)("KeychainStore", () => {
  it("tryOpen succeeds when @napi-rs/keyring is installed", async () => {
    const store = await KeychainStore.tryOpen(tmpDir);
    expect(store).not.toBeNull();
    expect(store!.backend).toBe("keychain");
    track(store!);
  });

  it("load returns null before any save", async () => {
    const store = track((await KeychainStore.tryOpen(tmpDir))!);
    expect(await store.load("config")).toBeNull();
    expect(await store.load("clients")).toBeNull();
    expect(await store.load("hosts")).toBeNull();
    expect(await store.load("auth")).toBeNull();
  });

  it("round-trips bytes through save/load", async () => {
    const store = track((await KeychainStore.tryOpen(tmpDir))!);
    const plaintext = new TextEncoder().encode("the quick brown fox");
    await store.save("config", plaintext);

    const loaded = await store.load("config");
    expect(loaded).not.toBeNull();
    expect(new TextDecoder().decode(loaded!)).toBe("the quick brown fox");
  });

  it("creates marker file on save", async () => {
    const store = track((await KeychainStore.tryOpen(tmpDir))!);
    await store.save("config", new TextEncoder().encode("x"));

    const marker = path.join(tmpDir, "config.json.keychain");
    expect(fs.existsSync(marker)).toBe(true);
  });

  it("stores different secret names independently", async () => {
    const store = track((await KeychainStore.tryOpen(tmpDir))!);
    await store.save("config", new TextEncoder().encode("config-data"));
    await store.save("clients", new TextEncoder().encode("clients-data"));
    await store.save("hosts", new TextEncoder().encode("hosts-data"));
    await store.save("auth", new TextEncoder().encode("auth-data"));

    expect(new TextDecoder().decode((await store.load("config"))!)).toBe(
      "config-data"
    );
    expect(new TextDecoder().decode((await store.load("clients"))!)).toBe(
      "clients-data"
    );
    expect(new TextDecoder().decode((await store.load("hosts"))!)).toBe(
      "hosts-data"
    );
    expect(new TextDecoder().decode((await store.load("auth"))!)).toBe(
      "auth-data"
    );
  });

  it("delete removes both the keychain entry and the marker file", async () => {
    const store = track((await KeychainStore.tryOpen(tmpDir))!);
    await store.save("config", new TextEncoder().encode("data"));

    const marker = path.join(tmpDir, "config.json.keychain");
    expect(fs.existsSync(marker)).toBe(true);

    await store.delete("config");

    expect(fs.existsSync(marker)).toBe(false);
    expect(await store.load("config")).toBeNull();
  });

  it("second tryOpen on same dir reuses the same master key", async () => {
    // Write with store A, read with a fresh store B pointing at the same
    // config dir — they must share a master key via the keychain.
    const a = track((await KeychainStore.tryOpen(tmpDir))!);
    await a.save("config", new TextEncoder().encode("via-a"));

    const b = track((await KeychainStore.tryOpen(tmpDir))!);
    const out = await b.load("config");
    expect(out).not.toBeNull();
    expect(new TextDecoder().decode(out!)).toBe("via-a");
  });

  it("different config dirs use independent master keys", async () => {
    const tmpDir2 = fs.mkdtempSync(path.join("/tmp", "keychain-store-test-"));
    try {
      const a = track((await KeychainStore.tryOpen(tmpDir))!);
      const b = track((await KeychainStore.tryOpen(tmpDir2))!);

      await a.save("config", new TextEncoder().encode("from-a"));
      await b.save("config", new TextEncoder().encode("from-b"));

      expect(new TextDecoder().decode((await a.load("config"))!)).toBe("from-a");
      expect(new TextDecoder().decode((await b.load("config"))!)).toBe("from-b");
    } finally {
      fs.rmSync(tmpDir2, { recursive: true, force: true });
    }
  });

  it("secrets stored in keychain are NOT readable from config dir as plaintext", async () => {
    const store = track((await KeychainStore.tryOpen(tmpDir))!);
    await store.save(
      "config",
      new TextEncoder().encode("ultra-secret-needle-xyz")
    );

    // The marker file should not contain the plaintext.
    const marker = path.join(tmpDir, "config.json.keychain");
    expect(fs.existsSync(marker)).toBe(true);
    const markerContent = fs.readFileSync(marker, "utf-8");
    expect(markerContent).not.toContain("ultra-secret-needle-xyz");

    // No other file in the config dir should contain the plaintext.
    for (const entry of fs.readdirSync(tmpDir)) {
      const contents = fs.readFileSync(path.join(tmpDir, entry), "utf-8");
      expect(contents).not.toContain("ultra-secret-needle-xyz");
    }
  });

  it("destroyAll removes all entries and master key", async () => {
    const store = track((await KeychainStore.tryOpen(tmpDir))!);
    await store.save("config", new TextEncoder().encode("a"));
    await store.save("clients", new TextEncoder().encode("b"));

    await store.destroyAll();

    expect(fs.existsSync(path.join(tmpDir, "config.json.keychain"))).toBe(false);
    expect(fs.existsSync(path.join(tmpDir, "clients.json.keychain"))).toBe(false);

    // A fresh tryOpen on the same dir must NOT decrypt old data — the
    // master key is gone, so even if someone had saved the envelope text,
    // they couldn't read it.
    const fresh = await KeychainStore.tryOpen(tmpDir);
    expect(fresh).not.toBeNull();
    expect(await fresh!.load("config")).toBeNull();
    track(fresh!);
  });
});
