import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import sodium from "libsodium-wrappers-sumo";
import { PassphraseStore } from "./passphrase-store.ts";
import { randomSalt } from "../crypto/aead.ts";

beforeAll(async () => {
  await sodium.ready;
});

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join("/tmp", "pphrase-store-test-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("PassphraseStore", () => {
  it("round-trips save/load/delete for each SecretName", async () => {
    const salt = randomSalt();
    const store = await PassphraseStore.open(
      tmpDir,
      "correct-horse-battery-staple",
      salt,
      "interactive"
    );

    const names = ["config", "clients", "hosts", "auth"] as const;
    for (const name of names) {
      expect(await store.load(name)).toBeNull();

      const plaintext = new TextEncoder().encode(`data for ${name}`);
      await store.save(name, plaintext);

      const loaded = await store.load(name);
      expect(loaded).not.toBeNull();
      expect(new TextDecoder().decode(loaded!)).toBe(`data for ${name}`);

      await store.delete(name);
      expect(await store.load(name)).toBeNull();
    }
  });

  it("writes files with mode 0o600", async () => {
    const salt = randomSalt();
    const store = await PassphraseStore.open(tmpDir, "pw", salt, "interactive");
    await store.save("config", new TextEncoder().encode("secret"));
    await store.save("clients", new TextEncoder().encode("more"));

    for (const name of ["config.json", "clients.json"]) {
      const p = path.join(tmpDir, name);
      const stat = fs.statSync(p);
      expect(stat.mode & 0o777).toBe(0o600);
    }
  });

  it("leaves no .tmp files on disk after a successful save", async () => {
    const salt = randomSalt();
    const store = await PassphraseStore.open(tmpDir, "pw", salt, "interactive");
    await store.save("config", new TextEncoder().encode("x"));

    const entries = fs.readdirSync(tmpDir);
    expect(entries).toContain("config.json");
    for (const entry of entries) {
      expect(entry).not.toMatch(/\.tmp\./);
    }
  });

  it("fails with a clear error when reopened with the wrong passphrase", async () => {
    const salt = randomSalt();
    const good = await PassphraseStore.open(tmpDir, "correct", salt, "interactive");
    await good.save("config", new TextEncoder().encode("payload"));

    const bad = await PassphraseStore.open(tmpDir, "wrong", salt, "interactive");
    await expect(bad.load("config")).rejects.toThrow(/decryption failed/i);
  });

  it("stores the hosts secret in the 'hosts' file (no extension)", async () => {
    const salt = randomSalt();
    const store = await PassphraseStore.open(tmpDir, "pw", salt, "interactive");
    await store.save("hosts", new TextEncoder().encode("[]"));

    expect(fs.existsSync(path.join(tmpDir, "hosts"))).toBe(true);
    expect(fs.existsSync(path.join(tmpDir, "hosts.json"))).toBe(false);
  });

  it("envelope on disk does not contain the plaintext", async () => {
    const salt = randomSalt();
    const store = await PassphraseStore.open(tmpDir, "pw", salt, "interactive");
    const plaintext = "unmistakable-marker-string";
    await store.save("config", new TextEncoder().encode(plaintext));

    const raw = fs.readFileSync(path.join(tmpDir, "config.json"), "utf-8");
    expect(raw).not.toContain(plaintext);
    expect(raw).toContain('"ct"');
  });
});
