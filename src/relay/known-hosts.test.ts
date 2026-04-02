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
import * as os from "node:os";
import sodium from "libsodium-wrappers-sumo";
import {
  loadKnownHosts,
  saveKnownHost,
  removeKnownHost,
} from "./known-hosts.ts";
import { PassphraseStore } from "../storage/passphrase-store.ts";
import { randomSalt } from "../crypto/aead.ts";

beforeAll(async () => {
  await sodium.ready;
  process.env.PTY_RELAY_KDF_PROFILE = "interactive";
});

let tmpDir: string;
let store: PassphraseStore;

beforeEach(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pty-relay-hosts-test-"));
  store = await PassphraseStore.open(
    tmpDir,
    "test-pass",
    randomSalt(),
    "interactive"
  );
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("known-hosts", () => {
  it("returns empty array when nothing is stored", async () => {
    const hosts = await loadKnownHosts(store);
    expect(hosts).toEqual([]);
  });

  it("saves and loads a host", async () => {
    await saveKnownHost("my-mac", "https://relay.example.com#key.secret", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts).toEqual([
      { label: "my-mac", url: "https://relay.example.com#key.secret" },
    ]);
  });

  it("saves multiple hosts", async () => {
    await saveKnownHost("mac-1", "https://relay.example.com#key1.secret1", store);
    await saveKnownHost("mac-2", "https://relay.example.com#key2.secret2", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts).toHaveLength(2);
    expect(hosts[0].label).toBe("mac-1");
    expect(hosts[1].label).toBe("mac-2");
  });

  it("updates label when same URL is saved again", async () => {
    await saveKnownHost("old-name", "https://relay.example.com#key.secret", store);
    await saveKnownHost("new-name", "https://relay.example.com#key.secret", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts).toHaveLength(1);
    expect(hosts[0].label).toBe("new-name");
  });

  it("removes a host by label", async () => {
    await saveKnownHost("mac-1", "https://relay.example.com#key1.secret1", store);
    await saveKnownHost("mac-2", "https://relay.example.com#key2.secret2", store);
    await removeKnownHost("mac-1", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts).toHaveLength(1);
    expect(hosts[0].label).toBe("mac-2");
  });

  it("handles URLs with colons in them", async () => {
    await saveKnownHost("local", "http://localhost:8099#key.secret", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts).toEqual([
      { label: "local", url: "http://localhost:8099#key.secret" },
    ]);
  });

  it("stores the hosts file as an encrypted envelope (no plaintext URL)", async () => {
    const url = "http://localhost:8099#marker-url-in-plaintext.secret";
    await saveKnownHost("local", url, store);
    const raw = fs.readFileSync(path.join(tmpDir, "hosts"), "utf-8");
    expect(raw).not.toContain("marker-url-in-plaintext");
    expect(raw).toContain('"ct"');
  });
});
