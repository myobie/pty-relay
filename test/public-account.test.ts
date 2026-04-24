import { describe, it, expect, beforeEach } from "vitest";
import type {
  SecretName,
  SecretStore,
} from "../src/storage/secret-store.ts";
import {
  loadPublicAccount,
  savePublicAccount,
  clearPublicAccount,
  type PublicAccount,
  type KeyIdentity,
} from "../src/storage/public-account.ts";

// Minimal in-memory SecretStore for unit tests. The real stores are
// exercised in passphrase-store.test.ts / keychain-store.test.ts — here
// we just need a backing byte-bucket keyed by SecretName to verify the
// public-account schema round-trips and is validated on load.
class MemStore implements SecretStore {
  readonly backend = "passphrase" as const;
  private data = new Map<SecretName, Uint8Array>();
  async load(name: SecretName): Promise<Uint8Array | null> {
    return this.data.get(name) ?? null;
  }
  async save(name: SecretName, plaintext: Uint8Array): Promise<void> {
    this.data.set(name, plaintext);
  }
  async delete(name: SecretName): Promise<void> {
    this.data.delete(name);
  }
  raw(name: SecretName): Uint8Array | undefined {
    return this.data.get(name);
  }
}

function sampleKey(overrides: Partial<KeyIdentity> = {}): KeyIdentity {
  return {
    signingKeys: {
      public: "cHViLWtleS1iNjQtdXJs",
      secret: "c2VjcmV0LWtleS1iNjQtdXJs",
    },
    registeredKeyId: "01HVC00KEY0000000000000000",
    enrolledAt: "2026-04-17T00:00:00.000Z",
    ...overrides,
  };
}

function sampleAccount(overrides: Partial<PublicAccount> = {}): PublicAccount {
  return {
    relayUrl: "http://localhost:4000",
    email: "me@example.com",
    accountId: "01HVC000000000000000000000",
    label: "laptop",
    totpSecretB32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    daemonKey: sampleKey(),
    clientKey: sampleKey({
      signingKeys: {
        public: "Y2xpZW50LXB1Yg",
        secret: "Y2xpZW50LXNlY3JldA",
      },
      registeredKeyId: "01HVC00CLIENT0000000000000",
    }),
    ...overrides,
  };
}

describe("public-account storage", () => {
  let store: MemStore;

  beforeEach(() => {
    store = new MemStore();
  });

  it("returns null when nothing is stored", async () => {
    expect(await loadPublicAccount(store)).toBeNull();
  });

  it("round-trips a full record", async () => {
    const account = sampleAccount();
    await savePublicAccount(account, store);
    expect(await loadPublicAccount(store)).toEqual(account);
  });

  it("round-trips without a TOTP secret (joined-device case)", async () => {
    const account = sampleAccount({ totpSecretB32: undefined });
    await savePublicAccount(account, store);
    const loaded = await loadPublicAccount(store);
    expect(loaded).not.toBeNull();
    expect(loaded!.totpSecretB32).toBeUndefined();
  });

  it("persists a daemon-only device (no client key)", async () => {
    const account = sampleAccount({ clientKey: undefined, label: "server-a" });
    await savePublicAccount(account, store);
    const loaded = await loadPublicAccount(store);
    expect(loaded).not.toBeNull();
    expect(loaded!.clientKey).toBeUndefined();
    expect(loaded!.daemonKey).toBeDefined();
  });

  it("persists a client-only device (no daemon key)", async () => {
    const account = sampleAccount({ daemonKey: undefined, label: "phone" });
    await savePublicAccount(account, store);
    const loaded = await loadPublicAccount(store);
    expect(loaded).not.toBeNull();
    expect(loaded!.daemonKey).toBeUndefined();
    expect(loaded!.clientKey).toBeDefined();
  });

  it("clearPublicAccount removes the record", async () => {
    await savePublicAccount(sampleAccount(), store);
    await clearPublicAccount(store);
    expect(await loadPublicAccount(store)).toBeNull();
  });

  it("writes to the 'public_account' secret name", async () => {
    await savePublicAccount(sampleAccount(), store);
    expect(store.raw("public_account")).toBeDefined();
    expect(store.raw("config")).toBeUndefined();
  });

  it("rejects malformed JSON on load", async () => {
    await store.save(
      "public_account",
      new TextEncoder().encode("not valid json {")
    );
    expect(await loadPublicAccount(store)).toBeNull();
  });

  it("rejects schema violations on load (missing signingKeys inside a key)", async () => {
    const broken: any = JSON.parse(JSON.stringify(sampleAccount()));
    delete broken.daemonKey.signingKeys;
    await store.save(
      "public_account",
      new TextEncoder().encode(JSON.stringify(broken))
    );
    expect(await loadPublicAccount(store)).toBeNull();
  });

  it("rejects a record with neither daemonKey nor clientKey", async () => {
    const broken = sampleAccount({
      daemonKey: undefined,
      clientKey: undefined,
    });
    await store.save(
      "public_account",
      new TextEncoder().encode(JSON.stringify(broken))
    );
    expect(await loadPublicAccount(store)).toBeNull();
  });
});
