import { describe, it, expect } from "vitest";
import type { SecretName, SecretStore } from "../src/storage/secret-store.ts";
import {
  loadKnownHosts,
  saveKnownHost,
  savePublicKnownHost,
  removeKnownHost,
  renameKnownHost,
  isPublicHost,
  pickUniqueLabel,
  type KnownHost,
} from "../src/relay/known-hosts.ts";

class MemStore implements SecretStore {
  readonly backend = "passphrase" as const;
  private data = new Map<SecretName, Uint8Array>();
  async load(n: SecretName) { return this.data.get(n) ?? null; }
  async save(n: SecretName, p: Uint8Array) { this.data.set(n, p); }
  async delete(n: SecretName) { this.data.delete(n); }
}

describe("KnownHost schema — self-hosted and public-relay coexist", () => {
  it("round-trips a self-hosted host with just {label, url}", async () => {
    const store = new MemStore();
    await saveKnownHost("local", "http://localhost:8099#pk.secret", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts).toEqual([
      { label: "local", url: "http://localhost:8099#pk.secret" },
    ]);
    expect(isPublicHost(hosts[0])).toBe(false);
  });

  it("round-trips a public-relay host with no url", async () => {
    const store = new MemStore();
    await savePublicKnownHost(
      {
        label: "laptop",
        relayUrl: "http://localhost:4000",
        publicKey: "pk_b64",
      },
      store
    );
    const hosts = await loadKnownHosts(store);
    expect(hosts).toEqual([
      {
        label: "laptop",
        relayUrl: "http://localhost:4000",
        publicKey: "pk_b64",
        role: "daemon",
      },
    ]);
    expect(isPublicHost(hosts[0])).toBe(true);
  });

  it("both flavors can live side-by-side", async () => {
    const store = new MemStore();
    await saveKnownHost("local", "http://localhost:8099#pk.secret", store);
    await savePublicKnownHost(
      { label: "remote", relayUrl: "http://localhost:4000", publicKey: "pk" },
      store
    );
    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(2);
    const local = hosts.find((h) => h.label === "local")!;
    const remote = hosts.find((h) => h.label === "remote")!;
    expect(isPublicHost(local)).toBe(false);
    expect(isPublicHost(remote)).toBe(true);
  });

  it("savePublicKnownHost de-dups by (relayUrl, publicKey) as well as label", async () => {
    const store = new MemStore();
    await savePublicKnownHost(
      { label: "old-name", relayUrl: "http://h", publicKey: "k" },
      store
    );
    await savePublicKnownHost(
      { label: "new-name", relayUrl: "http://h", publicKey: "k" },
      store
    );
    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(1);
    expect(hosts[0].label).toBe("new-name");
  });

  it("discards malformed entries on load (no url and no relayUrl)", async () => {
    const store = new MemStore();
    await store.save(
      "hosts",
      new TextEncoder().encode(
        JSON.stringify([
          { label: "ok", url: "http://a#b.c" },
          { label: "bad" }, // missing both transports
          { label: "ok2", relayUrl: "http://h", publicKey: "p" },
        ])
      )
    );
    const hosts = await loadKnownHosts(store);
    expect(hosts.map((h) => h.label)).toEqual(["ok", "ok2"]);
  });

  it("removeKnownHost drops matching labels regardless of flavor", async () => {
    const store = new MemStore();
    await saveKnownHost("a", "http://a#b.c", store);
    await savePublicKnownHost(
      { label: "b", relayUrl: "http://h", publicKey: "p" },
      store
    );
    await removeKnownHost("b", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts.map((h) => h.label)).toEqual(["a"]);
  });
});

describe("pickUniqueLabel", () => {
  it("returns the wanted label unchanged when it's free", () => {
    expect(pickUniqueLabel("laptop", "anything", new Set())).toBe("laptop");
  });

  it("suffixes with a distinguisher prefix when the label collides", () => {
    const used = new Set(["laptop"]);
    expect(pickUniqueLabel("laptop", "abcd1234efgh5678", used)).toBe("laptop-abcd");
  });

  it("widens the suffix in 4-char steps when the short form also collides", () => {
    const used = new Set(["laptop", "laptop-abcd"]);
    expect(pickUniqueLabel("laptop", "abcd1234efgh5678", used)).toBe(
      "laptop-abcd1234"
    );
  });

  it("handles a short distinguisher by appending a numeric counter", () => {
    // Short distinguisher + every candidate already used → counter
    // fallback produces "x-pk-2" so we never silently return a dup.
    const used = new Set(["x", "x-pk"]);
    expect(pickUniqueLabel("x", "pk", used)).toBe("x-pk-2");
  });

  it("walks the counter forward when numbered variants also collide", () => {
    const used = new Set(["x", "x-pk", "x-pk-2", "x-pk-3"]);
    expect(pickUniqueLabel("x", "pk", used)).toBe("x-pk-4");
  });
});

describe("label-collision avoidance on save", () => {
  it("saveKnownHost keeps both entries when a new URL arrives with the same label", async () => {
    const store = new MemStore();
    await saveKnownHost("home", "http://a.example/#k1.s1", store);
    await saveKnownHost("home", "http://b.example/#k2.s2", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(2);
    const labels = hosts.map((h) => h.label).sort();
    expect(labels[0]).toBe("home");
    expect(labels[1]).toMatch(/^home-http/); // suffixed with URL prefix
  });

  it("saveKnownHost re-save of the same URL updates its label in place (no collision)", async () => {
    const store = new MemStore();
    const url = "http://a.example/#k.s";
    await saveKnownHost("first-name", url, store);
    await saveKnownHost("second-name", url, store);
    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(1);
    expect(hosts[0].label).toBe("second-name");
  });

  it("saveKnownHost overwrites in place when the same host arrives with rotated key material (regression: known-hosts-host-dedup)", async () => {
    // Scenario: remote host's state was wiped, daemon came back up with
    // fresh #pk.secret. User runs `connect <new-token-url>`. We must
    // overwrite the stale entry — not append a second one that the old
    // label still resolves to. Pre-fix this filtered on the full URL
    // (including fragment) so the dedup missed, and the stale row kept
    // the original label while the new one got a URL-suffixed label.
    const store = new MemStore();
    await saveKnownHost("home", "http://a.example/#oldPk.oldSecret", store);
    await saveKnownHost("home", "http://a.example/#newPk.newSecret", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(1);
    expect(hosts[0].label).toBe("home");
    expect(hosts[0].url).toBe("http://a.example/#newPk.newSecret");
  });

  it("saveKnownHost overwrites in place even when only the secret rotates", async () => {
    // Same pubkey, new secret — still the same daemon, dedup must hit.
    const store = new MemStore();
    await saveKnownHost("home", "http://a.example/#pk.s1", store);
    await saveKnownHost("home", "http://a.example/#pk.s2", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(1);
    expect(hosts[0].url).toBe("http://a.example/#pk.s2");
  });

  it("saveKnownHost host-dedup ignores port-equal-but-host-different (different machines are different entries)", async () => {
    // a.example:8099 and b.example:8099 share a port but are different
    // daemons — they must NOT collapse into one entry. URL.host includes
    // the port + hostname, so the dedup naturally keeps them separate.
    const store = new MemStore();
    await saveKnownHost("alice", "http://a.example:8099/#k.s", store);
    await saveKnownHost("bob", "http://b.example:8099/#k.s", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(2);
  });

  it("saveKnownHost host-dedup leaves public-relay entries untouched", async () => {
    // Public-relay entries have no `url` field. The self-hosted save
    // must not interpret them as "stale self-hosted" and evict them.
    const store = new MemStore();
    await savePublicKnownHost(
      { label: "remote", relayUrl: "http://relay", publicKey: "pk1" },
      store
    );
    await saveKnownHost("local", "http://localhost:8099/#k.s", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(2);
    expect(hosts.some((h) => h.label === "remote" && isPublicHost(h))).toBe(true);
    expect(hosts.some((h) => h.label === "local" && h.url === "http://localhost:8099/#k.s")).toBe(true);
  });

  it("savePublicKnownHost re-save of the same pubkey updates the label in place", async () => {
    const store = new MemStore();
    await savePublicKnownHost(
      { label: "first", relayUrl: "http://h", publicKey: "pk1" },
      store
    );
    await savePublicKnownHost(
      { label: "second", relayUrl: "http://h", publicKey: "pk1" },
      store
    );
    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(1);
    expect(hosts[0].label).toBe("second");
  });

  it("renameKnownHost updates the label in place", async () => {
    const store = new MemStore();
    await saveKnownHost("old-name", "http://a.example/#k.s", store);
    await renameKnownHost("old-name", "new-name", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts.map((h) => h.label)).toEqual(["new-name"]);
    expect(hosts[0].url).toBe("http://a.example/#k.s");
  });

  it("renameKnownHost works for public-relay entries too", async () => {
    const store = new MemStore();
    await savePublicKnownHost(
      { label: "host-abcd1234", relayUrl: "http://h", publicKey: "pk" },
      store
    );
    await renameKnownHost("host-abcd1234", "laptop", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts.map((h) => h.label)).toEqual(["laptop"]);
    expect(isPublicHost(hosts[0])).toBe(true);
  });

  it("renameKnownHost errors when the old label doesn't exist", async () => {
    const store = new MemStore();
    await saveKnownHost("a", "http://a#b.c", store);
    await expect(renameKnownHost("nope", "whatever", store)).rejects.toThrow(
      /No known host/
    );
  });

  it("renameKnownHost errors when the new label is already taken", async () => {
    const store = new MemStore();
    await saveKnownHost("a", "http://a#b.c", store);
    await saveKnownHost("b", "http://b#c.d", store);
    await expect(renameKnownHost("a", "b", store)).rejects.toThrow(
      /already in use/
    );
  });

  it("renameKnownHost is a no-op when old and new labels match", async () => {
    const store = new MemStore();
    await saveKnownHost("a", "http://a#b.c", store);
    await renameKnownHost("a", "a", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(1);
  });

  it("savePublicKnownHost suffixes when two different pubkeys want the same label", async () => {
    const store = new MemStore();
    await savePublicKnownHost(
      { label: "laptop", relayUrl: "http://h", publicKey: "pk_abcd1234" },
      store
    );
    await savePublicKnownHost(
      { label: "laptop", relayUrl: "http://h", publicKey: "pk_ef567890" },
      store
    );
    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(2);
    const labels = hosts.map((h) => h.label).sort();
    expect(labels[0]).toBe("laptop");
    expect(labels[1]).toBe("laptop-pk_e");
  });
});
