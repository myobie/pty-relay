import { describe, it, expect } from "vitest";
import type { SecretName, SecretStore } from "../src/storage/secret-store.ts";
import {
  loadKnownHosts,
  saveKnownHost,
  savePublicKnownHost,
  saveSshKnownHost,
  removeKnownHost,
  isPublicHost,
  isSshHost,
} from "../src/relay/known-hosts.ts";
import { resolveHost } from "../src/relay/host-resolve.ts";

class MemStore implements SecretStore {
  readonly backend = "passphrase" as const;
  private data = new Map<SecretName, Uint8Array>();
  async load(n: SecretName) { return this.data.get(n) ?? null; }
  async save(n: SecretName, p: Uint8Array) { this.data.set(n, p); }
  async delete(n: SecretName) { this.data.delete(n); }
}

describe("KnownHost — ssh flavor coexists with self-hosted and public-relay", () => {
  it("round-trips an ssh host through save/load", async () => {
    const store = new MemStore();
    await saveSshKnownHost({ label: "homelab", sshUrl: "ssh://me@home" }, store);
    const hosts = await loadKnownHosts(store);
    expect(hosts).toEqual([{ label: "homelab", sshUrl: "ssh://me@home" }]);
    expect(isSshHost(hosts[0])).toBe(true);
    expect(isPublicHost(hosts[0])).toBe(false);
  });

  it("all three flavors live side-by-side", async () => {
    const store = new MemStore();
    await saveKnownHost("local", "http://localhost:8099#pk.s", store);
    await savePublicKnownHost(
      { label: "remote", relayUrl: "http://relay", publicKey: "pk" },
      store,
    );
    await saveSshKnownHost({ label: "headless", sshUrl: "ssh://headless" }, store);
    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(3);
    expect(hosts.filter((h) => isSshHost(h)).length).toBe(1);
    expect(hosts.filter((h) => isPublicHost(h)).length).toBe(1);
  });

  it("re-save of the same sshUrl updates the label in place", async () => {
    const store = new MemStore();
    await saveSshKnownHost({ label: "first", sshUrl: "ssh://h" }, store);
    await saveSshKnownHost({ label: "second", sshUrl: "ssh://h" }, store);
    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(1);
    expect(hosts[0].label).toBe("second");
  });

  it("different sshUrls keep both entries", async () => {
    const store = new MemStore();
    await saveSshKnownHost({ label: "a", sshUrl: "ssh://host-a" }, store);
    await saveSshKnownHost({ label: "b", sshUrl: "ssh://host-b" }, store);
    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(2);
    const labels = hosts.map((h) => h.label).sort();
    expect(labels).toEqual(["a", "b"]);
  });

  it("label collision against an unrelated ssh host gets a sshUrl-derived suffix", async () => {
    const store = new MemStore();
    await saveSshKnownHost({ label: "host", sshUrl: "ssh://a" }, store);
    await saveSshKnownHost({ label: "host", sshUrl: "ssh://b" }, store);
    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(2);
    const labels = hosts.map((h) => h.label).sort();
    expect(labels[0]).toBe("host");
    expect(labels[1]).toMatch(/^host-/);
  });

  it("loadKnownHosts drops a malformed ssh entry (no sshUrl + no other transport)", async () => {
    const store = new MemStore();
    await store.save(
      "hosts",
      new TextEncoder().encode(
        JSON.stringify([
          { label: "ok", sshUrl: "ssh://host" },
          { label: "bad" }, // no sshUrl, no url, no relayUrl
        ]),
      ),
    );
    const hosts = await loadKnownHosts(store);
    expect(hosts.map((h) => h.label)).toEqual(["ok"]);
  });

  it("removeKnownHost drops an ssh entry by label", async () => {
    const store = new MemStore();
    await saveSshKnownHost({ label: "remove-me", sshUrl: "ssh://h" }, store);
    await removeKnownHost("remove-me", store);
    const hosts = await loadKnownHosts(store);
    expect(hosts).toEqual([]);
  });
});

describe("resolveHost — ssh kind", () => {
  it("returns kind:ssh for an ssh-flavored label", async () => {
    const store = new MemStore();
    await saveSshKnownHost({ label: "headless", sshUrl: "ssh://me@h" }, store);
    const resolved = await resolveHost("headless", store);
    expect(resolved.kind).toBe("ssh");
    if (resolved.kind !== "ssh") return;
    expect(resolved.label).toBe("headless");
    expect(resolved.sshUrl).toBe("ssh://me@h");
  });

  it("still returns kind:self for a self-hosted label sharing the same store", async () => {
    const store = new MemStore();
    await saveSshKnownHost({ label: "headless", sshUrl: "ssh://me@h" }, store);
    await saveKnownHost("relay-pin", "http://host:8099#pk.s", store);
    const resolved = await resolveHost("relay-pin", store);
    expect(resolved.kind).toBe("self");
    if (resolved.kind !== "self") return;
    expect(resolved.url).toBe("http://host:8099#pk.s");
  });
});
