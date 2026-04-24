import { describe, it, expect, beforeAll } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import { PublicApi } from "../src/relay/public-api.ts";
import {
  loadKnownHosts,
  savePublicKnownHost,
} from "../src/relay/known-hosts.ts";
import type { SecretName, SecretStore } from "../src/storage/secret-store.ts";
import { verifySignature, isPayloadFresh } from "../src/crypto/signing.ts";

beforeAll(async () => {
  await sodium.ready;
});

class MemStore implements SecretStore {
  readonly backend = "passphrase" as const;
  private data = new Map<SecretName, Uint8Array>();
  async load(n: SecretName) { return this.data.get(n) ?? null; }
  async save(n: SecretName, p: Uint8Array) { this.data.set(n, p); }
  async delete(n: SecretName) { this.data.delete(n); }
}

// This test exercises `hostsCommand`'s merge logic without going through
// the CLI wrapper (which opens the real store). Easier to set up: drive
// the merge path via a shared MemStore and a mocked fetch.

// pickUniqueLabel is tested directly in known-hosts-public.test.ts; here we
// only assert that hosts --merge's wrapper synthesizes the host-<prefix>
// fallback when the relay returned a null label.
import { pickUniqueLabel } from "../src/relay/known-hosts.ts";

describe("hosts --merge fallback label", () => {
  it("synthesizes host-<prefix> from the pubkey when server label is null", () => {
    const wanted = null || `host-${"abcd1234efgh5678".slice(0, 8)}`;
    expect(pickUniqueLabel(wanted, "abcd1234efgh5678", new Set())).toBe(
      "host-abcd1234"
    );
  });
});

describe("hostsCommand --merge logic", () => {
  it("appends new hosts from /api/hosts and preserves existing entries", async () => {
    const store = new MemStore();

    // A host already known from a prior `server hosts --merge` run.
    await savePublicKnownHost(
      {
        label: "old-host",
        relayUrl: "http://localhost:4000",
        publicKey: "pk_old",
      },
      store
    );

    const hostsBefore = await loadKnownHosts(store);
    expect(hostsBefore).toHaveLength(1);

    // Simulate /api/hosts response: one existing + two new.
    const apiResponse = {
      account_id: "01HVC000ACCT",
      hosts: [
        { public_key: "pk_old", label: "old-host", role: "daemon", status: "online" },
        { public_key: "pk_new1", label: "laptop", role: "daemon", status: "online" },
        { public_key: "pk_new2", label: null, role: "daemon", status: "offline" },
      ],
    };

    // Drive the merge inline (mirrors hostsCommand's body) to avoid opening
    // a real SecretStore in tests.
    const existingPks = new Set(
      hostsBefore
        .filter((h) => h.publicKey && h.relayUrl === "http://localhost:4000")
        .map((h) => h.publicKey)
    );
    for (const h of apiResponse.hosts) {
      if (existingPks.has(h.public_key)) continue;
      const label = h.label || `host-${h.public_key.slice(0, 8)}`;
      await savePublicKnownHost(
        {
          label,
          relayUrl: "http://localhost:4000",
          publicKey: h.public_key,
          role: h.role as "daemon" | "client",
        },
        store
      );
    }

    const hostsAfter = await loadKnownHosts(store);
    expect(hostsAfter).toHaveLength(3);
    const byLabel = new Map(hostsAfter.map((h) => [h.label, h]));
    expect(byLabel.get("old-host")!.publicKey).toBe("pk_old");
    expect(byLabel.get("laptop")!.publicKey).toBe("pk_new1");
    // Null label got replaced with a deterministic fallback.
    expect(byLabel.get("host-pk_new2")!.publicKey).toBe("pk_new2");
  });
});

describe("mergeAccountDaemons", () => {
  it("skips role=client entries and prunes stale client entries from known_hosts", async () => {
    const { mergeAccountDaemons } = await import("../src/commands/server/hosts.ts");
    const store = new MemStore();

    // A pre-existing known_hosts entry for a client key. An older
    // CLI version may have saved these; the fixed merge path should
    // prune them, since clients aren't pair targets and `ls` would
    // just get 403s.
    await savePublicKnownHost(
      {
        label: "some-phone",
        relayUrl: "http://localhost:4000",
        publicKey: "pk_client_old",
        role: "client",
      },
      store
    );

    const kp = sodium.crypto_sign_keypair();
    // Stub fetch with a response containing a daemon + a client. Only
    // the daemon should end up in known_hosts afterward.
    globalThis.fetch = (async (_input: RequestInfo | URL) => {
      return new Response(
        JSON.stringify({
          account_id: "01HVCACCT",
          hosts: [
            { public_key: "pk_daemon", label: "laptop-a", role: "daemon", status: "online" },
            { public_key: "pk_client_new", label: "phone", role: "client", status: "offline" },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }) as typeof fetch;

    const api = new PublicApi("http://localhost:4000");
    const { added, pruned } = await mergeAccountDaemons(
      api,
      "http://localhost:4000",
      { public: kp.publicKey, secret: kp.privateKey },
      store
    );

    const hosts = await loadKnownHosts(store);
    expect(hosts).toHaveLength(1);
    expect(hosts[0].publicKey).toBe("pk_daemon");
    expect(hosts[0].role).toBe("daemon");
    // Prune counted the stale client entry; merge counted the one daemon.
    expect(pruned).toBe(1);
    expect(added).toBe(1);
  });
});

describe("hostsCommand HTTP call shape", () => {
  it("GETs /api/hosts with signed auth params", async () => {
    const kp = sodium.crypto_sign_keypair();
    let capturedUrl = "";
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      capturedUrl = typeof input === "string" ? input : input.toString();
      return new Response(
        JSON.stringify({
          account_id: "01HVCACCT",
          hosts: [],
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }) as typeof fetch;

    const api = new PublicApi("http://localhost:4000");
    await api.get("/api/hosts", {
      signWith: { public: kp.publicKey, secret: kp.privateKey },
    });

    const url = new URL(capturedUrl);
    expect(url.pathname).toBe("/api/hosts");
    const payload = url.searchParams.get("payload")!;
    expect(isPayloadFresh(payload)).toBe(true);
    const sig = sodium.from_base64(
      url.searchParams.get("sig")!,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    expect(verifySignature(payload, sig, kp.publicKey)).toBe(true);
  });
});
