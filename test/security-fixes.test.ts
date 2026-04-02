import { describe, it, expect } from "vitest";
import { sanitizeRemoteString } from "../src/sanitize.ts";
import {
  findTokenById,
  findTokenByExactId,
  updateClients,
  loadClients,
  type ClientsData,
} from "../src/relay/clients.ts";
import type { SecretStore } from "../src/storage/secret-store.ts";
import { InitiatorHandshake, ResponderHandshake } from "../src/crypto/noise.ts";
import { ready as sodiumReady } from "../src/crypto/index.ts";
import sodium from "libsodium-wrappers-sumo";

describe("sanitizeRemoteString", () => {
  it("returns empty string for non-strings", () => {
    expect(sanitizeRemoteString(undefined)).toBe("");
    expect(sanitizeRemoteString(null)).toBe("");
    expect(sanitizeRemoteString(42)).toBe("");
    expect(sanitizeRemoteString({})).toBe("");
  });

  it("passes ordinary printable text through unchanged", () => {
    expect(sanitizeRemoteString("iPhone 15 Pro")).toBe("iPhone 15 Pro");
    expect(sanitizeRemoteString("me@example.com")).toBe("me@example.com");
  });

  it("strips ESC and other C0 controls", () => {
    // \x1b[31mRED\x1b[0m — an ANSI color sequence in a "label"
    expect(sanitizeRemoteString("\x1b[31mRED\x1b[0m")).toBe("[31mRED[0m");
    // Carriage return could overwrite previous log output
    expect(sanitizeRemoteString("visible\rhidden")).toBe("visiblehidden");
    // Bell, backspace, form feed
    expect(sanitizeRemoteString("a\x07b\x08c\x0cd")).toBe("abcd");
  });

  it("keeps TAB (0x09) since it's harmless in most renderers", () => {
    expect(sanitizeRemoteString("col1\tcol2")).toBe("col1\tcol2");
  });

  it("strips DEL (0x7F)", () => {
    expect(sanitizeRemoteString("before\x7fafter")).toBe("beforeafter");
  });

  it("strips C1 controls (0x80–0x9F) including OSC-start CSI (0x9B)", () => {
    expect(sanitizeRemoteString("A\x9bB\x9dC")).toBe("ABC");
  });

  it("truncates to maxLen", () => {
    expect(sanitizeRemoteString("x".repeat(1000), 10)).toBe("x".repeat(10));
  });

  it("truncates using the JS string length so budgets are predictable", () => {
    // Emoji like 🔥 take 2 UTF-16 code units each; after maxLen=3 we accept
    // one whole emoji plus stop at the next iteration (out.length already 2,
    // add the next one → 4, which is ≥ 3 → break). Result has 2 emoji.
    const emoji = "🔥";
    const out = sanitizeRemoteString(emoji.repeat(5), 3);
    expect(out).toBe(emoji.repeat(2));
  });
});

// A minimal in-memory SecretStore that satisfies the interface loadClients/
// saveClients use. Enough for testing updateClients's serialization behavior
// without having to stand up the passphrase/keychain backends.
function makeMemoryStore(): SecretStore & { writeCount: number; concurrentWriters: number; maxConcurrent: number } {
  const data = new Map<string, Uint8Array>();
  let writeCount = 0;
  let concurrentWriters = 0;
  let maxConcurrent = 0;

  return {
    async load(name: string): Promise<Uint8Array | null> {
      return data.get(name) ?? null;
    },
    async save(name: string, bytes: Uint8Array): Promise<void> {
      // Instrument save() to detect overlapping writers: if updateClients is
      // serializing correctly, concurrentWriters must never exceed 1.
      concurrentWriters++;
      maxConcurrent = Math.max(maxConcurrent, concurrentWriters);
      try {
        // Yield so multiple save()s can actually overlap if unserialized.
        await new Promise((r) => setTimeout(r, 5));
        data.set(name, bytes);
        writeCount++;
      } finally {
        concurrentWriters--;
      }
    },
    async delete(name: string): Promise<void> {
      data.delete(name);
    },
    async close(): Promise<void> {},
    get writeCount() { return writeCount; },
    get concurrentWriters() { return concurrentWriters; },
    get maxConcurrent() { return maxConcurrent; },
  } as unknown as SecretStore & { writeCount: number; concurrentWriters: number; maxConcurrent: number };
}

describe("findTokenByExactId", () => {
  const data: ClientsData = {
    tokens: [
      { id: "abcdef123456789012345678", label: "first", status: "active", client_id: null, created: "", revoked_at: null },
      { id: "abcdef9999999999999999", label: "second", status: "active", client_id: null, created: "", revoked_at: null },
    ],
  };

  it("finds by exact ID", () => {
    expect(findTokenByExactId(data, "abcdef123456789012345678")?.label).toBe("first");
  });

  it("does NOT match a prefix, no matter how unique", () => {
    // The bug we're closing: the old findTokenById would match "abcdef123" here.
    expect(findTokenByExactId(data, "abcdef123")).toBeUndefined();
  });

  it("does NOT match a unique substring", () => {
    // The old prefix-match helper did match "abcdef1" (unique prefix).
    expect(findTokenByExactId(data, "abcdef1")).toBeUndefined();
  });

  it("returns undefined for empty string", () => {
    expect(findTokenByExactId(data, "")).toBeUndefined();
  });
});

describe("findTokenById (operator CLI — prefix still works)", () => {
  it("still supports unique-prefix match for CLI convenience", () => {
    const data: ClientsData = {
      tokens: [
        { id: "aaaabbbb", label: null, status: "active", client_id: null, created: "", revoked_at: null },
        { id: "ccccdddd", label: null, status: "active", client_id: null, created: "", revoked_at: null },
      ],
    };
    expect(findTokenById(data, "aaaa")?.id).toBe("aaaabbbb");
    expect(findTokenById(data, "cccc")?.id).toBe("ccccdddd");
  });
});

describe("updateClients serialization", () => {
  it("serializes concurrent mutations so writes never interleave", async () => {
    const store = makeMemoryStore();

    // Fire off 20 concurrent mutations that each append a token. If
    // updateClients serializes correctly, every append survives and we end
    // up with exactly 20 tokens. Without serialization, load→modify→save
    // overlaps and later writes clobber earlier ones.
    await Promise.all(
      Array.from({ length: 20 }).map((_, i) =>
        updateClients(store, (d) => {
          d.tokens.push({
            id: `tok-${i}`,
            label: null,
            status: "active",
            client_id: null,
            created: "",
            revoked_at: null,
          });
        })
      )
    );

    const final = await loadClients(store);
    expect(final.tokens).toHaveLength(20);
    // The key invariant: at no point were two save()s in flight simultaneously.
    expect(store.maxConcurrent).toBe(1);
  });

  it("does not deadlock the queue when a mutator throws", async () => {
    const store = makeMemoryStore();

    await expect(
      updateClients(store, () => {
        throw new Error("boom");
      })
    ).rejects.toThrow("boom");

    // Follow-up mutation must still run.
    await updateClients(store, (d) => {
      d.tokens.push({
        id: "post-error",
        label: null,
        status: "active",
        client_id: null,
        created: "",
        revoked_at: null,
      });
    });

    const final = await loadClients(store);
    expect(final.tokens.map((t) => t.id)).toContain("post-error");
  });

  it("returns the mutator's result to the caller", async () => {
    const store = makeMemoryStore();
    const picked = await updateClients(store, () => "hello");
    expect(picked).toBe("hello");
  });
});

describe("Noise readHello/readWelcome defensive-copy", () => {
  it("is not affected by the caller zeroing its input buffer after the call", async () => {
    await sodiumReady();

    // Responder static keypair (libsodium's box_keypair gives us an x25519 pair)
    const s = sodium.crypto_box_keypair();
    const responderStaticPub = new Uint8Array(s.publicKey);
    const responderStaticPriv = new Uint8Array(s.privateKey);

    // Initiator drives the handshake with an ephemeral key.
    const initiator = new InitiatorHandshake(responderStaticPub);
    const hello = initiator.writeHello();

    // The responder receives hello, then the caller reuses (zeroes) its
    // buffer — which used to alias the handshake transcript. After the fix,
    // readHello makes a defensive copy, so mixHash's state is still correct
    // when we compute the welcome.
    const responder = new ResponderHandshake(responderStaticPub, responderStaticPriv);
    responder.readHello(hello);
    hello.fill(0); // caller zeros the buffer

    const { message: welcome, result: respKeys } = responder.writeWelcome();

    // Initiator symmetrically: reads welcome, then caller zeros the input.
    const initKeys = initiator.readWelcome(welcome);
    welcome.fill(0);

    // If the defensive copy worked, the two sides derived matching transport
    // keys (sender/receiver swapped). Confirm by round-tripping an AEAD
    // message end-to-end through the counter-based CipherStates.
    const ad = new Uint8Array();
    const plaintext = new TextEncoder().encode("hi");
    const ciphertext = initKeys.send.encryptWithAd(ad, plaintext);
    const decrypted = respKeys.recv.decryptWithAd(ad, ciphertext);
    expect(new TextDecoder().decode(decrypted)).toBe("hi");
  });
});
