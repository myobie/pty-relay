import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import sodium from "libsodium-wrappers-sumo";
import { ready, generateKeypair, generateSecret, createToken, parseToken } from "../src/crypto/index.ts";
import { recordHostFromParsed } from "../src/commands/connect.ts";
import { loadKnownHosts } from "../src/relay/known-hosts.ts";
import type { SecretName, SecretStore } from "../src/storage/secret-store.ts";

/**
 * Q2 regression tests — known-host entries must only be persisted after
 * the Noise handshake has cryptographically confirmed the daemon's
 * identity. Pre-fix, `connect()` and `connectEmbedded()` saved the host
 * up-front, before any network round-trip; pasting a typo'd token URL
 * polluted the store.
 *
 * Two halves:
 *  1. `recordHostFromParsed` (the helper now gated on `onReady`) records
 *     the entry correctly when called.
 *  2. Structural invariant: every direct `saveKnownHost(` call site in
 *     `src/commands/connect.ts` lives inside `recordHostFromParsed` —
 *     there is no path that saves before the handshake. This is a file-
 *     content assertion rather than a runtime drive of the whole
 *     connect/reconnect loop because that loop is harder to terminate
 *     cleanly from a unit test (interruptible sleeps, no external
 *     cancel hook). If a future change reintroduces an eager save, this
 *     test fails immediately and points at the file.
 */

class MemStore implements SecretStore {
  readonly backend = "passphrase" as const;
  private data = new Map<SecretName, Uint8Array>();
  async load(n: SecretName) { return this.data.get(n) ?? null; }
  async save(n: SecretName, p: Uint8Array) { this.data.set(n, p); }
  async delete(n: SecretName) { this.data.delete(n); }
}

describe("recordHostFromParsed", () => {
  it("saves the parsed host with the canonical base URL (no session segment)", async () => {
    await ready();
    const store = new MemStore();
    const { publicKey } = generateKeypair();
    const secret = generateSecret();
    const tokenUrl = createToken("home.local:8099", publicKey, secret, "some-session");
    const parsed = parseToken(tokenUrl);

    recordHostFromParsed(parsed, store);
    // The helper is fire-and-forget (.catch on the inner save). Yield
    // a microtask so the save promise lands.
    await new Promise((r) => setImmediate(r));

    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(1);
    expect(hosts[0].label).toBe("home.local:8099");
    // The persisted URL strips the session and preserves the parsed
    // clientToken (none in this case).
    const persisted = hosts[0].url!;
    expect(persisted).not.toContain("/some-session");
    const reparsed = parseToken(persisted);
    expect(reparsed.host).toBe("home.local:8099");
    expect(sodium.to_base64(reparsed.publicKey, sodium.base64_variants.URLSAFE_NO_PADDING))
      .toBe(sodium.to_base64(publicKey, sodium.base64_variants.URLSAFE_NO_PADDING));
  });

  it("overwrites the prior entry for the same host (composes with Q1 host-dedup)", async () => {
    await ready();
    const store = new MemStore();
    const oldKey = generateKeypair();
    const newKey = generateKeypair();
    const oldUrl = createToken("home.local:8099", oldKey.publicKey, generateSecret());
    const newUrl = createToken("home.local:8099", newKey.publicKey, generateSecret());

    recordHostFromParsed(parseToken(oldUrl), store);
    await new Promise((r) => setImmediate(r));
    recordHostFromParsed(parseToken(newUrl), store);
    await new Promise((r) => setImmediate(r));

    const hosts = await loadKnownHosts(store);
    expect(hosts.length).toBe(1);
    expect(hosts[0].label).toBe("home.local:8099");
    expect(hosts[0].url).toBe(newUrl);
  });
});

describe("connect.ts save-only-on-success invariant", () => {
  it("the only direct `saveKnownHost(` call site lives inside recordHostFromParsed", () => {
    // Read the connect.ts source. Every `saveKnownHost(` substring must
    // be either (a) the import, (b) inside a comment, or (c) inside the
    // body of `recordHostFromParsed`. If a new eager save reappears,
    // this test pins the regression.
    const src = fs.readFileSync(
      path.join(import.meta.dirname, "..", "src/commands/connect.ts"),
      "utf8"
    );

    const lines = src.split("\n");
    // Find the body of recordHostFromParsed — from its declaration to
    // the matching closing brace.
    const declIdx = lines.findIndex((l) => l.includes("export function recordHostFromParsed"));
    expect(declIdx).toBeGreaterThan(-1);
    let depth = 0;
    let bodyEnd = -1;
    let started = false;
    for (let i = declIdx; i < lines.length; i++) {
      for (const ch of lines[i]) {
        if (ch === "{") { depth++; started = true; }
        else if (ch === "}") {
          depth--;
          if (started && depth === 0) { bodyEnd = i; break; }
        }
      }
      if (bodyEnd !== -1) break;
    }
    expect(bodyEnd).toBeGreaterThan(declIdx);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Strip an inline `//` comment so a commented-out save doesn't
      // trip the assertion.
      const slashIdx = line.indexOf("//");
      const codePart = slashIdx === -1 ? line : line.slice(0, slashIdx);
      if (!codePart.includes("saveKnownHost(")) continue;

      // Allowed: the import line.
      if (codePart.match(/import\s*\{\s*[^}]*saveKnownHost/)) continue;
      // Allowed: inside recordHostFromParsed body.
      if (i >= declIdx && i <= bodyEnd) continue;

      throw new Error(
        `Unexpected direct \`saveKnownHost(\` call site at connect.ts:${i + 1}: ` +
          `${line.trim()}\nAll persistence must go through recordHostFromParsed, ` +
          `which is gated on the post-handshake \`onReady\` callback.`
      );
    }
  });

  it("`saveKnownHost(` is not reachable from the `connect()` entry path before WS open", () => {
    // Stricter slice: lines from the top of `export async function connect`
    // up to (but not including) the `attachSession(` tail. If any direct
    // saveKnownHost or recordHostFromParsed call slips in here, an
    // eager pre-handshake save snuck back in.
    const src = fs.readFileSync(
      path.join(import.meta.dirname, "..", "src/commands/connect.ts"),
      "utf8"
    );
    const lines = src.split("\n");
    const fnStart = lines.findIndex((l) => l.match(/^export async function connect\(/));
    expect(fnStart).toBeGreaterThan(-1);
    const fnEnd = lines.findIndex((l, i) => i > fnStart && l.match(/^\}/));
    expect(fnEnd).toBeGreaterThan(fnStart);

    for (let i = fnStart; i < fnEnd; i++) {
      const line = lines[i];
      const slashIdx = line.indexOf("//");
      const codePart = slashIdx === -1 ? line : line.slice(0, slashIdx);
      expect(codePart.includes("saveKnownHost(")).toBe(false);
      expect(codePart.includes("recordHostFromParsed(")).toBe(false);
    }
  });
});
