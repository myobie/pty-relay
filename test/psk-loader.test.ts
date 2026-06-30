import { describe, it, expect, beforeEach, afterEach, beforeAll, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import sodium from "libsodium-wrappers-sumo";
import {
  loadPsk,
  generatePsk,
  pskFingerprint,
} from "../src/relay/psk.ts";
import { PSK_LEN, ready } from "../src/crypto/index.ts";

beforeAll(async () => {
  await ready();
});

let dir: string;
let stderrSpy: ReturnType<typeof vi.spyOn>;
let stderrBytes: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "psk-loader-"));
  stderrBytes = "";
  stderrSpy = vi
    .spyOn(process.stderr, "write")
    .mockImplementation((chunk: string | Uint8Array) => {
      stderrBytes += typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk);
      return true;
    });
});

afterEach(() => {
  stderrSpy.mockRestore();
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
});

function writePskFile(name: string, contents: string, mode = 0o600): string {
  const p = path.join(dir, name);
  fs.writeFileSync(p, contents, { mode });
  return p;
}

describe("generatePsk", () => {
  it("produces a 43-char URL-safe-base64-no-padding string", () => {
    const psk = generatePsk();
    expect(psk.length).toBe(43);
    expect(psk).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("decodes back to exactly PSK_LEN bytes", () => {
    const psk = generatePsk();
    const bytes = sodium.from_base64(psk, sodium.base64_variants.URLSAFE_NO_PADDING);
    expect(bytes.length).toBe(PSK_LEN);
  });

  it("generates a different value each call (sanity check on RNG)", () => {
    const a = generatePsk();
    const b = generatePsk();
    expect(a).not.toBe(b);
  });
});

describe("pskFingerprint", () => {
  it("returns a stable 16-char string for the same PSK", () => {
    const bytes = sodium.randombytes_buf(PSK_LEN);
    const a = pskFingerprint(bytes);
    const b = pskFingerprint(bytes);
    expect(a).toBe(b);
    expect(a.length).toBe(16);
  });

  it("differs for different PSKs", () => {
    const a = pskFingerprint(sodium.randombytes_buf(PSK_LEN));
    const b = pskFingerprint(sodium.randombytes_buf(PSK_LEN));
    expect(a).not.toBe(b);
  });
});

describe("loadPsk — resolution order", () => {
  it("returns null when neither --psk-file nor PTY_RELAY_PSK is set", async () => {
    const result = await loadPsk({ envVar: null });
    expect(result).toBeNull();
  });

  it("prefers --psk-file over PTY_RELAY_PSK", async () => {
    const filePsk = generatePsk();
    const envPsk = generatePsk();
    const p = writePskFile("psk", filePsk);
    const result = await loadPsk({ pskFile: p, envVar: envPsk });
    expect(result).not.toBeNull();
    // Compare via fingerprint — easier than asserting array equality.
    expect(pskFingerprint(result!)).toBe(
      pskFingerprint(
        sodium.from_base64(filePsk, sodium.base64_variants.URLSAFE_NO_PADDING),
      ),
    );
  });

  it("falls back to PTY_RELAY_PSK when --psk-file is absent", async () => {
    const envPsk = generatePsk();
    const result = await loadPsk({ envVar: envPsk });
    expect(result).not.toBeNull();
    expect(pskFingerprint(result!)).toBe(
      pskFingerprint(
        sodium.from_base64(envPsk, sodium.base64_variants.URLSAFE_NO_PADDING),
      ),
    );
  });

  it("treats empty env var as not-configured", async () => {
    const result = await loadPsk({ envVar: "" });
    expect(result).toBeNull();
  });
});

describe("loadPsk — format validation", () => {
  it("trims a trailing newline in the file", async () => {
    const psk = generatePsk();
    const p = writePskFile("psk", psk + "\n");
    const result = await loadPsk({ pskFile: p, envVar: null });
    expect(result).not.toBeNull();
    expect(result!.length).toBe(PSK_LEN);
  });

  it("trims surrounding whitespace", async () => {
    const psk = generatePsk();
    const p = writePskFile("psk", `  ${psk}  \n`);
    const result = await loadPsk({ pskFile: p, envVar: null });
    expect(result).not.toBeNull();
  });

  it("rejects an empty PSK", async () => {
    const p = writePskFile("psk", "");
    await expect(loadPsk({ pskFile: p, envVar: null })).rejects.toThrow(
      /PSK is empty/,
    );
  });

  it("rejects a whitespace-only PSK", async () => {
    const p = writePskFile("psk", "   \n");
    await expect(loadPsk({ pskFile: p, envVar: null })).rejects.toThrow(
      /PSK is empty/,
    );
  });

  it("rejects embedded whitespace (multi-line / mangled paste)", async () => {
    const p = writePskFile("psk", "abc def\n");
    await expect(loadPsk({ pskFile: p, envVar: null })).rejects.toThrow(
      /contains whitespace/,
    );
  });

  it("rejects non-base64url content", async () => {
    const p = writePskFile("psk", "not_base64_$$$\n");
    await expect(loadPsk({ pskFile: p, envVar: null })).rejects.toThrow(
      /valid URL-safe-base64-no-padding/,
    );
  });

  it("rejects a too-short PSK (decoded < 32 bytes)", async () => {
    // 8 random bytes → ~11-char b64.
    const short = sodium.to_base64(
      sodium.randombytes_buf(8),
      sodium.base64_variants.URLSAFE_NO_PADDING,
    );
    const p = writePskFile("psk", short);
    await expect(loadPsk({ pskFile: p, envVar: null })).rejects.toThrow(
      /must be exactly 32/,
    );
  });

  it("rejects a too-long PSK (decoded > 32 bytes)", async () => {
    const long = sodium.to_base64(
      sodium.randombytes_buf(64),
      sodium.base64_variants.URLSAFE_NO_PADDING,
    );
    const p = writePskFile("psk", long);
    await expect(loadPsk({ pskFile: p, envVar: null })).rejects.toThrow(
      /must be exactly 32/,
    );
  });

  it("rejects a PSK file that doesn't exist", async () => {
    await expect(
      loadPsk({ pskFile: path.join(dir, "nope"), envVar: null }),
    ).rejects.toThrow(/cannot read/);
  });

  it("rejects env PSK with bad format too", async () => {
    await expect(
      loadPsk({ envVar: "not_base64_$$$" }),
    ).rejects.toThrow(/valid URL-safe-base64-no-padding/);
  });
});

describe("loadPsk — file mode warning", () => {
  it("warns to stderr when the PSK file is world-readable (mode 0644)", async () => {
    const psk = generatePsk();
    const p = writePskFile("psk", psk, 0o644);
    await loadPsk({ pskFile: p, envVar: null });
    expect(stderrBytes).toMatch(/readable by group\/other/);
    expect(stderrBytes).toContain(p);
  });

  it("does NOT warn when the file is mode 0600", async () => {
    const psk = generatePsk();
    const p = writePskFile("psk", psk, 0o600);
    await loadPsk({ pskFile: p, envVar: null });
    expect(stderrBytes).toBe("");
  });

  it("the warning is informational — load still succeeds", async () => {
    const psk = generatePsk();
    const p = writePskFile("psk", psk, 0o644);
    const result = await loadPsk({ pskFile: p, envVar: null });
    expect(result).not.toBeNull();
  });
});
