import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { localResetCommand } from "../src/commands/local/reset.ts";

/**
 * `pty-relay local reset` deletes self-hosted daemon state (config,
 * clients, auth, daemon.pid) and leaves the other files alone. These
 * tests run against a fresh tmpdir with a fake marker + representative
 * files for each secret — we're verifying selection, not a real
 * signin/start cycle.
 */

const SELF_HOSTED_FILES = ["config.json", "clients.json", "auth.json"];
const PRESERVED_FILES = ["hosts", "public-account.json", "storage.json"];
const ALL_FILES = [...SELF_HOSTED_FILES, ...PRESERVED_FILES, "daemon.pid"];

describe("localResetCommand", () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "pty-relay-local-reset-"));
    // Write a passphrase-backend marker so no keychain probing happens.
    fs.writeFileSync(
      path.join(dir, "storage.json"),
      JSON.stringify({ backend: "passphrase", salt: "x".repeat(40) })
    );
    for (const name of ALL_FILES) {
      if (name === "storage.json") continue;
      fs.writeFileSync(path.join(dir, name), `fake ${name}`);
    }
  });

  afterEach(() => {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {}
  });

  it("with --force: deletes self-hosted files, preserves the rest", async () => {
    await localResetCommand({ configDir: dir, force: true });

    for (const name of SELF_HOSTED_FILES) {
      expect(
        fs.existsSync(path.join(dir, name)),
        `${name} should be deleted`
      ).toBe(false);
    }
    expect(fs.existsSync(path.join(dir, "daemon.pid"))).toBe(false);

    for (const name of PRESERVED_FILES) {
      expect(
        fs.existsSync(path.join(dir, name)),
        `${name} should be preserved`
      ).toBe(true);
    }
  });

  it("no-ops cleanly when the config dir has no self-hosted state", async () => {
    for (const name of SELF_HOSTED_FILES) {
      fs.rmSync(path.join(dir, name), { force: true });
    }
    fs.rmSync(path.join(dir, "daemon.pid"), { force: true });

    const before = fs.readdirSync(dir).sort();
    await localResetCommand({ configDir: dir, force: true });
    const after = fs.readdirSync(dir).sort();

    expect(after).toEqual(before);
  });

  it("no-ops cleanly when the config dir doesn't exist", async () => {
    const missing = path.join(dir, "does-not-exist");
    // Should not throw, should not create the directory.
    await localResetCommand({ configDir: missing, force: true });
    expect(fs.existsSync(missing)).toBe(false);
  });

  it("rejects without --force on a non-TTY stdin", async () => {
    // Non-TTY + no --force should exit with code 1 before touching anything.
    const origExit = process.exit;
    const origIsTTY = process.stdin.isTTY;
    let exitCode: number | undefined;
    (process as any).exit = (code?: number) => {
      exitCode = code;
      throw new Error("__exit");
    };
    (process.stdin as any).isTTY = false;
    try {
      await expect(
        localResetCommand({ configDir: dir, force: false })
      ).rejects.toThrow("__exit");
      expect(exitCode).toBe(1);
      // No files were touched.
      for (const name of SELF_HOSTED_FILES) {
        expect(fs.existsSync(path.join(dir, name))).toBe(true);
      }
    } finally {
      (process as any).exit = origExit;
      (process.stdin as any).isTTY = origIsTTY;
    }
  });
});
