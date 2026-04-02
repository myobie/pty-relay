import { Session } from "@myobie/pty/testing";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const CLI_ENTRY = path.resolve(import.meta.dirname, "../../src/cli.ts");

/**
 * Env vars injected into every spawned pty-relay process in integration tests.
 *
 * We force the passphrase backend in integration tests because (a) the
 * existing tests were written against that backend's on-disk format and
 * (b) keychain writes would pollute the developer's real OS keychain on
 * every run. Dedicated keychain tests live in src/storage/keychain-store.test.ts
 * and src/storage/bootstrap.test.ts and clean up after themselves.
 */
export const INTEG_ENV = {
  PTY_RELAY_PASSPHRASE: "test-passphrase",
  PTY_RELAY_KDF_PROFILE: "interactive",
  PTY_RELAY_BACKEND: "passphrase",
};

/** Merge the integration env into a caller's per-process env. */
export function integEnv(extra: Record<string, string> = {}): Record<string, string> {
  return { ...INTEG_ENV, ...extra };
}

export { CLI_ENTRY, Session };

export interface TestContext {
  stateDir: string;
  cleanup: Array<{ close(): Promise<void> | void }>;
}

export function createTestContext(): TestContext {
  // Use /tmp directly instead of os.tmpdir() because macOS resolves tmpdir
  // to /var/folders/... which is too long for Unix socket paths (104 char limit).
  const stateDir = fs.mkdtempSync(path.join("/tmp", "pty-integ-"));
  return { stateDir, cleanup: [] };
}

export function track<T extends { close(): Promise<void> | void }>(
  ctx: TestContext,
  session: T
): T {
  ctx.cleanup.push(session);
  return session;
}

export async function destroyTestContext(ctx: TestContext): Promise<void> {
  for (const s of ctx.cleanup.reverse()) {
    try {
      await s.close();
    } catch {}
  }
  try {
    fs.rmSync(ctx.stateDir, { recursive: true, force: true });
  } catch {}
}

export function extractTokenUrl(screen: { lines: string[]; text: string }): string {
  const joined = screen.lines.join(" ");
  const match = joined.match(
    /(http:\/\/localhost:\d+#[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)/
  );
  if (!match) {
    throw new Error(
      `Could not find token URL in daemon output:\n${screen.text}`
    );
  }
  return match[1];
}

export function tokenWithSession(
  baseToken: string,
  sessionName: string
): string {
  const hashIdx = baseToken.indexOf("#");
  return `${baseToken.slice(0, hashIdx)}/${sessionName}${baseToken.slice(hashIdx)}`;
}

// Find a free port (each test gets its own)
let nextPort = 18100;
export function getPort(): number {
  return nextPort++;
}
