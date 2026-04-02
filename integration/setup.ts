/**
 * Integration test setup: sets env vars that flow down to every spawned
 * pty-relay process. Argon2id INTERACTIVE profile keeps KDF fast; fixed
 * passphrase lets all tests share the same credentials; forcing the
 * passphrase backend keeps tests out of the developer's real OS keychain.
 *
 * Keychain coverage lives in src/storage/keychain-store.test.ts and
 * src/storage/bootstrap.test.ts, which properly clean up after themselves.
 */
import * as fs from "node:fs";
import * as path from "node:path";

process.env.PTY_RELAY_KDF_PROFILE = "interactive";
process.env.PTY_RELAY_PASSPHRASE = "test-passphrase";
process.env.PTY_RELAY_BACKEND = "passphrase";

// Safety net: if a test forgets to override PTY_SESSION_DIR in beforeEach,
// don't fall back to the developer's real ~/.local/state/pty directory.
if (!process.env.PTY_SESSION_DIR) {
  process.env.PTY_SESSION_DIR = fs.mkdtempSync(path.join("/tmp", "pty-integ-fallback-"));
}
