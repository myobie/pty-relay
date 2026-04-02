/**
 * Global vitest setup — runs before every test file.
 *
 * Argon2id at production params is ~0.7s per derivation; we use INTERACTIVE
 * profile (~50ms) across the test suite so the storage stack stays fast.
 */
import * as fs from "node:fs";
import * as path from "node:path";

process.env.PTY_RELAY_KDF_PROFILE = "interactive";

// Every test that bootstraps via openSecretStore needs a passphrase. Set a
// default here so tests can still override if they need to.
if (!process.env.PTY_RELAY_PASSPHRASE) {
  process.env.PTY_RELAY_PASSPHRASE = "test-passphrase";
}

// Isolate from the developer's real pty sessions: if PTY_SESSION_DIR isn't
// already pointing somewhere test-specific, redirect it to a throwaway temp
// directory. Without this, any test that reaches the pty daemon/client would
// read/write the user's actual session state under ~/.local/state/pty.
if (!process.env.PTY_SESSION_DIR) {
  process.env.PTY_SESSION_DIR = fs.mkdtempSync(path.join("/tmp", "pty-relay-unit-"));
}
