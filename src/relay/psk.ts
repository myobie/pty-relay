/**
 * Pre-shared key loader for `--psk-file` / `PTY_RELAY_PSK` (server and
 * client side). See `docs/psk-auth.md` § "CLI surface (headless-
 * friendly)" for the priority + format contract.
 *
 * Resolution order (first found wins):
 *   1. `opts.pskFile` — absolute or relative path; reads the file's
 *      first line, trims whitespace.
 *   2. `PTY_RELAY_PSK` env var — verbatim (trimmed).
 *
 * Format: exactly `PSK_LEN`-byte (32-byte) URL-safe-base64-no-padding
 * (43 chars: 6 bits × 43 = 258 ≥ 32×8 = 256). Anything else is
 * rejected with a precise error so the operator can fix it without
 * re-reading the design doc.
 *
 * No KDF for v1. PSK is a machine-to-machine secret — treat it like
 * an SSH key (binary, generated, copied). `generatePsk()` produces a
 * spec-shape PSK; `pty-relay psk-gen` exposes it on the CLI.
 */

import * as fs from "node:fs";
import sodium from "libsodium-wrappers-sumo";
import { PSK_LEN } from "../crypto/index.ts";
import { log } from "../log.ts";

export interface LoadPskOptions {
  /** Path to a file whose first line is the 43-char base64url PSK.
   *  Whitespace + a trailing newline are trimmed. Read mode 0600 is
   *  enforced via a stderr warning (not a refusal — operator may
   *  have intentionally relaxed perms for a deploy). */
  pskFile?: string;
  /** Override `process.env.PTY_RELAY_PSK` for tests / non-interactive
   *  callers that want explicit scoping. Defaults to reading the env
   *  var directly. */
  envVar?: string | null;
}

/**
 * Resolve a PSK from the operator's environment. Returns `null` when
 * neither `pskFile` nor `PTY_RELAY_PSK` is present — callers treat
 * that as "PSK auth not configured."
 *
 * Throws (rather than warns) for any of the following — these are
 * misconfigurations the operator must fix, not graceful fallbacks:
 *   - `pskFile` is set but the file doesn't exist or can't be read.
 *   - The decoded byte length isn't `PSK_LEN`.
 *   - The string isn't a valid URL-safe-base64 sequence.
 */
export async function loadPsk(opts: LoadPskOptions = {}): Promise<Uint8Array | null> {
  const env = opts.envVar !== undefined ? opts.envVar : process.env.PTY_RELAY_PSK;

  let source: string;
  let raw: string;

  if (opts.pskFile) {
    source = `--psk-file ${opts.pskFile}`;
    try {
      raw = fs.readFileSync(opts.pskFile, "utf-8");
    } catch (err) {
      throw new Error(
        `--psk-file: cannot read ${opts.pskFile}: ${(err as Error).message}`,
      );
    }
    warnIfWorldReadable(opts.pskFile);
  } else if (typeof env === "string" && env.length > 0) {
    source = "PTY_RELAY_PSK";
    raw = env;
  } else {
    log("psk", "not configured");
    return null;
  }

  // Trim ONE optional trailing newline + any surrounding whitespace.
  // We intentionally don't tolerate embedded whitespace — typos that
  // pasted multi-line garbage should fail, not silently truncate.
  const trimmed = raw.trim();

  if (trimmed.length === 0) {
    throw new Error(`${source}: PSK is empty`);
  }
  if (/\s/.test(trimmed)) {
    throw new Error(
      `${source}: PSK contains whitespace (expected a single 43-char base64url string)`,
    );
  }

  let bytes: Uint8Array;
  try {
    bytes = sodium.from_base64(trimmed, sodium.base64_variants.URLSAFE_NO_PADDING);
  } catch (err) {
    throw new Error(
      `${source}: PSK isn't valid URL-safe-base64-no-padding (${(err as Error).message})`,
    );
  }

  if (bytes.length !== PSK_LEN) {
    throw new Error(
      `${source}: PSK decoded to ${bytes.length} bytes; must be exactly ${PSK_LEN}.\n` +
        `  Generate one with \`pty-relay psk-gen\`.`,
    );
  }

  log("psk", "loaded", {
    source,
    // Don't log the PSK itself, obviously — fingerprint via a
    // hash prefix so two daemons can be eyeballed to "same PSK"
    // without leaking the key.
    fingerprint: pskFingerprint(bytes),
  });
  return bytes;
}

/**
 * Generate a fresh PSK as a 43-char URL-safe-base64-no-padding
 * string. The encoding the operator pastes into `PTY_RELAY_PSK` /
 * writes to a `--psk-file` and that `loadPsk` round-trips back to 32
 * bytes.
 */
export function generatePsk(): string {
  const bytes = sodium.randombytes_buf(PSK_LEN);
  return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
}

/**
 * Short fingerprint of a PSK suitable for logging — a 16-char
 * URL-safe-base64 prefix of `blake2b(psk)`. Lets two daemons confirm
 * "same PSK loaded" without exposing the key itself.
 */
export function pskFingerprint(psk: Uint8Array): string {
  const hash = sodium.crypto_generichash(32, psk, null);
  return sodium
    .to_base64(hash, sodium.base64_variants.URLSAFE_NO_PADDING)
    .slice(0, 16);
}

/** stat the PSK file; warn (don't refuse) if other/group bits are
 *  set. Mirrors openssh's `Permissions for '<file>' are too open`
 *  warning — actionable without being draconian about deploy
 *  configurations where the operator deliberately relaxed perms. */
function warnIfWorldReadable(pskFile: string): void {
  try {
    const stat = fs.statSync(pskFile);
    const otherReadable = (stat.mode & 0o077) !== 0;
    if (otherReadable) {
      process.stderr.write(
        `Warning: ${pskFile} is readable by group/other (mode 0${(stat.mode & 0o777).toString(8)}).\n` +
          `  Tighten with \`chmod 600 ${pskFile}\` — PSK shouldn't be world-readable.\n`,
      );
    }
  } catch {
    // Stat failure isn't actionable for the operator at this point;
    // the actual read above would have surfaced it already.
  }
}
