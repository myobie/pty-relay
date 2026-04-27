/**
 * RFC 6238 TOTP (HMAC-SHA1, 30-second step, 6-digit code) — compatible with
 * the Elixir relay's NimbleTOTP usage in `Relay.TOTP`. Used during daemon
 * signup and preauth minting: the client generates a shared secret locally,
 * authenticator apps consume the otpauth URL (or its QR), and both sides
 * derive the same time-based codes from the secret.
 */

import { createHmac, randomBytes } from "node:crypto";
import { log } from "../log.ts";

const TIME_STEP_SECONDS = 30;
const DIGITS = 6;
const DIGIT_MODULO = 10 ** DIGITS;
const SECRET_BYTES = 20;
const DEFAULT_ISSUER = "pty-relay";

/** Generate a fresh 160-bit random secret (20 bytes). */
export function generateTotpSecret(): Uint8Array {
  return new Uint8Array(randomBytes(SECRET_BYTES));
}

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** RFC 4648 base32, no padding — what NimbleTOTP / authenticator apps expect. */
export function base32Encode(bytes: Uint8Array): string {
  let out = "";
  let bits = 0;
  let value = 0;
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(value >>> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  }
  return out;
}

/** Decode an unpadded RFC 4648 base32 string. Throws on invalid input. */
export function base32Decode(encoded: string): Uint8Array {
  const clean = encoded.replace(/=+$/u, "").toUpperCase();
  const out = new Uint8Array(Math.floor((clean.length * 5) / 8));
  let bits = 0;
  let value = 0;
  let outIdx = 0;
  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i];
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) {
      throw new Error(`base32: invalid character "${ch}" at position ${i}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[outIdx++] = (value >>> bits) & 0xff;
    }
  }
  return out.slice(0, outIdx);
}

/** HOTP / TOTP dynamic truncation per RFC 4226 §5.3. */
function truncate(hmac: Buffer, digits: number): string {
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const mod = bin % 10 ** digits;
  return mod.toString().padStart(digits, "0");
}

/** Generate a TOTP code for a specific point in time. `atSec` defaults to now. */
export function generateTotpCode(secretB32: string, atSec?: number): string {
  const now = atSec ?? Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / TIME_STEP_SECONDS);
  log("totp", "generate code", { counter, atSec: now });

  // 8-byte big-endian counter. JS bitshifts are 32-bit, so split high/low.
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x1_0000_0000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);

  const secret = Buffer.from(base32Decode(secretB32));
  const hmac = createHmac("sha1", secret).update(buf).digest();
  const code = truncate(hmac, DIGITS);

  // Defense-in-depth: padding keeps fixed width but the modulo should
  // already be < 10^6.
  return code.length === DIGITS ? code : (parseInt(code, 10) % DIGIT_MODULO)
    .toString()
    .padStart(DIGITS, "0");
}

/** Build an otpauth:// URI for authenticator apps. Matches the format
 *  `Relay.TOTP.generate_otpauth_url` emits (issuer `pty-relay`). */
export function otpauthUrl(
  secretB32: string,
  email: string,
  issuer: string = DEFAULT_ISSUER
): string {
  const label = encodeURIComponent(`${issuer}:${email}`);
  const params = new URLSearchParams({
    secret: secretB32,
    issuer,
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/** Sleep the minimum time needed so the next `generateTotpCode` call lands
 *  in the next 30-second window. Used during signup to produce two
 *  consecutive codes without the user waiting manually. */
export function secondsUntilNextStep(atSec?: number): number {
  const now = atSec ?? Math.floor(Date.now() / 1000);
  return TIME_STEP_SECONDS - (now % TIME_STEP_SECONDS);
}

/** Produce two TOTP codes from consecutive 30-second windows. Used for
 *  `/api/verify/totp` on first-daemon signup, which requires two codes
 *  to prove the authenticator is set up correctly. */
export function generateConsecutiveCodes(
  secretB32: string,
  atSec?: number
): [string, string] {
  const now = atSec ?? Math.floor(Date.now() / 1000);
  const code1 = generateTotpCode(secretB32, now);
  const code2 = generateTotpCode(secretB32, now + TIME_STEP_SECONDS);
  return [code1, code2];
}
