import sodium from "libsodium-wrappers-sumo";
import type { SecretStore } from "./secret-store.ts";

/**
 * Per-device state for a relay account.
 *
 * A device can hold a daemon key, a client key, or both:
 *   - **Daemon key**  — authorizes `server start` (primary WS +
 *     per-client responders), plus account-management endpoints
 *     (`/api/keys/revoke`, `/api/pairing_hashes/mint`, `/api/acls`, …).
 *     Authenticates `role=daemon` WS upgrades.
 *   - **Client key**  — authorizes session commands (`ls` / `peek` /
 *     `send` / `tag` / `events` / `connect`). Authenticates
 *     `role=client_pair` WS upgrades.
 *
 * The relay enforces these roles strictly: a daemon key can't open
 * `role=client_pair` and a client key can't open `role=daemon` or
 * call mint/revoke/ACL endpoints. A single device that does both
 * must hold both keys.
 *
 * At least one of `daemonKey` / `clientKey` is always present after
 * enrollment. `signup` creates both; `join --role X` creates one.
 *
 * Base64url encoding (no padding) everywhere pubkey/secret bytes
 * cross a boundary — matches the Elixir relay's `Base.url_encode64`
 * with `padding: false`.
 */
export interface PublicAccount {
  /** Relay origin, e.g. `http://localhost:4000` — scheme + host + port
   *  only, no trailing slash. */
  relayUrl: string;
  /** Primary email address on the account. Empty on devices that joined
   *  via preauth without learning the account email. */
  email: string;
  /** Relay-issued account id (ULID). */
  accountId: string;
  /** Human-readable label the operator set on enrollment. Used as the
   *  key's `label` on both daemon and client rows. */
  label: string;
  /** Shared TOTP secret, unpadded base32. Present only on devices that
   *  own the secret (signup device). Joined devices leave it unset;
   *  account-management flows requiring TOTP must run on the signup
   *  device (or a device that later gained the secret via sync — not
   *  implemented). */
  totpSecretB32?: string;
  /** Daemon identity, if this device serves / manages the account. */
  daemonKey?: KeyIdentity;
  /** Client identity, if this device consumes sessions. */
  clientKey?: KeyIdentity;
}

export interface KeyIdentity {
  /** Ed25519 keypair, base64url (no padding). Public is 32 bytes
   *  encoded; secret is 64 bytes (libsodium seed+public) encoded. */
  signingKeys: { public: string; secret: string };
  /** Relay-returned identifier for this registered key. The relay uses
   *  this as an opaque id; most client code just re-sends the pubkey
   *  instead (also unique). Stored for parity with the relay's rows. */
  registeredKeyId: string;
  /** ISO 8601 enrollment timestamp. */
  enrolledAt: string;
  /** Set only on client keys claimed via a preauth. The relay binds
   *  such keys to the minting daemon's stable identity id; at
   *  `role=client_pair` time, attempts to pair with any other daemon
   *  on the account return 403. Clients registered via
   *  `client signin` have no pin (account-wide reach). Daemon keys
   *  never have this field.
   *
   *  `identityId` is authoritative and survives daemon key rotations.
   *  `label` / `publicKey` are display hints captured at claim time;
   *  the pubkey goes stale after the pinned daemon rotates (fine —
   *  the relay enforces by identity, the display is best-effort). */
  pin?: {
    daemonIdentityId: string;
    daemonLabel: string;
    daemonPublicKey: string;
  };
  /** Set while a two-step rotation is in progress for THIS role's key.
   *  `rotate` / `rotate --complete` on each role operates on its own
   *  pending record; a daemon rotation doesn't touch the client key. */
  pendingRotation?: {
    oldPublicB64: string;
    oldSecretB64: string;
    newPublicB64: string;
    newSecretB64: string;
    /** ISO 8601 timestamp of `rotate` (without --complete). */
    startedAt: string;
  };
}

/** Raw-bytes view of a KeyIdentity. Handy because signing /
 *  scalarmult / libsodium calls all want Uint8Arrays, not base64url. */
export interface KeyIdentityRaw {
  public: Uint8Array;
  secret: Uint8Array;
}

/** Decode a KeyIdentity's base64url keys into Uint8Array form. */
export function decodeKey(k: KeyIdentity): KeyIdentityRaw {
  return {
    public: sodium.from_base64(
      k.signingKeys.public,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
    secret: sodium.from_base64(
      k.signingKeys.secret,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
  };
}

/** Fetch the daemon key or throw a user-readable error. */
export function requireDaemonKey(a: PublicAccount): KeyIdentity {
  if (!a.daemonKey) {
    throw new Error(
      "This device has no daemon key on this account.\n" +
        "Run `pty-relay server signin --email <addr>` to register one."
    );
  }
  return a.daemonKey;
}

/** Fetch the client key or throw a user-readable error. */
export function requireClientKey(a: PublicAccount): KeyIdentity {
  if (!a.clientKey) {
    throw new Error(
      "This device has no client key on this account.\n" +
        "Run `pty-relay client signin --email <addr>` to register one (account-wide), or claim a preauth with `pty-relay server join <url>` (daemon-pinned)."
    );
  }
  return a.clientKey;
}

function isKeyIdentity(v: unknown): v is KeyIdentity {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  if (!o.signingKeys || typeof o.signingKeys !== "object") return false;
  const k = o.signingKeys as Record<string, unknown>;
  if (typeof k.public !== "string" || typeof k.secret !== "string") return false;
  if (typeof o.registeredKeyId !== "string") return false;
  if (typeof o.enrolledAt !== "string") return false;
  return true;
}

function isPublicAccount(obj: unknown): obj is PublicAccount {
  if (!obj || typeof obj !== "object") return false;
  const o = obj as Record<string, unknown>;
  if (typeof o.relayUrl !== "string") return false;
  if (typeof o.email !== "string") return false;
  if (typeof o.accountId !== "string") return false;
  if (typeof o.label !== "string") return false;
  if (
    o.totpSecretB32 !== undefined &&
    typeof o.totpSecretB32 !== "string"
  ) {
    return false;
  }
  if (o.daemonKey !== undefined && !isKeyIdentity(o.daemonKey)) return false;
  if (o.clientKey !== undefined && !isKeyIdentity(o.clientKey)) return false;
  // At least one role must be present — a keyless account record is
  // invalid. Guards against partial writes leaving unusable state.
  if (!o.daemonKey && !o.clientKey) return false;
  return true;
}

export async function loadPublicAccount(
  store: SecretStore
): Promise<PublicAccount | null> {
  const bytes = await store.load("public_account");
  if (!bytes) return null;
  try {
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    return isPublicAccount(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export async function savePublicAccount(
  account: PublicAccount,
  store: SecretStore
): Promise<void> {
  const bytes = new TextEncoder().encode(JSON.stringify(account));
  await store.save("public_account", bytes);
}

export async function clearPublicAccount(store: SecretStore): Promise<void> {
  await store.delete("public_account");
}
