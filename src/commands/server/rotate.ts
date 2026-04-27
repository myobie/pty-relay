import sodium from "libsodium-wrappers-sumo";
import { ready } from "../../crypto/index.ts";
import { openSecretStore } from "../../storage/bootstrap.ts";
import { log } from "../../log.ts";
import {
  loadPublicAccount,
  savePublicAccount,
  type PublicAccount,
  type KeyIdentity,
} from "../../storage/public-account.ts";
import { PublicApi, PublicApiError } from "../../relay/public-api.ts";
import { savePublicKnownHost, removeKnownHost } from "../../relay/known-hosts.ts";
import { generateSigningKeypair } from "../../crypto/keys.ts";

/** Two-step Ed25519 key rotation for one of this device's role-scoped
 *  account keys. Daemon and client keys rotate independently — call
 *  `pty-relay server rotate --role daemon` (or `--role client`) to pick.
 *
 * Step 1 (`--start`, the default): generate a fresh keypair, call
 *   /api/keys/rotate/start signed with the OLD key for that role. Relay
 *   marks the old key "deprecated" and creates the new key "active".
 *   The new keypair is persisted alongside the old one so both can
 *   sign during the transition.
 *
 * Step 2 (`--complete`): call /api/keys/rotate/complete signed with
 *   the NEW key, passing old_public_key. Relay revokes the old key.
 *   Locally, drop the old key material and keep only the new.
 */

interface RotateStartResponse {
  old_key: string;
  new_key: string;
  old_status: string; // "deprecated" after success
}
interface RotateCompleteResponse {
  status: "completed";
  revoked_key: string;
}

type Role = "daemon" | "client";

/** How long a half-started rotation stays valid. Past this, the next
 *  `server rotate` call treats the old pending record as abandoned and
 *  lets the user start fresh; `server rotate --complete` refuses
 *  because the relay-side "deprecated" window is effectively spent. */
const PENDING_ROTATION_TTL_MS = 24 * 60 * 60 * 1000;

/** Classify a pending record's age. `startedAt` is a wall-clock ISO
 *  timestamp, so clock skew (NTP jumps, manual reset) can produce
 *  negative ages or implausibly far futures. We treat any of those
 *  as "skew — tell the operator to reset and start over" rather than
 *  silently trusting the timestamp and blocking rotations forever. */
type PendingStatus =
  | { kind: "valid"; ageMs: number }
  | { kind: "expired" }
  | { kind: "skew"; reason: string };

function classifyPending(startedAtIso: string): PendingStatus {
  const startedAt = Date.parse(startedAtIso);
  if (!isFinite(startedAt)) {
    return { kind: "skew", reason: `unparseable startedAt "${startedAtIso}"` };
  }
  const ageMs = Date.now() - startedAt;
  if (ageMs < 0) {
    return {
      kind: "skew",
      reason: `startedAt is in the future by ${Math.ceil(-ageMs / 60_000)} minutes — clock moved backward?`,
    };
  }
  // Sanity-cap: anything older than 30 days is almost certainly
  // garbage (forgotten rotation + clock jump). Surface as skew so the
  // operator gets a clear message instead of just the normal
  // "expired" notice (which says the relay window is spent, which
  // may or may not be true).
  if (ageMs > 30 * 24 * 60 * 60 * 1000) {
    return {
      kind: "skew",
      reason: `startedAt is ${Math.ceil(ageMs / (24 * 60 * 60 * 1000))} days ago; likely stale`,
    };
  }
  if (ageMs > PENDING_ROTATION_TTL_MS) return { kind: "expired" };
  return { kind: "valid", ageMs };
}

function skewInstructions(): string {
  return (
    "Clock skew detected on the pending rotation record.\n" +
    "To recover: run `pty-relay reset` (destroys this device's credentials,\n" +
    "then sign up / join again) OR hand-edit public-account.json in the\n" +
    "config dir and delete the role's `pendingRotation` field."
  );
}

/** Extract the KeyIdentity for the requested role, or exit with a
 *  user-readable error if this device doesn't hold that role. */
function requireRoleKey(account: PublicAccount, role: Role): KeyIdentity {
  const key = role === "daemon" ? account.daemonKey : account.clientKey;
  if (!key) {
    console.error(
      `This device has no ${role} key on this account.\n` +
        `Run \`pty-relay server rotate --role ${role === "daemon" ? "client" : "daemon"}\` instead, ` +
        `or enroll a ${role} key on this device first.`
    );
    process.exit(1);
  }
  return key;
}

/** Rewrite the account record replacing the key for one role. */
function withRoleKey(
  account: PublicAccount,
  role: Role,
  key: KeyIdentity
): PublicAccount {
  return {
    ...account,
    daemonKey: role === "daemon" ? key : account.daemonKey,
    clientKey: role === "client" ? key : account.clientKey,
  };
}

export async function rotateCommand(opts: {
  role: Role;
  complete?: boolean;
  configDir?: string;
  passphraseFile?: string;
}): Promise<void> {
  await ready();
  log("cli", "server rotate begin", { role: opts.role, complete: !!opts.complete });
  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });
  const loaded = await loadPublicAccount(store);
  if (!loaded) {
    console.error("Not enrolled on any public relay.");
    process.exit(1);
    return;
  }
  const account = loaded;

  const api = new PublicApi(account.relayUrl);

  if (opts.complete) {
    await doComplete(account, opts.role, api, store);
  } else {
    await doStart(account, opts.role, api, store);
  }
}

async function doStart(
  account: PublicAccount,
  role: Role,
  api: PublicApi,
  store: import("../../storage/secret-store.ts").SecretStore
): Promise<void> {
  const roleKey = requireRoleKey(account, role);
  if (roleKey.pendingRotation) {
    const status = classifyPending(roleKey.pendingRotation.startedAt);
    if (status.kind === "skew") {
      console.error(`${status.reason}\n\n${skewInstructions()}`);
      process.exit(1);
    }
    if (status.kind === "valid") {
      const ageMs = status.ageMs;
      const hoursLeft = Math.ceil(
        (PENDING_ROTATION_TTL_MS - ageMs) / (60 * 60 * 1000)
      );
      console.error(
        `A ${role} rotation is already in progress (${Math.floor(ageMs / 60_000)}m ago; valid ~${hoursLeft}h more).\n` +
          `Run \`pty-relay server rotate --role ${role} --complete\` to finish it, or wait for it to expire.`
      );
      process.exit(1);
    }
    // Expired: fall through; the new `rotate` will overwrite. Don't
    // auto-undo the relay-side deprecated state — the operator should
    // know they're starting over.
    console.warn(
      `Previous ${role} rotation attempt was abandoned (> 24h ago); starting fresh.`
    );
  }

  const oldKeys = {
    public: sodium.from_base64(
      roleKey.signingKeys.public,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
    secret: sodium.from_base64(
      roleKey.signingKeys.secret,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
  };

  // Fresh keypair for the replacement.
  const { signPublicKey, signSecretKey } = generateSigningKeypair();
  const newPublicB64 = sodium.to_base64(
    signPublicKey,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );
  const newSecretB64 = sodium.to_base64(
    signSecretKey,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );

  try {
    const res = await api.post<RotateStartResponse>(
      "/api/keys/rotate/start",
      { new_public_key: newPublicB64 },
      { signWith: oldKeys }
    );
    console.log(`Old ${role} key marked ${res.old_status}: ${res.old_key}`);
    console.log(`New ${role} key active:                ${res.new_key}`);

    // Persist the pending pair on this role's KeyIdentity. Don't switch
    // active keys yet — the old key is still the canonical identity
    // until --complete runs.
    const updatedKey: KeyIdentity = {
      ...roleKey,
      pendingRotation: {
        oldPublicB64: roleKey.signingKeys.public,
        oldSecretB64: roleKey.signingKeys.secret,
        newPublicB64,
        newSecretB64,
        startedAt: new Date().toISOString(),
      },
    };
    await savePublicAccount(withRoleKey(account, role, updatedKey), store);

    console.log("");
    console.log(`Next step: \`pty-relay server rotate --role ${role} --complete\``);
    console.log("(Both keys remain valid until complete.)");
  } catch (err: any) {
    if (err instanceof PublicApiError) {
      console.error(`rotate start failed: ${err.message} (HTTP ${err.status})`);
    } else {
      console.error(`rotate start failed: ${err?.message ?? err}`);
    }
    process.exit(1);
  }
}

async function doComplete(
  account: PublicAccount,
  role: Role,
  api: PublicApi,
  store: import("../../storage/secret-store.ts").SecretStore
): Promise<void> {
  const roleKey = requireRoleKey(account, role);
  if (!roleKey.pendingRotation) {
    console.error(
      `No ${role} rotation in progress. Run \`pty-relay server rotate --role ${role}\` (without --complete) to start one.`
    );
    process.exit(1);
    return;
  }
  const pending = roleKey.pendingRotation;

  const status = classifyPending(pending.startedAt);
  if (status.kind === "skew") {
    console.error(`${status.reason}\n\n${skewInstructions()}`);
    process.exit(1);
    return;
  }
  if (status.kind === "expired") {
    console.error(
      `The pending ${role} rotation is older than 24h; the relay-side deprecated window is spent.\n` +
        `Run \`pty-relay server rotate --role ${role}\` (without --complete) to start a fresh rotation.`
    );
    process.exit(1);
    return;
  }

  const newKeys = {
    public: sodium.from_base64(
      pending.newPublicB64,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
    secret: sodium.from_base64(
      pending.newSecretB64,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
  };

  try {
    const res = await api.post<RotateCompleteResponse>(
      "/api/keys/rotate/complete",
      { old_public_key: pending.oldPublicB64 },
      { signWith: newKeys }
    );
    console.log(`Revoked old ${role} key: ${res.revoked_key}`);

    // Swap in the new keys on this role's KeyIdentity. Clear the pending
    // record.
    const updatedKey: KeyIdentity = {
      signingKeys: {
        public: pending.newPublicB64,
        secret: pending.newSecretB64,
      },
      registeredKeyId: pending.newPublicB64,
      enrolledAt: roleKey.enrolledAt,
    };
    await savePublicAccount(withRoleKey(account, role, updatedKey), store);

    // Update the known-hosts self-entry for daemon rotations only —
    // client keys don't have a pair-target row in known_hosts.
    if (role === "daemon") {
      await removeKnownHost(account.label, store);
      await savePublicKnownHost(
        {
          label: account.label,
          relayUrl: account.relayUrl,
          publicKey: pending.newPublicB64,
          role: "daemon",
        },
        store
      );
    }

    console.log(`${role} rotation complete.`);
  } catch (err: any) {
    if (err instanceof PublicApiError) {
      console.error(`rotate complete failed: ${err.message} (HTTP ${err.status})`);
    } else {
      console.error(`rotate complete failed: ${err?.message ?? err}`);
    }
    process.exit(1);
  }
}
