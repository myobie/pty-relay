import sodium from "libsodium-wrappers-sumo";
import { ready } from "../../crypto/index.ts";
import { openSecretStore } from "../../storage/bootstrap.ts";
import { loadPublicAccount, requireDaemonKey } from "../../storage/public-account.ts";
import { PublicApi, PublicApiError } from "../../relay/public-api.ts";
import {
  loadKnownHosts,
  removeKnownHost,
} from "../../relay/known-hosts.ts";

interface HostsResponse {
  account_id?: string;
  hosts: Array<{
    public_key: string;
    label: string | null;
    role: "daemon" | "client";
    status: "online" | "offline";
  }>;
}

interface RevokeResponse {
  status: "revoked";
  public_key: string;
}

/**
 * `pty-relay server revoke <key-or-label>` — revoke another device's
 * registered key on this account. Accepts either a known-host label,
 * a full base64url public key, or a short unique prefix.
 *
 * The relay's /api/keys/revoke is authenticated with the CALLER'S
 * Ed25519 key; the target just has to belong to the same account.
 * A revoked target daemon's primary WebSocket is closed server-side.
 *
 * Always prompts for confirmation before revoking, because this is a
 * destructive one-way action. `--yes` skips the prompt for scripting
 * (like git's `--confirm`-bypass flags). Revoking THIS device's own
 * key additionally requires `--force`.
 */
export async function revokeCommand(opts: {
  keyOrLabel: string;
  force?: boolean;
  yes?: boolean;
  configDir?: string;
  passphraseFile?: string;
}): Promise<void> {
  await ready();

  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });
  const account = await loadPublicAccount(store);
  if (!account) {
    console.error("Not enrolled on any public relay.");
    process.exit(1);
    return;
  }

  // /api/keys/revoke is a daemon-role endpoint on the relay, so we must
  // sign with this device's daemon key even if we're revoking its own
  // (or the companion client's) key.
  const daemonKey = requireDaemonKey(account);
  const accountKeys = {
    public: sodium.from_base64(
      daemonKey.signingKeys.public,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
    secret: sodium.from_base64(
      daemonKey.signingKeys.secret,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
  };

  const api = new PublicApi(account.relayUrl);

  // Both of this device's keys count as "self" for the confirmation prompt.
  const ownKeys = [account.daemonKey?.signingKeys.public, account.clientKey?.signingKeys.public]
    .filter((k): k is string => typeof k === "string");

  // Resolve key-or-label → target pubkey (base64url).
  const targetPublicKey = await resolveTargetKey(
    opts.keyOrLabel,
    ownKeys,
    api,
    accountKeys,
    store
  );

  const isSelf = ownKeys.includes(targetPublicKey);
  if (isSelf && !opts.force) {
    console.error(
      `Refusing to revoke THIS device's own key without --force.\n` +
        `If you really want to do this, run \`pty-relay server revoke ${opts.keyOrLabel} --force\`.\n` +
        `You will lose access to this account from this device until you join again via preauth.`
    );
    process.exit(1);
  }

  // Confirmation prompt. Revoking a key is irreversible (the key slot
  // stays revoked even if you join a new device), so we always check
  // unless the operator explicitly bypasses with --yes.
  if (!opts.yes) {
    const target = await describeTarget(targetPublicKey, api, accountKeys, isSelf);
    console.log(`About to revoke:`);
    console.log(`  ${target}`);
    if (isSelf) {
      console.log(
        `  WARNING: this is THIS device's own key. You will lose access from here.`
      );
    }
    const answer = (await promptStdinLine("Proceed? [y/N] ")).trim().toLowerCase();
    if (answer !== "y" && answer !== "yes") {
      console.log("Aborted.");
      process.exit(0);
    }
  }

  try {
    const res = await api.post<RevokeResponse>(
      "/api/keys/revoke",
      { target_public_key: targetPublicKey },
      { signWith: accountKeys }
    );
    console.log(`Revoked key: ${res.public_key}`);

    // Drop the now-useless known-hosts entry so `ls` stops trying to
    // reach the revoked daemon. Match by publicKey OR label.
    const hosts = await loadKnownHosts(store);
    for (const h of hosts) {
      if (h.publicKey === targetPublicKey) {
        await removeKnownHost(h.label, store);
      }
    }
  } catch (err: any) {
    if (err instanceof PublicApiError) {
      console.error(`revoke failed: ${err.message} (HTTP ${err.status})`);
    } else {
      console.error(`revoke failed: ${err?.message ?? err}`);
    }
    process.exit(1);
  }
}

async function resolveTargetKey(
  input: string,
  ownKeys: string[],
  api: PublicApi,
  accountKeys: { public: Uint8Array; secret: Uint8Array },
  store: import("../../storage/secret-store.ts").SecretStore
): Promise<string> {
  // First: exact match against known_hosts labels or full pubkeys.
  const hosts = await loadKnownHosts(store);
  const byLabel = hosts.find((h) => h.label === input);
  if (byLabel?.publicKey) return byLabel.publicKey;
  if (hosts.some((h) => h.publicKey === input)) return input;

  // Then: /api/hosts for the full picture — pubkey prefix / label / "you".
  const res = await api.get<HostsResponse>("/api/hosts", { signWith: accountKeys });
  if (input === "you" || input === "self") {
    // "self" on a dual-role device is ambiguous — the operator must name
    // one specific key. Surface that clearly instead of silently picking.
    if (ownKeys.length === 1) return ownKeys[0];
    throw new Error(
      'This device has multiple keys on the account; "self"/"you" is ambiguous. Run `pty-relay server hosts` and pass the specific label or pubkey.'
    );
  }

  const byHostLabel = res.hosts.find((h) => h.label === input);
  if (byHostLabel) return byHostLabel.public_key;

  const byExact = res.hosts.find((h) => h.public_key === input);
  if (byExact) return byExact.public_key;

  // Prefix match — must be unique.
  const byPrefix = res.hosts.filter((h) => h.public_key.startsWith(input));
  if (byPrefix.length === 1) return byPrefix[0].public_key;
  if (byPrefix.length > 1) {
    throw new Error(
      `Ambiguous key prefix "${input}" — matches ${byPrefix.length} hosts.`
    );
  }

  throw new Error(
    `No host matches "${input}". Run \`pty-relay server hosts\` to see labels and pubkeys.`
  );
}

/** Human-readable description of a pubkey target for the confirm prompt. */
async function describeTarget(
  targetPublicKey: string,
  api: PublicApi,
  accountKeys: { public: Uint8Array; secret: Uint8Array },
  isSelf: boolean
): Promise<string> {
  try {
    const res = await api.get<HostsResponse>("/api/hosts", { signWith: accountKeys });
    const match = res.hosts.find((h) => h.public_key === targetPublicKey);
    if (match) {
      const label = match.label || "(unlabeled)";
      return `${label}  role=${match.role}  status=${match.status}  ${targetPublicKey}${isSelf ? "  (THIS DEVICE)" : ""}`;
    }
  } catch {
    // Fall through — the bare pubkey is still a useful identifier.
  }
  return `${targetPublicKey}${isSelf ? "  (THIS DEVICE)" : ""}`;
}

function promptStdinLine(label: string): Promise<string> {
  return new Promise<string>((resolve) => {
    process.stdout.write(label);
    let buf = "";
    const onData = (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl !== -1) {
        process.stdin.off("data", onData);
        process.stdin.pause();
        process.stdin.unref();
        resolve(buf.slice(0, nl).replace(/\r$/u, ""));
      }
    };
    process.stdin.ref();
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", onData);
  });
}
