import sodium from "libsodium-wrappers-sumo";
import { ready } from "../../crypto/index.ts";
import { openSecretStore } from "../../storage/bootstrap.ts";
import { loadPublicAccount } from "../../storage/public-account.ts";
import { PublicApi, PublicApiError } from "../../relay/public-api.ts";
import {
  loadKnownHosts,
  savePublicKnownHost,
  removeKnownHost,
  pickUniqueLabel,
} from "../../relay/known-hosts.ts";
// Note: several of these are used by `mergeAccountDaemons` below — the
// merge helper and the `hosts` listing share the same knownhosts module.

/** Response shape from /api/hosts. `account_id` is at the top level;
 *  each host has `{public_key, label, role, status}`. */
export interface HostsResponse {
  account_id?: string;
  hosts: Array<{
    public_key: string;
    label: string | null;
    role: "daemon" | "client";
    status: "online" | "offline";
  }>;
}

/**
 * Sync known_hosts to match the set of daemons the relay reports for
 * this account. Called by `server hosts --merge` and auto-invoked
 * after a successful `client signin` so a fresh client can run
 * `client ls` / `client connect` immediately.
 *
 * Only role=daemon entries get saved — clients aren't pair targets
 * (a client key can't be WS-paired TO; the relay would 403 with
 * "target key is not a daemon"). Existing role=client entries this
 * CLI might have saved in an earlier version are also pruned so
 * they stop showing up as broken entries in `client ls`.
 *
 * Returns {added, pruned} so the caller can log something useful.
 */
export async function mergeAccountDaemons(
  api: PublicApi,
  accountRelayUrl: string,
  accountSigningKeys: { public: Uint8Array; secret: Uint8Array },
  store: import("../../storage/secret-store.ts").SecretStore
): Promise<{ res: HostsResponse; added: number; pruned: number }> {
  const res = await api.get<HostsResponse>("/api/hosts", {
    signWith: accountSigningKeys,
  });

  // Only daemons are pair targets. Build the set of daemon pubkeys
  // the server currently knows about; anything else in our local
  // known_hosts for this relay is stale and should go away.
  const serverDaemonKeys = new Set(
    res.hosts.filter((h) => h.role === "daemon").map((h) => h.public_key)
  );

  const existing = await loadKnownHosts(store);
  const stale = existing.filter(
    (h) =>
      h.publicKey &&
      h.relayUrl === accountRelayUrl &&
      !serverDaemonKeys.has(h.publicKey)
  );
  for (const s of stale) {
    await removeKnownHost(s.label, store);
  }

  // Re-read after prune to compute the unique-label set correctly.
  const after = await loadKnownHosts(store);
  const existingKeys = new Set(
    after
      .filter((h) => h.publicKey && h.relayUrl === accountRelayUrl)
      .map((h) => h.publicKey)
  );
  // Labels in use across all known_hosts (self-hosted + public). The
  // `connect <label>` resolver sees one namespace, so collisions
  // there matter too.
  const usedLabels = new Set(after.map((h) => h.label));
  let added = 0;
  for (const h of res.hosts) {
    if (h.role !== "daemon") continue;
    if (existingKeys.has(h.public_key)) continue;
    const wanted = h.label || `host-${h.public_key.slice(0, 8)}`;
    const label = pickUniqueLabel(wanted, h.public_key, usedLabels);
    await savePublicKnownHost(
      {
        label,
        relayUrl: accountRelayUrl,
        publicKey: h.public_key,
        role: "daemon",
      },
      store
    );
    usedLabels.add(label);
    added++;
  }

  return { res, added, pruned: stale.length };
}

/**
 * `pty-relay server hosts` — list the registered keys on this device's
 * account, optionally merging new peer daemons into the local
 * known_hosts so `pty-relay ls` can see them.
 */
export async function hostsCommand(opts: {
  json?: boolean;
  merge?: boolean;
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

  const api = new PublicApi(account.relayUrl);
  // /api/hosts is a read endpoint; any active key on the account works.
  // Prefer the daemon key (consistent with other management commands)
  // and fall back to the client key on client-only devices.
  const signingKey = account.daemonKey ?? account.clientKey;
  if (!signingKey) {
    console.error("No active keys on this device.");
    process.exit(1);
    return;
  }
  const edPk = sodium.from_base64(
    signingKey.signingKeys.public,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );
  const edSk = sodium.from_base64(
    signingKey.signingKeys.secret,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );

  try {
    if (opts.merge) {
      const { res, added, pruned } = await mergeAccountDaemons(
        api,
        account.relayUrl,
        { public: edPk, secret: edSk },
        store
      );
      if (opts.json) {
        console.log(JSON.stringify(res, null, 2));
      } else {
        if (res.account_id) console.log(`Account: ${res.account_id}`);
        console.log(`Hosts on this account (${res.hosts.length}):`);
        for (const h of res.hosts) {
          const label = h.label || "(unlabeled)";
          const isMine =
            h.public_key === account.daemonKey?.signingKeys.public ||
            h.public_key === account.clientKey?.signingKeys.public;
          const mine = isMine ? " *this device*" : "";
          console.log(`  ${h.status.padEnd(7)}  ${h.role.padEnd(6)}  ${label}${mine}`);
        }
        if (pruned > 0) {
          console.log(`Pruned ${pruned} stale host(s) from known_hosts.`);
        }
        console.log(`Merged ${added} daemon(s) into known_hosts.`);
      }
    } else {
      // Non-merge listing: just show the inventory, don't touch local state.
      const res = await api.get<HostsResponse>("/api/hosts", {
        signWith: { public: edPk, secret: edSk },
      });
      if (opts.json) {
        console.log(JSON.stringify(res, null, 2));
      } else {
        if (res.account_id) console.log(`Account: ${res.account_id}`);
        console.log(`Hosts on this account (${res.hosts.length}):`);
        for (const h of res.hosts) {
          const label = h.label || "(unlabeled)";
          const isMine =
            h.public_key === account.daemonKey?.signingKeys.public ||
            h.public_key === account.clientKey?.signingKeys.public;
          const mine = isMine ? " *this device*" : "";
          console.log(`  ${h.status.padEnd(7)}  ${h.role.padEnd(6)}  ${label}${mine}`);
        }
      }
    }
  } catch (err: any) {
    if (err instanceof PublicApiError) {
      console.error(`hosts failed: ${err.message} (HTTP ${err.status})`);
    } else {
      console.error(`hosts failed: ${err?.message ?? err}`);
    }
    process.exit(1);
  }
}

