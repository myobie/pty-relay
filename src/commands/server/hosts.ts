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

/** Response shape from /api/hosts. `account_id` is at the top level;
 *  each host has `{public_key, label, role, status}`. */
interface HostsResponse {
  account_id?: string;
  hosts: Array<{
    public_key: string;
    label: string | null;
    role: "daemon" | "client";
    status: "online" | "offline";
  }>;
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
    const res = await api.get<HostsResponse>("/api/hosts", {
      signWith: { public: edPk, secret: edSk },
    });

    if (opts.json) {
      console.log(JSON.stringify(res, null, 2));
    } else {
      if (res.account_id) {
        console.log(`Account: ${res.account_id}`);
      }
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

    if (opts.merge) {
      // Three passes over the local known_hosts list:
      //   1. Prune: drop any entry we have for this relay whose pubkey
      //      is no longer in /api/hosts — that peer was revoked (or
      //      rotated; the revocation side-effect is the same here).
      //   2. Merge: add any new peers we don't yet have, using
      //      pickUniqueLabel to avoid stomping a local name.
      //   3. Report counts.
      const existing = await loadKnownHosts(store);
      const serverKeys = new Set(res.hosts.map((h) => h.public_key));
      const stale = existing.filter(
        (h) =>
          h.publicKey &&
          h.relayUrl === account.relayUrl &&
          !serverKeys.has(h.publicKey)
      );
      for (const s of stale) {
        await removeKnownHost(s.label, store);
      }

      // Re-read to account for the prune before computing what's new.
      const after = await loadKnownHosts(store);
      const existingKeys = new Set(
        after
          .filter((h) => h.publicKey && h.relayUrl === account.relayUrl)
          .map((h) => h.publicKey)
      );
      // Labels in use locally — used to detect collisions below. Includes
      // both self-hosted and public-relay entries since `pty-relay connect
      // <label>` resolves in one namespace.
      const usedLabels = new Set(after.map((h) => h.label));
      let added = 0;
      for (const h of res.hosts) {
        if (existingKeys.has(h.public_key)) continue;
        const wanted = h.label || `host-${h.public_key.slice(0, 8)}`;
        const label = pickUniqueLabel(wanted, h.public_key, usedLabels);
        await savePublicKnownHost(
          {
            label,
            relayUrl: account.relayUrl,
            publicKey: h.public_key,
            role: h.role,
          },
          store
        );
        usedLabels.add(label);
        added++;
      }
      if (!opts.json) {
        if (stale.length > 0) {
          console.log(
            `Pruned ${stale.length} stale host(s) (no longer on account): ${stale.map((s) => s.label).join(", ")}`
          );
        }
        console.log(`Merged ${added} new host(s) into known_hosts.`);
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

