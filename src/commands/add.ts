import { openSecretStore } from "../storage/bootstrap.ts";
import {
  saveSshKnownHost,
  loadKnownHosts,
} from "../relay/known-hosts.ts";
import {
  looksLikeSshUrl,
  parseSshUrl,
  probeSshPeer,
} from "../relay/transport-ssh.ts";
import { log } from "../log.ts";

/**
 * `pty-relay add <peer>` — record a new peer in known-hosts. Today
 * the only supported peer shape is an `ssh://[user@]host[:port]` URL
 * (brief-010 phase 1). Self-hosted hosts are still saved
 * automatically on the first successful `connect`; public-relay hosts
 * come from the `server signin`/`server join` flows.
 *
 * The save is gated on a connectivity probe (`ssh <host> pty
 * --version`). Refusing to record a peer that we can't reach saves
 * the user from a later `pty-relay ls <label>` failing with an
 * opaque "command not found" or "could not resolve hostname" error.
 */

export interface AddOptions {
  configDir?: string;
  passphraseFile?: string;
  /** Override the auto-derived label (defaults to the bare hostname
   *  from the URL, e.g. `me@host.tld:2222` → `host.tld`). */
  label?: string;
}

export async function addCommand(target: string, opts: AddOptions = {}): Promise<void> {
  if (!looksLikeSshUrl(target)) {
    console.error(
      `pty-relay add only supports ssh:// peers today. Got: ${target}`,
    );
    console.error("  Self-hosted hosts are saved automatically on `connect`.");
    console.error("  Public-relay hosts use `pty-relay server signin`/`server join`.");
    process.exit(1);
  }

  let parsed: ReturnType<typeof parseSshUrl>;
  try {
    parsed = parseSshUrl(target);
  } catch (err: any) {
    console.error(`Invalid ssh URL: ${err?.message ?? err}`);
    process.exit(1);
  }

  const label = opts.label ?? deriveDefaultLabel(parsed.userHost);
  log("cli", "add ssh begin", { sshUrl: target, label });

  // Probe before save. If pty isn't installed remotely or the host is
  // unreachable, surface the actionable error from translateSshError
  // verbatim — the operator gets the same message they'd see if they
  // had tried `pty-relay ls` afterwards, but without polluting the
  // known-hosts file with a non-functional entry.
  process.stdout.write(`Checking ${target} ...`);
  let version: string;
  try {
    version = await probeSshPeer(target);
  } catch (err: any) {
    process.stdout.write("\n");
    console.error(err?.message ?? err);
    process.exit(1);
  }
  process.stdout.write(` ok (pty ${version || "unknown"})\n`);

  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });

  await saveSshKnownHost({ label, sshUrl: target }, store);

  // Report the canonical name `ls` will show. saveSshKnownHost runs
  // pickUniqueLabel internally; re-read so any collision suffix is
  // surfaced to the operator.
  const all = await loadKnownHosts(store);
  const saved = all.find((h) => h.sshUrl === target);
  const finalLabel = saved?.label ?? label;
  console.log(`Added ${finalLabel} → ${target}`);
  if (finalLabel !== label) {
    console.log(
      `  (label collided with an existing entry; auto-suffixed to "${finalLabel}")`,
    );
  }
}

/** Pick a friendly default label from the `[user@]host` portion of an
 *  ssh URL. Drops the `user@` prefix because the label is for the
 *  human-typed `pty-relay ls <label>` flow, not the underlying
 *  identity. */
function deriveDefaultLabel(userHost: string): string {
  const atIdx = userHost.lastIndexOf("@");
  return atIdx === -1 ? userHost : userHost.slice(atIdx + 1);
}
