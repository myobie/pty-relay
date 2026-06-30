import { ready } from "../crypto/index.ts";
import { killSshRemoteSession } from "../relay/transport-ssh.ts";
import { resolveHost } from "../relay/host-resolve.ts";
import { openSecretStore } from "../storage/bootstrap.ts";
import { log } from "../log.ts";

/**
 * `pty-relay kill <host> <session>` — terminate a session on a remote
 * peer.
 *
 * Phase-2 scope: ssh:// peers only. The remote `pty kill <session>`
 * does the actual termination; this is just a transport wrapper. For
 * self-hosted (#pk.secret) and public-relay peers, kill needs a relay
 * control message we haven't shipped yet — surface a clear "not yet
 * implemented over this transport" error rather than silently
 * succeeding-or-failing. Tracked as a follow-up.
 */
export async function killCommand(
  hostLabel: string,
  session: string,
  opts: {
    configDir?: string;
    passphraseFile?: string;
  } = {},
): Promise<void> {
  await ready();
  log("cli", "kill begin", { hostLabel, session });

  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });

  let resolved;
  try {
    resolved = await resolveHost(hostLabel, store);
  } catch (err: any) {
    console.error(err?.message ?? err);
    process.exit(1);
  }

  if (resolved.kind === "ssh") {
    try {
      await killSshRemoteSession(resolved.sshUrl, session);
      return;
    } catch (err: any) {
      console.error(err?.message ?? err);
      process.exit(1);
    }
  }

  // Non-ssh transports: explicit "not yet" so the operator doesn't
  // think their command silently no-op'd against the wrong host.
  console.error(
    `kill via ${resolved.kind === "public" ? "public-relay" : "self-hosted"} ` +
      `peers is not yet supported. For now: ssh peers can be killed with ` +
      `\`pty-relay kill <ssh-peer> <session>\`; for relay peers, run ` +
      `\`pty kill <session>\` directly on the remote.`,
  );
  process.exit(1);
}
