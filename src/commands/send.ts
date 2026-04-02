import { ready } from "../crypto/index.ts";
import { loadKnownHosts } from "../relay/known-hosts.ts";
import { sendToRemoteSession } from "../relay/relay-client.ts";
import { openSecretStore } from "../storage/bootstrap.ts";

export async function send(
  hostLabel: string,
  session: string,
  data: string[],
  opts: {
    delayMs?: number;
    paste?: boolean;
    configDir?: string;
    passphraseFile?: string;
  } = {}
): Promise<void> {
  await ready();

  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });
  const hosts = await loadKnownHosts(store);
  const host = hosts.find((h) => h.label === hostLabel);
  if (!host) {
    console.error(`No known host with label "${hostLabel}".`);
    console.error("Run 'pty-relay ls' to see host labels.");
    process.exit(1);
  }

  await sendToRemoteSession(host.url, session, data, {
    delayMs: opts.delayMs,
    paste: opts.paste,
  });
}
