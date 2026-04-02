import { ready } from "../crypto/index.ts";
import { loadKnownHosts } from "../relay/known-hosts.ts";
import { tagRemoteSession } from "../relay/relay-client.ts";
import { openSecretStore } from "../storage/bootstrap.ts";

export async function tag(
  hostLabel: string,
  session: string,
  opts: {
    set?: Record<string, string>;
    remove?: string[];
    json?: boolean;
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

  const result = await tagRemoteSession(host.url, session, {
    set: opts.set,
    remove: opts.remove,
  });

  if (opts.json) {
    console.log(JSON.stringify(result.tags, null, 2));
    return;
  }

  const entries = Object.entries(result.tags);
  if (entries.length === 0) {
    console.log("(no tags)");
    return;
  }
  for (const [k, v] of entries) {
    console.log(`#${k}=${v}`);
  }
}
