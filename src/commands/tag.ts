import { ready } from "../crypto/index.ts";
import {
  tagRemoteSession,
  tagPublicRemoteSession,
} from "../relay/relay-client.ts";
import { tagSshRemoteSession } from "../relay/transport-ssh.ts";
import { resolveHost } from "../relay/host-resolve.ts";
import { openSecretStore } from "../storage/bootstrap.ts";
import { log } from "../log.ts";

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
  log("cli", "tag begin", {
    hostLabel,
    session,
    setCount: opts.set ? Object.keys(opts.set).length : 0,
    removeCount: opts.remove?.length ?? 0,
    json: !!opts.json,
  });

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

  const tagOpts = { set: opts.set, remove: opts.remove };
  let result: { tags: Record<string, string> };
  if (resolved.kind === "public") {
    result = await tagPublicRemoteSession(resolved.target, session, tagOpts);
  } else if (resolved.kind === "ssh") {
    result = await tagSshRemoteSession(resolved.sshUrl, session, tagOpts);
  } else {
    result = await tagRemoteSession(resolved.url, session, tagOpts);
  }

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
