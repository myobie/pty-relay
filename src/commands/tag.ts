import { ready } from "../crypto/index.ts";
import {
  tagRemoteSession,
  tagPublicRemoteSession,
} from "../relay/relay-client.ts";
import { resolveHost } from "../relay/host-resolve.ts";
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
  let resolved;
  try {
    resolved = await resolveHost(hostLabel, store);
  } catch (err: any) {
    console.error(err?.message ?? err);
    process.exit(1);
  }

  const tagOpts = { set: opts.set, remove: opts.remove };
  const result =
    resolved.kind === "public"
      ? await tagPublicRemoteSession(resolved.target, session, tagOpts)
      : await tagRemoteSession(resolved.url, session, tagOpts);

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
