import { ready } from "../crypto/index.ts";
import {
  sendToRemoteSession,
  sendToPublicRemoteSession,
} from "../relay/relay-client.ts";
import { resolveHost } from "../relay/host-resolve.ts";
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

  let resolved;
  try {
    resolved = await resolveHost(hostLabel, store);
  } catch (err: any) {
    console.error(err?.message ?? err);
    process.exit(1);
  }

  const sendOpts = { delayMs: opts.delayMs, paste: opts.paste };
  if (resolved.kind === "public") {
    await sendToPublicRemoteSession(resolved.target, session, data, sendOpts);
  } else {
    await sendToRemoteSession(resolved.url, session, data, sendOpts);
  }
}
