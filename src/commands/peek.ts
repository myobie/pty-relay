import { ready } from "../crypto/index.ts";
import { loadKnownHosts } from "../relay/known-hosts.ts";
import { peekRemoteSession } from "../relay/relay-client.ts";
import { openSecretStore } from "../storage/bootstrap.ts";

export async function peek(
  hostLabel: string,
  session: string,
  opts: {
    plain?: boolean;
    full?: boolean;
    wait?: string[];
    timeoutSec?: number;
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

  try {
    const result = await peekRemoteSession(host.url, session, {
      plain: !!opts.plain,
      full: !!opts.full,
      wait: opts.wait,
      timeoutSec: opts.timeoutSec,
    });
    // Write the screen to stdout as-is; callers can pipe or redirect.
    process.stdout.write(result.screen);
    // Add a trailing newline only if the screen didn't end with one, so
    // shells don't glue the next prompt onto the last row.
    if (result.screen.length > 0 && !result.screen.endsWith("\n")) {
      process.stdout.write("\n");
    }
  } catch (err: any) {
    // `--wait` timeouts come back as remote errors — surface with exit 1
    // to match local `pty peek --wait` which also exits non-zero on miss.
    console.error(err.message || "peek failed");
    process.exit(1);
  }
}
