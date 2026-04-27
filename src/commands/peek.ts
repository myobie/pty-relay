import { ready } from "../crypto/index.ts";
import {
  peekRemoteSession,
  peekPublicRemoteSession,
} from "../relay/relay-client.ts";
import { resolveHost } from "../relay/host-resolve.ts";
import { openSecretStore } from "../storage/bootstrap.ts";
import { log } from "../log.ts";

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
  log("cli", "peek begin", {
    hostLabel,
    session,
    plain: !!opts.plain,
    full: !!opts.full,
    wait: opts.wait,
    timeoutSec: opts.timeoutSec,
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

  try {
    const peekOpts = {
      plain: !!opts.plain,
      full: !!opts.full,
      wait: opts.wait,
      timeoutSec: opts.timeoutSec,
    };
    const result =
      resolved.kind === "public"
        ? await peekPublicRemoteSession(resolved.target, session, peekOpts)
        : await peekRemoteSession(resolved.url, session, peekOpts);
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
