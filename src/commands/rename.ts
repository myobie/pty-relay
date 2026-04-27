import { ready } from "../crypto/index.ts";
import { openSecretStore } from "../storage/bootstrap.ts";
import { renameKnownHost } from "../relay/known-hosts.ts";
import { log } from "../log.ts";

/** `pty-relay rename <old> <new>` — rename a known-hosts entry.
 *
 *  Needed because `saveKnownHost` and `server hosts --merge` both
 *  suffix colliding labels automatically (so two unrelated hosts can't
 *  stomp each other on save). After the fact you may end up with
 *  `host-abcd1234` or `home-http-a-example`; this is how you clean
 *  those up.
 *
 *  Self-hosted and public-relay entries live in the same store under
 *  the same labels, so one command covers both.
 */
export async function renameCommand(
  oldLabel: string,
  newLabel: string,
  opts: { configDir?: string; passphraseFile?: string } = {}
): Promise<void> {
  await ready();
  log("cli", "rename begin", { oldLabel, newLabel });
  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });

  try {
    await renameKnownHost(oldLabel, newLabel, store);
    console.log(`Renamed "${oldLabel}" → "${newLabel}".`);
  } catch (err: any) {
    console.error(err?.message ?? err);
    process.exit(1);
  }
}
