import sodium from "libsodium-wrappers-sumo";
import { ready } from "../../crypto/index.ts";
import { openSecretStore } from "../../storage/bootstrap.ts";
import { log } from "../../log.ts";
import { loadPublicAccount, requireDaemonKey } from "../../storage/public-account.ts";
import { PublicApi, PublicApiError } from "../../relay/public-api.ts";

/** `pty-relay server add-email <email>` — add a secondary email to this
 *  device's account. The relay sends a verification code; we prompt for
 *  it and call /api/account/verify-email to finish. */

export async function addEmailCommand(opts: {
  email: string;
  emailCode?: string;
  configDir?: string;
  passphraseFile?: string;
}): Promise<void> {
  await ready();
  log("cli", "server add-email begin", { email: opts.email });
  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });
  const account = await loadPublicAccount(store);
  if (!account) {
    console.error("Not enrolled on any public relay.");
    process.exit(1);
    return;
  }

  // `/api/account/add-email` is a daemon-role endpoint on the relay.
  const daemonKey = requireDaemonKey(account);
  const accountKeys = {
    public: sodium.from_base64(
      daemonKey.signingKeys.public,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
    secret: sodium.from_base64(
      daemonKey.signingKeys.secret,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
  };

  const api = new PublicApi(account.relayUrl);

  try {
    const { request_id } = await api.post<{ request_id: string }>(
      "/api/account/add-email",
      { email: opts.email },
      { signWith: accountKeys }
    );
    console.log(`Check ${opts.email} for a verification code.`);

    const code =
      opts.emailCode ??
      (await promptStdinLine("Email code (6 digits): ")).trim();

    const verified = await api.post<{ status: "verified"; email: string }>(
      "/api/account/verify-email",
      { request_id, code }
    );
    console.log(`Added secondary email: ${verified.email}`);
  } catch (err: any) {
    if (err instanceof PublicApiError) {
      console.error(`add-email failed: ${err.message} (HTTP ${err.status})`);
    } else {
      console.error(`add-email failed: ${err?.message ?? err}`);
    }
    process.exit(1);
  }
}

function promptStdinLine(label: string): Promise<string> {
  return new Promise<string>((resolve) => {
    process.stdout.write(label);
    let buf = "";
    const onData = (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl !== -1) {
        process.stdin.off("data", onData);
        process.stdin.pause();
        process.stdin.unref();
        resolve(buf.slice(0, nl).replace(/\r$/u, ""));
      }
    };
    process.stdin.ref();
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", onData);
  });
}
