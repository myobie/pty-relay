import sodium from "libsodium-wrappers-sumo";
import { ready } from "../../crypto/index.ts";
import { openSecretStore } from "../../storage/bootstrap.ts";
import { log } from "../../log.ts";
import {
  loadPublicAccount,
  clearPublicAccount,
} from "../../storage/public-account.ts";
import { PublicApi, PublicApiError } from "../../relay/public-api.ts";
import { loadKnownHosts, removeKnownHost } from "../../relay/known-hosts.ts";

/** `pty-relay server delete-account` — permanently delete this device's
 *  account (and every peer daemon on it) from the relay.
 *
 *  Any enrolled device can call this; membership is the only permission
 *  concept. The relay pushes `:revoked` to every connected primary
 *  daemon before the HTTP response returns, so other devices will see
 *  their serves drop and their keys invalidate. After success, the
 *  local public_account record and all related known-hosts entries
 *  are wiped. Signup with the same email is free to start fresh.
 *
 *  Always prompts for confirmation. `--yes` skips the prompt. */
export async function deleteAccountCommand(opts: {
  yes?: boolean;
  configDir?: string;
  passphraseFile?: string;
}): Promise<void> {
  await ready();
  log("cli", "server delete-account begin", { yes: !!opts.yes });

  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });
  const account = await loadPublicAccount(store);
  if (!account) {
    console.error("Not enrolled on any public relay — nothing to delete.");
    process.exit(1);
    return;
  }

  console.log("About to DELETE the entire account:");
  console.log(`  relay:    ${account.relayUrl}`);
  console.log(`  email:    ${account.email || "(unknown)"}`);
  console.log(`  account:  ${account.accountId}`);
  console.log(
    "This wipes every registered key on the account, every email on the account,"
  );
  console.log(
    "the TOTP secret, and every pending preauth. It is NOT reversible."
  );

  if (!opts.yes) {
    // Owner-device flow (has email): require typing the email back.
    // Joiner-device flow (empty email): require a fixed non-empty
    // sentinel so a bare Enter doesn't delete the account.
    const expected = account.email || "DELETE";
    const prompt =
      account.email
        ? "Type the email address to confirm: "
        : `Type "${expected}" (all caps) to confirm: `;
    const answer = (await promptStdinLine(prompt)).trim();
    if (!answer || answer !== expected) {
      console.log(
        `Aborted. (Got "${answer}", expected "${expected}".)`
      );
      process.exit(0);
    }
  }

  // `/api/account/delete` accepts any active key on the account;
  // prefer the daemon key, fall back to the client key.
  const signingKey = account.daemonKey ?? account.clientKey;
  if (!signingKey) {
    console.error("No active keys on this device — unable to authenticate the delete call.");
    process.exit(1);
    return;
  }
  const accountKeys = {
    public: sodium.from_base64(
      signingKey.signingKeys.public,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
    secret: sodium.from_base64(
      signingKey.signingKeys.secret,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
  };
  const api = new PublicApi(account.relayUrl);

  try {
    const res = await api.post<{ status: "deleted"; account_id: string }>(
      "/api/account/delete",
      {},
      { signWith: accountKeys }
    );
    console.log(`Server confirmed: ${res.status} ${res.account_id}`);
  } catch (err: any) {
    if (err instanceof PublicApiError) {
      console.error(`delete-account failed: ${err.message} (HTTP ${err.status})`);
    } else {
      console.error(`delete-account failed: ${err?.message ?? err}`);
    }
    process.exit(1);
  }

  // Local cleanup: drop the public_account secret + every known-host
  // entry pointing at this relay. Leaves self-hosted entries alone.
  await clearPublicAccount(store);
  const hosts = await loadKnownHosts(store);
  for (const h of hosts) {
    if (h.relayUrl === account.relayUrl) {
      await removeKnownHost(h.label, store);
    }
  }
  console.log("Local account state cleared.");
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
