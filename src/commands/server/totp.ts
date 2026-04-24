import { ready } from "../../crypto/index.ts";
import { openSecretStore } from "../../storage/bootstrap.ts";
import { loadPublicAccount } from "../../storage/public-account.ts";
import {
  generateTotpCode,
  otpauthUrl,
} from "../../crypto/totp.ts";

/**
 * `pty-relay server totp <show|code>` — display the account's TOTP
 * secret (or just the current code). Only works on the device that
 * stored the TOTP locally; joined devices don't own the secret.
 */
export async function totpCommand(opts: {
  subcommand: "show" | "code";
  configDir?: string;
  passphraseFile?: string;
}): Promise<void> {
  await ready();

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

  if (!account.totpSecretB32) {
    console.error(
      "This device doesn't own the account's TOTP secret. Use the device that ran `server signin` (first daemon on the account)."
    );
    process.exit(1);
    return;
  }

  if (opts.subcommand === "code") {
    console.log(generateTotpCode(account.totpSecretB32));
    return;
  }

  // show — print the otpauth URL, the base32 secret, and the current code.
  console.log("TOTP secret (base32):");
  console.log(`  ${account.totpSecretB32}`);
  console.log("");
  console.log("otpauth URL (scan into an authenticator app):");
  console.log(`  ${otpauthUrl(account.totpSecretB32, account.email, "pty-relay")}`);
  console.log("");
  console.log(`Current code: ${generateTotpCode(account.totpSecretB32)}`);
}
