import { ready } from "../../crypto/index.ts";
import { PublicApi, PublicApiError } from "../../relay/public-api.ts";
import { log } from "../../log.ts";

/** `pty-relay server reset --email <addr>` — request an account reset
 *  from the relay when locked out (lost device keys, etc.).
 *
 *  Unauthenticated by design: the user has no working keys here. The
 *  relay sends an email with a link to a confirmation form requiring
 *  a current TOTP code; on submit, every non-revoked key on the
 *  account is revoked. The account itself, all emails on it, the
 *  TOTP secret, and ACLs survive. After confirming in the email
 *  flow, re-enroll a fresh daemon with `pty-relay server signin
 *  --email <addr>`.
 *
 *  Threat floor matches signin: needs both email AND TOTP. The relay
 *  always returns `{status: "maybe_sent"}` (no account enumeration),
 *  so we can't tell the user "we sent it" with certainty — only
 *  that we asked. */
export async function resetCommand(opts: {
  email: string;
  relayUrl: string;
}): Promise<void> {
  await ready();
  log("cli", "server reset begin", { email: opts.email, relay: opts.relayUrl });

  const api = new PublicApi(opts.relayUrl);

  try {
    await api.post<{ status: string }>(
      "/api/account/reset",
      { email: opts.email }
    );
  } catch (err: unknown) {
    if (err instanceof PublicApiError && err.status === 429) {
      console.error(
        `Rate limited: ${err.message}. Please wait a minute and try again.`
      );
      process.exit(1);
      return;
    }
    if (err instanceof PublicApiError) {
      console.error(
        `Reset request failed: ${err.message} (HTTP ${err.status})`
      );
      process.exit(1);
      return;
    }
    const e = err as { message?: string } | null;
    console.error(`Reset request failed: ${e?.message ?? err}`);
    process.exit(1);
    return;
  }

  console.log("Reset requested.");
  console.log();
  console.log(
    `If an account exists for ${opts.email}, the relay will email a`
  );
  console.log(
    "confirmation link. Open it, enter your current TOTP code, and"
  );
  console.log(
    "submit the form to revoke every key on the account."
  );
  console.log();
  console.log("Then re-enroll this device:");
  console.log(`  pty-relay server signin --email ${opts.email}`);
}
