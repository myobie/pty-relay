import sodium from "libsodium-wrappers-sumo";
import { ready } from "../../crypto/index.ts";
import { openSecretStore } from "../../storage/bootstrap.ts";
import {
  loadPublicAccount,
  savePublicAccount,
  type PublicAccount,
  type KeyIdentity,
} from "../../storage/public-account.ts";
import { savePublicKnownHost } from "../../relay/known-hosts.ts";
import { PublicApi, PublicApiError } from "../../relay/public-api.ts";
import {
  generateTotpSecret,
  base32Encode,
  generateConsecutiveCodes,
  otpauthUrl,
} from "../../crypto/totp.ts";

/**
 * Dependencies that make the signin wizard testable without real HTTP,
 * real stdin, or a real clock. In production we wire these to the
 * actual implementations; in tests we pass stubs that record calls and
 * return scripted responses.
 */
export interface SigninDeps {
  api: PublicApi;
  /** Ed25519 keypair factory. Default: libsodium. Override for deterministic tests. */
  generateSigningKeypair?: () => { publicKey: Uint8Array; secretKey: Uint8Array };
  /** 20-byte TOTP secret factory. */
  generateTotpSecret?: () => Uint8Array;
  /** Blocking stdin prompt — returns user input (stripped of newline). */
  promptLine: (label: string) => Promise<string>;
  /** Printf replacement. Separate from stdin prompts so tests can assert. */
  log: (line: string) => void;
  /** Clock in seconds since epoch. Used so two consecutive TOTP codes fall
   *  in different 30s windows deterministically in tests. */
  now?: () => number;
  /** How many attempts to poll /api/verify/poll before asking the user to
   *  paste the code. Default 0 — we always ask the user to paste today.
   *  Infrastructure for the email-link flow can hook in later. */
  pollAttempts?: number;
  /** Delay between poll attempts in ms. */
  pollIntervalMs?: number;
}

export interface SigninInput {
  email: string;
  relayUrl: string;
  label: string;
  /** Pre-supplied TOTP code(s), skipping the interactive prompt. Used by
   *  non-interactive tests and scripted flows. */
  overrideTotpCode?: string;
}

export interface SigninResult {
  account: PublicAccount;
  /** True if this signin bootstrapped a new account (and we set up a fresh
   *  TOTP secret); false if an additional daemon was added to an existing
   *  account. Determines whether we print the QR code. */
  freshTotp: boolean;
}

/** Response shapes from the Elixir relay — documented in `auth_controller.ex`. */
interface SigninOk { request_id: string }
interface VerifyTotpSetup {
  status: "totp_setup";
  totp_url: string;
  totp_secret: string;
  request_id: string;
}
interface VerifyTotpRequired { status: "totp_required"; request_id: string }
type VerifyResult = VerifyTotpSetup | VerifyTotpRequired;
interface VerifyTotpOk {
  status: "verified";
  public_key: string;
  account_id: string;
  totp_secret: string;
}

/**
 * Run the email+TOTP signin wizard against a public relay. On a fresh
 * email this creates a new account with this key as its first daemon;
 * on an existing email it adds this daemon key to the account (gated
 * by a current TOTP code from an authenticator already enrolled on the
 * account). Returns the PublicAccount record to persist.
 *
 * This function only handles the pure wire+state logic. The CLI wrapper
 * opens the secret store and constructs the PublicApi; tests can bypass
 * that plumbing and drive the wizard directly with stubbed deps.
 */
export async function runSignin(
  input: SigninInput,
  deps: SigninDeps
): Promise<SigninResult> {
  await ready();

  const keypair =
    deps.generateSigningKeypair?.() ?? defaultSigningKeypair();
  const totpRaw = deps.generateTotpSecret?.() ?? generateTotpSecret();
  const totpB32 = base32Encode(totpRaw);

  const publicKeyB64 = sodium.to_base64(
    keypair.publicKey,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );

  deps.log(`Starting signin for ${input.email} on ${input.relayUrl}...`);

  // Step 1: /api/signin — the relay emails a 6-digit code. Works for
  // both fresh accounts (creates one) and existing accounts (adds this
  // daemon key to it, gated by TOTP). Role is "daemon" on this path;
  // the client path has its own command.
  const signup = await deps.api.post<SigninOk>("/api/signin", {
    email: input.email,
    public_key: publicKeyB64,
    role: "daemon",
    label: input.label,
    totp_secret: totpB32,
  });
  const requestId = signup.request_id;
  deps.log(`Check ${input.email} for a verification code.`);

  // Step 2: /api/verify — read the code from stdin (poll-for-link is a
  // later improvement and not needed for CLI UX today).
  const emailCode = await deps.promptLine("Email code (6 digits): ");
  const verify = await deps.api.post<VerifyResult>("/api/verify", {
    request_id: requestId,
    code: emailCode.trim(),
  });

  // Step 3: /api/verify/totp — branch on whether this is the first daemon
  // (totp_setup; two consecutive codes auto-generated from our secret)
  // or an additional daemon on an existing account (totp_required;
  // the user types a code from their authenticator).
  let verified: VerifyTotpOk;
  let freshTotp: boolean;
  /** The TOTP secret this device should persist and print, after the
   *  verify round. On the totp_setup path this comes from the relay
   *  (which may have kept an earlier secret from a parallel signup of
   *  the same email); otherwise the device doesn't own a TOTP secret. */
  let finalTotpB32: string | undefined;

  if (verify.status === "totp_setup") {
    freshTotp = true;
    // The relay echoes back the secret it stored. Normally that's
    // ours (we supplied it on signup), but a concurrent signup of the
    // same email would leave the earlier secret in place. Always
    // treat the relay's copy as authoritative so we don't end up
    // with a device whose local TOTP diverges from what the server
    // expects forever after.
    const serverTotpB32 = (verify as VerifyTotpSetup).totp_secret;
    finalTotpB32 = serverTotpB32;
    const codes = deps.generateTotpSecret
      ? // Test mode: use our input secret with deterministic clock
        generateConsecutiveCodes(totpB32, deps.now?.())
      : generateConsecutiveCodes(serverTotpB32, deps.now?.());
    verified = await deps.api.post<VerifyTotpOk>("/api/verify/totp", {
      request_id: requestId,
      code1: codes[0],
      code2: codes[1],
    });
  } else {
    freshTotp = false;
    deps.log(
      "This email already has TOTP set up. Enter a code from your existing authenticator."
    );
    const code =
      input.overrideTotpCode ?? (await deps.promptLine("TOTP code: ")).trim();
    verified = await deps.api.post<VerifyTotpOk>("/api/verify/totp", {
      request_id: requestId,
      code,
    });
    // Server includes `totp_secret` on the verify response for every
    // daemon signin (both fresh-account and adding-to-existing). Persist
    // it here too — the design is "every daemon holds the TOTP so it
    // can mint preauths"; if only the first-ever daemon kept it, a
    // fleet-of-two could mint from machine A but not machine B, which
    // defeats the "any daemon can invite" property.
    if (typeof verified.totp_secret === "string" && verified.totp_secret.length > 0) {
      finalTotpB32 = verified.totp_secret;
    }
  }

  // The daemon key is now registered on the relay. Build its KeyIdentity
  // and stop here — a daemon machine holds a daemon key only. Machines
  // that also need to act as a client run `pty-relay client signin`
  // separately (which registers a role=client key, account-wide). No
  // auto-upgrade: the relay now rejects role=daemon on /api/keys/mint and
  // a daemon-key self-minting a client would defeat the point of strict
  // role enforcement.
  const daemonKey: KeyIdentity = {
    signingKeys: {
      public: publicKeyB64,
      secret: sodium.to_base64(
        keypair.secretKey,
        sodium.base64_variants.URLSAFE_NO_PADDING
      ),
    },
    registeredKeyId: verified.public_key,
    enrolledAt: new Date().toISOString(),
  };

  const account: PublicAccount = {
    relayUrl: input.relayUrl,
    email: input.email,
    accountId: verified.account_id,
    label: input.label,
    // Every daemon persists the account's TOTP secret. On the
    // totp_setup path this is what we just set up; on totp_required
    // it's echoed back by the relay for the new daemon to keep.
    totpSecretB32: finalTotpB32,
    daemonKey,
  };

  if (freshTotp && finalTotpB32) {
    const url = otpauthUrl(finalTotpB32, input.email, "pty-relay");
    deps.log("");
    deps.log("Your TOTP authenticator URL:");
    deps.log(url);
    deps.log("");
    deps.log("Scan the above URL in Authy / 1Password / Google Authenticator.");
  }

  deps.log("");
  deps.log(`Enrolled as "${input.label}" on ${input.relayUrl}.`);

  return { account, freshTotp };
}

function defaultSigningKeypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, secretKey: kp.privateKey };
}

/** CLI entry point — opens the secret store, runs the wizard, persists. */
export async function signinCommand(opts: {
  email: string;
  relayUrl: string;
  label: string;
  configDir?: string;
  passphraseFile?: string;
}): Promise<void> {
  await ready();

  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });

  // If the machine already has a PublicAccount, the only case we
  // accept is "same account, no daemon key yet" (rare dual-role case:
  // this device previously joined as a pinned client via preauth, and
  // now wants to also run a daemon). Anything else is a conflict.
  const existing = await loadPublicAccount(store);
  if (existing) {
    if (existing.relayUrl !== opts.relayUrl) {
      console.error(
        `This device is enrolled on ${existing.relayUrl}; signin was pointed at ${opts.relayUrl}.`
      );
      console.error("Run `pty-relay reset` to start over on a different relay.");
      process.exit(1);
    }
    if (existing.daemonKey) {
      console.error(
        `This device already has a daemon key on this account (label "${existing.label}").`
      );
      console.error(
        "Use `pty-relay server rotate --role daemon` to replace it, or `pty-relay server status` to inspect."
      );
      process.exit(1);
    }
  }

  const api = new PublicApi(opts.relayUrl);

  try {
    const { account: freshAccount } = await runSignin(
      { email: opts.email, relayUrl: opts.relayUrl, label: opts.label },
      {
        api,
        promptLine: promptStdinLine,
        log: (line) => console.log(line),
      }
    );
    // Merge onto any existing account (client-only machine adding a
    // daemon key). Otherwise the fresh record stands on its own.
    const merged: PublicAccount = existing
      ? {
          ...existing,
          email: existing.email || freshAccount.email,
          totpSecretB32: existing.totpSecretB32 ?? freshAccount.totpSecretB32,
          daemonKey: freshAccount.daemonKey,
        }
      : freshAccount;
    await savePublicAccount(merged, store);
    // Register the account's own daemon as a known host so `pty-relay ls`
    // and future `server hosts` calls see it even before peers exist.
    if (merged.daemonKey) {
      await savePublicKnownHost(
        {
          label: merged.label,
          relayUrl: merged.relayUrl,
          publicKey: merged.daemonKey.signingKeys.public,
          role: "daemon",
        },
        store
      );
    }
    console.log("");
    console.log("Saved. `pty-relay server status` will show this account.");
  } catch (err: any) {
    if (err instanceof PublicApiError) {
      console.error(`Signin failed: ${err.message} (HTTP ${err.status})`);
    } else {
      console.error(`Signin failed: ${err?.message ?? err}`);
    }
    process.exit(1);
  }
}

/** Minimal one-shot line prompt — avoids readline for smaller surface.
 *  Echoes the label, blocks until newline, strips trailing CR/LF. */
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
        // Release our reference to stdin so a piped-in parent process
        // (orchestration tests, scripts) doesn't keep the event loop
        // alive after the CLI finishes work.
        process.stdin.unref();
        resolve(buf.slice(0, nl).replace(/\r$/u, ""));
      }
    };
    // Re-ref stdin in case a prior prompt called unref() — resume()
    // by itself doesn't undo unref(), so without this a second prompt
    // in the same run (e.g. email code + TOTP code) would silently
    // drop off the event loop and the process would exit mid-wait.
    process.stdin.ref();
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", onData);
  });
}
