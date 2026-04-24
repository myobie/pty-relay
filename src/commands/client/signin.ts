import sodium from "libsodium-wrappers-sumo";
import { ready } from "../../crypto/index.ts";
import { openSecretStore } from "../../storage/bootstrap.ts";
import {
  loadPublicAccount,
  savePublicAccount,
  type PublicAccount,
  type KeyIdentity,
} from "../../storage/public-account.ts";
import { PublicApi, PublicApiError } from "../../relay/public-api.ts";

/**
 * `pty-relay client signin --email <addr>` — register a role=client key
 * on an existing public-relay account. The new key is account-wide
 * (NOT daemon-pinned) and can pair with every daemon on the account
 * (subject to ACLs, when those land).
 *
 * Differences from `server signin`:
 *   - The relay rejects client signin for a fresh email — a client key
 *     cannot bootstrap a new account; run `server signin` on some
 *     machine first.
 *   - The verify/totp response omits `totp_secret` (clients never mint
 *     preauths, so they have no business holding the shared TOTP).
 *   - No QR — the TOTP secret is not handed out here.
 */

export interface ClientSigninDeps {
  api: PublicApi;
  generateSigningKeypair?: () => { publicKey: Uint8Array; secretKey: Uint8Array };
  promptLine: (label: string) => Promise<string>;
  log: (line: string) => void;
}

export interface ClientSigninInput {
  email: string;
  relayUrl: string;
  label: string;
  /** Skip the TOTP prompt (automation). */
  overrideTotpCode?: string;
}

export interface ClientSigninResult {
  account: PublicAccount;
}

interface SigninOk { request_id: string }
interface VerifyTotpRequired { status: "totp_required"; request_id: string }
// Distinguish totp_setup if the relay ever sends it on this path —
// we treat it as a hard error because the relay isn't supposed to
// create accounts via client signin.
interface VerifyTotpSetup { status: "totp_setup" }
type VerifyResult = VerifyTotpRequired | VerifyTotpSetup;
interface VerifyTotpOk {
  status: "verified";
  public_key: string;
  account_id: string;
}

export async function runClientSignin(
  input: ClientSigninInput,
  deps: ClientSigninDeps
): Promise<ClientSigninResult> {
  await ready();

  const keypair = deps.generateSigningKeypair?.() ?? defaultSigningKeypair();
  const publicKeyB64 = sodium.to_base64(
    keypair.publicKey,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );
  const secretKeyB64 = sodium.to_base64(
    keypair.secretKey,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );

  deps.log(`Starting client signin for ${input.email} on ${input.relayUrl}...`);

  const signin = await deps.api.post<SigninOk>("/api/signin", {
    email: input.email,
    public_key: publicKeyB64,
    role: "client",
    label: input.label,
  });
  const requestId = signin.request_id;
  deps.log(`Check ${input.email} for a verification code.`);

  const emailCode = await deps.promptLine("Email code (6 digits): ");
  const verify = await deps.api.post<VerifyResult>("/api/verify", {
    request_id: requestId,
    code: emailCode.trim(),
  });

  if (verify.status === "totp_setup") {
    // Belt-and-braces. The relay shouldn't emit this for role=client;
    // if it ever does, we bail rather than stumbling into an account-
    // creation flow from the client side.
    throw new Error(
      "relay returned totp_setup on a client signin — client signin cannot create accounts. Run `pty-relay server signin` first."
    );
  }

  const totpCode =
    input.overrideTotpCode ??
    (await deps.promptLine("TOTP code from your authenticator: ")).trim();

  const verified = await deps.api.post<VerifyTotpOk>("/api/verify/totp", {
    request_id: requestId,
    code: totpCode,
  });

  const clientKey: KeyIdentity = {
    signingKeys: { public: publicKeyB64, secret: secretKeyB64 },
    registeredKeyId: verified.public_key,
    enrolledAt: new Date().toISOString(),
    // No pin — signed-in clients are account-wide.
  };

  // Fresh account record. Callers merge onto an existing one if needed
  // (same-account dual-role case). Email is populated here because
  // we just used it to auth.
  const account: PublicAccount = {
    relayUrl: input.relayUrl,
    email: input.email,
    accountId: verified.account_id,
    label: input.label,
    // No totpSecretB32 — clients never hold the shared TOTP.
    clientKey,
  };

  deps.log("");
  deps.log(`Registered as client "${input.label}" on ${input.relayUrl}.`);
  deps.log("This key can pair with every daemon on the account.");

  return { account };
}

function defaultSigningKeypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, secretKey: kp.privateKey };
}

export async function clientSigninCommand(opts: {
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

  const existing = await loadPublicAccount(store);
  if (existing) {
    if (existing.relayUrl !== opts.relayUrl) {
      console.error(
        `This device is enrolled on ${existing.relayUrl}; signin was pointed at ${opts.relayUrl}.`
      );
      console.error("Run `pty-relay reset` to start over on a different relay.");
      process.exit(1);
    }
    if (existing.clientKey) {
      console.error(
        `This device already has a client key on this account (label "${existing.label}").`
      );
      console.error(
        "Use `pty-relay server rotate --role client` to replace it, or `pty-relay server status` to inspect."
      );
      process.exit(1);
    }
  }

  const api = new PublicApi(opts.relayUrl);

  try {
    const { account: freshAccount } = await runClientSignin(
      { email: opts.email, relayUrl: opts.relayUrl, label: opts.label },
      {
        api,
        promptLine: promptStdinLine,
        log: (line) => console.log(line),
      }
    );
    const merged: PublicAccount = existing
      ? { ...existing, clientKey: freshAccount.clientKey }
      : freshAccount;
    await savePublicAccount(merged, store);
    console.log("");
    console.log("Saved. `pty-relay client ls` will now show hosts on the account.");
  } catch (err: any) {
    if (err instanceof PublicApiError) {
      console.error(`Signin failed: ${err.message} (HTTP ${err.status})`);
    } else {
      console.error(`Signin failed: ${err?.message ?? err}`);
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
