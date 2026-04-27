import sodium from "libsodium-wrappers-sumo";
import { ready } from "../../crypto/index.ts";
import { log, now, sinceMs } from "../../log.ts";
import { openSecretStore } from "../../storage/bootstrap.ts";
import { loadPublicAccount, requireDaemonKey } from "../../storage/public-account.ts";
import { PublicApi, PublicApiError } from "../../relay/public-api.ts";
import { ed25519PkToCurve25519 } from "../../crypto/key-conversion.ts";

/**
 * `pty-relay server mint` — mint a one-time preauth so another device
 * can join this account as a client pinned to this daemon.
 *
 * The mint itself is a single signed HTTP POST (`/api/pairing_hashes/mint`).
 * The actual pairing (Noise handshake + minter-signature exchange)
 * happens later when the joining device runs `pty-relay server join <url>`
 * and this daemon is running `pty-relay server start`. If the daemon
 * isn't running, the preauth stays minted (for its TTL) and can be
 * claimed once serve is up.
 *
 * The resulting client key is daemon-pinned: it can only ever pair
 * with this daemon (per the relay's preauth-pin invariant). If the
 * invitee needs account-wide access, use `client signin` on their
 * end instead.
 */

export interface MintResponse {
  id: string;
  raw_secret: string; // base64url, 32 bytes decoded
  secret_hash: string; // 64-char hex (SHA-256 of raw_secret bytes)
  expires_at: string; // ISO 8601
  purpose: string;
  single_use: boolean;
}

export interface MintInput {
  totpCode: string;
  /** Seconds the preauth remains valid; relay caps at 900. */
  ttlSeconds?: number;
}

export interface MintOutput {
  /** Preauth URL to hand to the joining device (QR-friendly). */
  url: string;
  /** Seconds until the preauth expires — also shown to the user. */
  ttlSeconds: number;
  expiresAt: string;
  mint: MintResponse;
}

/** Mint a preauth + build the URL the joining device will scan/paste.
 *  Pure-ish: hits HTTP but no file IO. Safe to unit-test via the usual
 *  fetch-mock pattern. */
export async function runMint(
  account: {
    relayUrl: string;
    signingKeys: { public: string; secret: string };
  },
  input: MintInput,
  api: PublicApi
): Promise<MintOutput> {
  const start = now();
  await ready();
  log("cli", "mint begin", { relayUrl: account.relayUrl, ttlSeconds: input.ttlSeconds ?? 300 });

  const secret = sodium.from_base64(
    account.signingKeys.secret,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );
  const pub = sodium.from_base64(
    account.signingKeys.public,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );

  const mint = await api.post<MintResponse>(
    "/api/pairing_hashes/mint",
    {
      totp_code: input.totpCode,
      ttl_seconds: input.ttlSeconds ?? 300,
    },
    { signWith: { public: pub, secret } }
  );

  // The preauth URL reuses the self-hosted `#pk.secret` fragment shape
  // because the joining device goes through the same Noise NK path the
  // self-hosted client does. `pk` is the minting daemon's Curve25519
  // static key — which we derive from its Ed25519 via libsodium.
  const curvePk = await ed25519PkToCurve25519(pub);
  const url = buildPreauthUrl(account.relayUrl, curvePk, mint.raw_secret);

  const expiresAt = new Date(mint.expires_at);
  const ttlSeconds = Math.max(
    0,
    Math.floor((expiresAt.getTime() - Date.now()) / 1000)
  );

  log("cli", "mint done", { preauthId: mint.id, ttlSeconds, ms: sinceMs(start) });
  return { url, ttlSeconds, expiresAt: mint.expires_at, mint };
}

/** http(s)://<host>/#<curve25519-pk-b64url>.<raw-secret-b64url> */
export function buildPreauthUrl(
  relayUrl: string,
  curvePk: Uint8Array,
  rawSecretB64: string
): string {
  const base = relayUrl.replace(/\/+$/u, "");
  const pkB64 = sodium.to_base64(
    curvePk,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );
  return `${base}/#${pkB64}.${rawSecretB64}`;
}

/** CLI entry — opens store, loads account, prompts TOTP, calls runMint. */
export async function mintCommand(opts: {
  totpCode?: string;
  ttlSeconds?: number;
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
    console.error(
      "This device isn't enrolled on a public relay yet. Run `pty-relay server signin --email <addr>` first."
    );
    process.exit(1);
  }

  const totpCode =
    opts.totpCode ?? (await promptStdinLine("Current TOTP code: ")).trim();

  const api = new PublicApi(account.relayUrl);
  // Minting is a daemon-role endpoint on the relay; the daemon key of
  // this device is what the mint call must be signed with. Also doubles
  // as the Curve25519 static key the joiner will handshake to when they
  // claim the preauth.
  const daemonKey = requireDaemonKey(account);
  try {
    const { url, ttlSeconds, mint } = await runMint(
      { relayUrl: account.relayUrl, signingKeys: daemonKey.signingKeys },
      { totpCode, ttlSeconds: opts.ttlSeconds },
      api
    );

    // No local bookkeeping needed — the relay carries pairing_hash_id
    // in the `paired` frame when the joining device arrives, so the
    // minting daemon reads it off the wire at signing time.

    console.log("");
    console.log("One-time preauth minted.");
    console.log(`URL:         ${url}`);
    console.log(`Expires:     ${mint.expires_at} (in ${ttlSeconds}s)`);
    console.log("");
    console.log("On the new device, run:");
    console.log(`  pty-relay server join '${url}'`);
    console.log("");
    console.log(
      "The joining device will ask for the current TOTP code from your authenticator."
    );
  } catch (err: any) {
    if (err instanceof PublicApiError) {
      console.error(`Mint failed: ${err.message} (HTTP ${err.status})`);
    } else {
      console.error(`Mint failed: ${err?.message ?? err}`);
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
