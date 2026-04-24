import sodium from "libsodium-wrappers-sumo";
import WebSocket from "ws";
import {
  ready,
  parseToken,
  computeSecretHash,
  Handshake,
  NK,
  Transport,
} from "../../crypto/index.ts";
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
  buildMintBody,
  newMintNonce,
  type MintReady,
  type MintRequest,
} from "../server/mint-protocol.ts";

/**
 * `pty-relay client join <preauth-url>` — claim a one-time preauth to
 * enroll this device as a daemon-pinned client on an existing account.
 *
 * Wire flow:
 *   1. Parse preauth URL → relay host, minter Curve25519 pubkey, raw secret.
 *   2. Open `/ws?role=client_mint&secret_hash=...&totp_code=...`.
 *      Relay verifies TOTP before routing the pair to the minting daemon.
 *   3. Noise NK handshake as initiator against the minter's Curve25519 pk.
 *   4. Over Noise: send MintRequest with our fresh Ed25519 pubkey;
 *      receive MintReady with the minter's signature over the canonical
 *      preauth payload.
 *   5. Close the Noise tunnel.
 *   6. POST /api/keys/mint (unauthenticated HTTP — the minter_signature
 *      is the proof of authorization).
 *   7. Persist the new `public_account` record.
 */

export interface JoinInput {
  preauthUrl: string;
  label: string;
  totpCode: string;
  /** Seconds this enrollment proposal is valid for. Caps at the preauth's
   *  own expiry server-side. */
  expTtlSeconds?: number;
}

export interface JoinDeps {
  api: PublicApi;
  /** WS factory — override for tests. */
  openWebSocket?: (url: string) => WebSocket;
  generateSigningKeypair?: () => { publicKey: Uint8Array; secretKey: Uint8Array };
  now?: () => number;
  log?: (line: string) => void;
}

export interface JoinResponse {
  public_key: string;
  key_id: string;
  role: string;
  label: string | null;
  minter_key_id: string;
  /** Preauth-claimed clients are pinned to the minting daemon's stable
   *  identity. These fields are populated on every `/api/keys/mint`
   *  response because the relay now only mints role=client preauths
   *  (role=daemon preauth claims are 400). The identity id is stable
   *  across the pinned daemon's key rotations; the pubkey is a hint. */
  pinned_daemon_identity_id: string;
  pinned_daemon_label: string;
  pinned_daemon_public_key: string;
}

export interface JoinResult {
  /** The newly registered KeyIdentity for the claimed role. */
  key: KeyIdentity;
  /** Role the minter signed off on (matches JoinInput.role). */
  role: "daemon" | "client";
  /** Relay origin + account id learned from the enrollment handshake. */
  relayUrl: string;
  accountId: string;
  /** Label the joiner proposed (may be echoed back through the enroll response). */
  label: string;
  enroll: JoinResponse;
}

/** Run a join from URL + TOTP code to a persisted PublicAccount.
 *  No file IO — the caller (joinCommand) stores the result. */
export async function runJoin(
  input: JoinInput,
  deps: JoinDeps
): Promise<JoinResult> {
  await ready();
  const log = deps.log ?? (() => {});

  const parsed = parseToken(input.preauthUrl);
  // Relay origin = scheme://host (no path, no fragment).
  const relayUrl = new URL(input.preauthUrl).origin;

  // Fresh Ed25519 keypair for this device. Never reused across enrollments.
  const kp = deps.generateSigningKeypair?.() ?? defaultKeypair();
  const joinerPubB64 = sodium.to_base64(
    kp.publicKey,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );

  const nonce = await newMintNonce();
  const now = deps.now?.() ?? Math.floor(Date.now() / 1000);
  const exp = now + (input.expTtlSeconds ?? 300);

  // Preauth claims always produce role=client now — the relay rejects
  // role=daemon on /api/keys/mint. New daemons on an existing account
  // go through `server signin` (TOTP-gated) instead.
  const request: MintRequest = {
    type: "mint_request",
    public_key: joinerPubB64,
    label: input.label,
    role: "client",
    nonce,
    exp,
  };

  log(`Opening enrollment channel to ${relayUrl}...`);
  const ready_ = await pairAndExchange(
    input.preauthUrl,
    input.totpCode,
    parsed.publicKey,
    parsed.secret,
    request,
    deps
  );

  log("Received minter signature. Claiming preauth...");
  const enrollRes = await deps.api.post<JoinResponse>(
    "/api/keys/mint",
    buildMintBody(request, ready_)
  );

  const key: KeyIdentity = {
    signingKeys: {
      public: joinerPubB64,
      secret: sodium.to_base64(
        kp.secretKey,
        sodium.base64_variants.URLSAFE_NO_PADDING
      ),
    },
    registeredKeyId: enrollRes.public_key,
    enrolledAt: new Date().toISOString(),
    pin: {
      daemonIdentityId: enrollRes.pinned_daemon_identity_id,
      daemonLabel: enrollRes.pinned_daemon_label,
      daemonPublicKey: enrollRes.pinned_daemon_public_key,
    },
  };

  return {
    key,
    role: "client",
    relayUrl,
    accountId: ready_.account_id,
    label: input.label,
    enroll: enrollRes,
  };
}

/** Open the mint WS, do Noise NK, exchange one round of JSON, close. */
async function pairAndExchange(
  preauthUrl: string,
  totpCode: string,
  minterCurvePk: Uint8Array,
  rawSecret: Uint8Array,
  request: MintRequest,
  deps: JoinDeps
): Promise<MintReady> {
  const wsUrl = buildMintWsUrl(preauthUrl, rawSecret, totpCode);

  const ws = (deps.openWebSocket ?? defaultOpenWebSocket)(wsUrl);
  ws.binaryType = "nodebuffer";

  return new Promise<MintReady>((resolve, reject) => {
    let handshake: Handshake | null = null;
    let transport: Transport | null = null;
    let settled = false;

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      try { ws.close(); } catch {}
      reject(err);
    };
    const succeed = (r: MintReady) => {
      if (settled) return;
      settled = true;
      try { ws.close(); } catch {}
      resolve(r);
    };

    ws.onmessage = (event: any) => {
      try {
        if (typeof event.data === "string") {
          const msg = JSON.parse(event.data);
          if (msg.type === "paired") {
            // Mint pair: joiner has no registered key yet, so NK.
            // The preauth hash gate is enforced by the relay at WS
            // upgrade time; the Noise layer just needs confidentiality.
            handshake = new Handshake({
              pattern: NK,
              initiator: true,
              remoteStaticPublicKey: minterCurvePk,
            });
            ws.send(handshake.writeMessage());
          } else if (msg.type === "waiting_for_approval") {
            // Mint shouldn't need operator approval — the TOTP +
            // preauth hash are the gate. If the relay sends this, surface
            // it as an error rather than hang.
            fail(new Error("relay asked for approval on a mint connection"));
          } else if (msg.type === "error") {
            fail(new Error(msg.message || "relay error"));
          }
          return;
        }

        const data = Buffer.isBuffer(event.data)
          ? event.data
          : Buffer.from(event.data as ArrayBuffer);

        if (!transport && handshake) {
          handshake.readMessage(new Uint8Array(data));
          transport = new Transport(handshake.split());
          handshake = null;
          const ct = transport.encrypt(
            new TextEncoder().encode(JSON.stringify(request))
          );
          ws.send(ct);
        } else if (transport) {
          const plaintext = transport.decrypt(new Uint8Array(data));
          const msg = JSON.parse(new TextDecoder().decode(plaintext));
          if (msg.type === "mint_ready") {
            succeed(msg as MintReady);
          } else if (msg.type === "error") {
            fail(new Error(msg.message || "minter error"));
          }
          // Other message types (e.g. "approved") are informational and ignored.
        }
      } catch (err: any) {
        fail(err instanceof Error ? err : new Error(String(err)));
      }
    };

    ws.onerror = (err: any) => {
      fail(new Error(`WS error: ${err?.message ?? String(err)}`));
    };
    ws.onclose = () => {
      if (!settled) fail(new Error("relay closed the enrollment connection"));
    };
  });
}

/** Construct the ws:// or wss:// URL for role=client_mint. */
export function buildMintWsUrl(
  preauthUrl: string,
  rawSecret: Uint8Array,
  totpCode: string
): string {
  const u = new URL(preauthUrl);
  const scheme = u.protocol === "https:" ? "wss:" : "ws:";
  const secretHash = computeSecretHash(rawSecret);
  const params = new URLSearchParams({
    role: "client_mint",
    secret_hash: secretHash,
    totp_code: totpCode,
  });
  return `${scheme}//${u.host}/ws?${params.toString()}`;
}

function defaultKeypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const kp = sodium.crypto_sign_keypair();
  return { publicKey: kp.publicKey, secretKey: kp.privateKey };
}

function defaultOpenWebSocket(url: string): WebSocket {
  return new WebSocket(url);
}

/** CLI entry point. */
export async function joinCommand(opts: {
  preauthUrl: string;
  label: string;
  totpCode?: string;
  configDir?: string;
  passphraseFile?: string;
}): Promise<void> {
  await ready();

  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });
  const existing = await loadPublicAccount(store);
  const relayOrigin = new URL(opts.preauthUrl).origin;

  // Preauth claims always produce a pinned role=client key. Allowed in
  // two cases:
  //   1. Fresh device — no existing account. Create one with just the
  //      new clientKey.
  //   2. Same account, no current client key. Merge it in. Guards:
  //      relay + accountId must match.
  if (existing) {
    if (existing.relayUrl !== relayOrigin) {
      console.error(
        `This device is already enrolled on ${existing.relayUrl}; the preauth URL is for ${relayOrigin}.`
      );
      console.error("Run `pty-relay reset` to start over on a different relay.");
      process.exit(1);
      return;
    }
    if (existing.clientKey) {
      console.error("This device already has a client key on this account.");
      console.error("Use `pty-relay server rotate --role client` to replace it.");
      process.exit(1);
      return;
    }
  }

  const totpCode =
    opts.totpCode ??
    (await promptStdinLine("TOTP code from minting device: ")).trim();

  const api = new PublicApi(relayOrigin);
  try {
    const { key, relayUrl, accountId, label, enroll } = await runJoin(
      {
        preauthUrl: opts.preauthUrl,
        label: opts.label,
        totpCode,
      },
      { api, log: (l) => console.log(l) }
    );

    let merged: PublicAccount;
    if (existing) {
      if (existing.accountId !== accountId) {
        console.error(
          `Preauth enrolled into account ${accountId} but this device already belongs to ${existing.accountId}.`
        );
        process.exit(1);
        return;
      }
      merged = { ...existing, clientKey: key };
    } else {
      merged = {
        relayUrl,
        email: "",
        accountId,
        label,
        clientKey: key,
      };
    }

    await savePublicAccount(merged, store);
    // The pinned daemon is the only host this client can reach; seed
    // known_hosts with it so `ls` / `connect <pinned-label>` work
    // immediately. We use the pinned daemon's current pubkey (hint;
    // survives rotation via the identity_id stored on the clientKey.pin).
    await savePublicKnownHost(
      {
        label: enroll.pinned_daemon_label,
        relayUrl,
        publicKey: enroll.pinned_daemon_public_key,
        role: "daemon",
      },
      store
    );
    console.log("");
    console.log(
      `Enrolled as client "${label}" on ${relayUrl}, pinned to daemon "${enroll.pinned_daemon_label}".`
    );
    console.log(`Your key id: ${enroll.key_id}`);
  } catch (err: any) {
    if (err instanceof PublicApiError) {
      console.error(`Join failed: ${err.message} (HTTP ${err.status})`);
    } else {
      console.error(`Join failed: ${err?.message ?? err}`);
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
