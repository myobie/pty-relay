import sodium from "libsodium-wrappers-sumo";
import {
  ready,
  type Config,
} from "../../crypto/index.ts";
import { log } from "../../log.ts";
import { openSecretStore } from "../../storage/bootstrap.ts";
import { loadPublicAccount, requireDaemonKey } from "../../storage/public-account.ts";
import {
  ed25519PkToCurve25519,
  ed25519SkToCurve25519,
} from "../../crypto/key-conversion.ts";
import {
  PrimaryRelayConnection,
  REVOKED_CLOSE_CODE,
} from "../../relay/primary-connection.ts";
import { RelayConnection } from "../../relay/relay-connection.ts";
import { SessionBridge } from "../../relay/session-bridge.ts";
import { ClientTracker } from "../../relay/client-tracker.ts";
import {
  buildPublicDaemonUrl,
} from "../../relay/public-server-url.ts";
import { EventFollower } from "@myobie/pty/client";
import { signMinterPayload } from "./mint-protocol.ts";
import {
  handleSessionControlMessage,
  teardownSharedClient,
} from "../start-shared.ts";

/**
 * `pty-relay server start` — run the daemon half of a public-relay
 * account. Connects to the public relay's primary socket with Ed25519
 * auth, spawns per-client Noise tunnels on demand, and services the
 * shared session vocabulary (list / attach / peek / send / tag /
 * events_subscribe / spawn) plus `mint_request` for minter-signed joins.
 *
 * The session vocabulary lives in `../start-shared.ts`; this module
 * is the public-mode transport + primary-connection wrapper.
 */

const MAX_CLIENTS = 10;

interface ClientSession {
  connection: RelayConnection;
  bridge: SessionBridge | null;
  tracker: ClientTracker;
  eventsFollower?: EventFollower;
  eventsHeartbeat?: ReturnType<typeof setInterval>;
  /** For enrollment pairs: the relay tells us which pairing hash this
   *  peer is claiming via the "paired" frame. The minter signature
   *  payload needs it, but the joining device can't know it. */
  pairingHashId?: string;
}

export interface StartOptions {
  allowNewSessions?: boolean;
  autoReconnectMs?: number;
  passphraseFile?: string;
}

export async function startCommand(
  configDir: string | undefined,
  options: StartOptions = {}
): Promise<void> {
  await ready();
  log("cli", "server start begin", {
    configDir,
    allowNewSessions: !!options.allowNewSessions,
  });

  const { store } = await openSecretStore(configDir, {
    interactive: true,
    passphraseFile: options.passphraseFile,
  });

  const loaded = await loadPublicAccount(store);
  if (!loaded) {
    console.error(
      "This device isn't enrolled on a public relay. Run `pty-relay server signin --email <addr>` first."
    );
    process.exit(1);
    return;
  }
  const account = loaded;

  // Current account + derived keys, kept in a mutable holder so
  // `server rotate --complete` (which rewrites the on-disk record) is
  // picked up transparently at the next primary reconnect. Without
  // this, the old Ed25519 key stays in-memory and every subsequent
  // WS upgrade fails with 401 "public key not registered."
  interface KeyState {
    accountId: string;
    relayUrl: string;
    label: string;
    accountKeys: { public: Uint8Array; secret: Uint8Array };
    sessionConfig: Config;
  }

  async function deriveKeyState(
    acct: NonNullable<Awaited<ReturnType<typeof loadPublicAccount>>>
  ): Promise<KeyState> {
    const daemonKey = requireDaemonKey(acct);
    const edPk = sodium.from_base64(
      daemonKey.signingKeys.public,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    const edSk = sodium.from_base64(
      daemonKey.signingKeys.secret,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
    const curvePk = await ed25519PkToCurve25519(edPk);
    const curveSk = await ed25519SkToCurve25519(edSk);
    return {
      accountId: acct.accountId,
      relayUrl: acct.relayUrl,
      label: acct.label,
      accountKeys: { public: edPk, secret: edSk },
      sessionConfig: {
        publicKey: curvePk,
        secretKey: curveSk,
        secret: new Uint8Array(32),
        signPublicKey: edPk,
        signSecretKey: edSk,
      },
    };
  }

  let state = await deriveKeyState(account);

  /** Reload account from disk and derive fresh keys. Called on each
   *  primary reconnect so key rotations land without a process restart. */
  async function reloadState(): Promise<void> {
    const fresh = await loadPublicAccount(store);
    if (!fresh) return; // reset happened mid-run; keep last-known good
    state = await deriveKeyState(fresh);
  }

  console.log(`Connecting to ${state.relayUrl} as ${state.label}...`);
  if (options.allowNewSessions) {
    console.warn(
      "WARNING: --allow-new-sessions is enabled. Remote clients on this account can start new pty sessions."
    );
  }

  const clients = new Map<string, ClientSession>();

  function teardownClient(clientId: string): void {
    const cs = clients.get(clientId);
    if (!cs) return;
    teardownSharedClient(cs);
    cs.connection.close();
    clients.delete(clientId);
    log("bridge", "per-client torn down", { clientId, remaining: clients.size });
    console.log(`Client ${clientId} disconnected. (${clients.size} active)`);
  }

  function openClientConnection(clientId: string): void {
    log("bridge", "per-client connect", { clientId });
    const tracker = new ClientTracker();
    const urlFactory = () =>
      buildPublicDaemonUrl(state.relayUrl, state.accountKeys, { clientId });

    const connection = new RelayConnection(urlFactory, state.sessionConfig, {
      onPaired: (meta) => {
        console.log(
          `Client ${clientId} paired.${meta.pairing_hash_id ? ` (enrollment for preauth ${meta.pairing_hash_id.slice(0, 8)})` : ""}`
        );
        const cs = clients.get(clientId);
        if (cs && meta.pairing_hash_id) {
          cs.pairingHashId = meta.pairing_hash_id;
        }
      },
      onHandshakeComplete: () => {
        // No operator approval in public-relay mode — Ed25519 on the WS
        // handshake is the gate.
      },
      onEncryptedMessage: (plaintext: Uint8Array) => {
        const cs = clients.get(clientId);
        if (!cs) return;
        if (
          handleControlMessage(
            clientId,
            cs,
            tracker,
            plaintext,
            state.accountKeys.secret,
            state.accountId,
            options
          )
        ) {
          return;
        }
        if (cs.bridge?.isConnected()) {
          cs.bridge.handleRelayData(plaintext);
        }
      },
      onPeerDisconnected: () => {
        teardownClient(clientId);
      },
      onError: (err: Error) => {
        console.error(`Client ${clientId} error: ${err.message}`);
        // Defense: teardown on error in case onClose doesn't follow
        // (e.g. an error during setup that doesn't reach the WS-level
        // close event). teardownClient is idempotent.
        teardownClient(clientId);
      },
      onClose: () => {
        teardownClient(clientId);
      },
    });

    clients.set(clientId, {
      connection,
      bridge: null,
      tracker,
    });
    connection.connect();
  }

  const primaryUrlFactory = () =>
    buildPublicDaemonUrl(state.relayUrl, state.accountKeys, {
      label: state.label,
    });

  const ts = () => new Date().toISOString().slice(11, 23);
  // Latched when the relay sends `{type:"revoked"}` or closes with
  // code 4001. The close handler below checks this before scheduling
  // a reconnect — a revoked key would loop on 401 forever otherwise,
  // and the operator wouldn't see why. One-shot: survives the
  // transition from revoked frame → close event.
  let revoked = false;
  const primary = new PrimaryRelayConnection(primaryUrlFactory, {
    onConnected: () => {
      console.log(`[${ts()}] Primary control connection established.`);
    },
    onClientWaiting: (clientId: string) => {
      if (clients.size >= MAX_CLIENTS) {
        console.warn(
          `[${ts()}] Rejecting client ${clientId}: max ${MAX_CLIENTS} reached`
        );
        primary.sendText(
          JSON.stringify({
            type: "reject_client",
            client_id: clientId,
            reason: "max clients reached",
          })
        );
        return;
      }
      console.log(`[${ts()}] Client ${clientId} waiting — opening per-client channel`);
      openClientConnection(clientId);
    },
    onClientDisconnected: (clientId: string) => {
      teardownClient(clientId);
    },
    onError: (err: Error) => {
      console.error(
        `[${ts()}] Primary error: ${err.message ?? "(empty)"} type=${(err as any)?.type ?? "?"} code=${(err as any)?.code ?? "?"}`
      );
    },
    onRevoked: () => {
      revoked = true;
      console.error(
        `[${ts()}] Primary revoked by relay. This daemon's key is no longer valid on ${state.relayUrl}.`
      );
      console.error(
        "Run `pty-relay server signin --email <addr>` to enroll a fresh key, or `pty-relay reset` to wipe this device's credentials."
      );
    },
    onClose: (code?: number) => {
      for (const id of clients.keys()) teardownClient(id);
      if (revoked || code === REVOKED_CLOSE_CODE) {
        // Terminal: don't reconnect. A revoked key would loop on 401
        // forever, which is worse than just exiting and letting the
        // operator deal with it.
        console.error(
          `[${ts()}] Primary closed code=${code ?? "?"} (revoked) — not reconnecting.`
        );
        process.exit(1);
      }
      console.error(`[${ts()}] Primary closed code=${code ?? "?"} — reconnecting`);
      const delay = options.autoReconnectMs ?? 2_000;
      // Reload state before reconnecting. If a `server rotate --complete`
      // just ran on the same machine, the old key is now revoked and
      // the primary would loop with 401; the fresh load picks up the
      // new key so the next attempt succeeds.
      setTimeout(async () => {
        try { await reloadState(); } catch {}
        primary.connect();
      }, delay);
    },
  });

  process.on("SIGINT", () => {
    primary.close();
    process.exit(0);
  });

  primary.connect();
}

/** Decode a control frame and dispatch. Returns true if handled; false
 *  means the bytes are binary-relay data for the session bridge.
 *
 *  Public-mode-specific: the `mint_request` branch signs a preauth
 *  claim for a joining device. Everything else is common session
 *  vocabulary and delegated to handleSessionControlMessage. */
function handleControlMessage(
  clientId: string,
  cs: ClientSession,
  tracker: ClientTracker,
  plaintext: Uint8Array,
  minterSecretKey: Uint8Array,
  accountId: string,
  options: StartOptions
): boolean {
  if (plaintext.length === 0 || plaintext[0] !== 0x7b) return false;
  let msg: Record<string, unknown>;
  try {
    msg = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    return false;
  }
  const type = msg.type;
  const reply = (payload: Record<string, unknown>) => {
    try {
      cs.connection.send(new TextEncoder().encode(JSON.stringify(payload)));
    } catch {
      // Connection torn down; nothing to do.
    }
  };

  if (type === "hello") {
    tracker.setClient(msg);
    const meta = tracker.getClient();
    if (meta) console.log(`Client ${clientId}: ${meta.client} on ${meta.os}`);
    return true;
  }

  if (type === "mint_request") {
    handleMintRequest(msg, minterSecretKey, accountId, cs.pairingHashId, reply).catch(
      (err) => {
        reply({ type: "error", message: err?.message ?? "mint failed" });
      }
    );
    return true;
  }

  return handleSessionControlMessage(msg, cs, clientId, {
    allowNewSessions: options.allowNewSessions,
    log: (m) => console.log(m),
  });
}

export async function handleMintRequest(
  msg: Record<string, unknown>,
  minterSecretKey: Uint8Array,
  accountId: string,
  pairingHashId: string | undefined,
  reply: (payload: Record<string, unknown>) => void
): Promise<void> {
  // Minimal structural validation — the TOTP gate was already enforced
  // by the relay at WS upgrade time, so at this point the joiner is an
  // authorized party for this preauth. Preauth claims are client-only
  // now; a `role=daemon` request would be rejected by the relay on the
  // subsequent /api/keys/mint call anyway, but we short-circuit here so
  // the joiner gets a clear message over the tunnel.
  const pubkey = msg.public_key;
  const label = msg.label;
  const role = msg.role;
  const nonce = msg.nonce;
  const exp = msg.exp;
  if (
    typeof pubkey !== "string" ||
    typeof label !== "string" ||
    role !== "client" ||
    typeof nonce !== "string" ||
    typeof exp !== "number"
  ) {
    reply({ type: "error", message: "malformed mint_request (role must be client)" });
    return;
  }

  // The preauth_hash_id comes from the relay's `paired` frame (see
  // relay_socket.ex client_pair_meta). No local state — the relay
  // already knows which preauth this peer claimed at WS upgrade time.
  if (!pairingHashId) {
    reply({
      type: "error",
      message: "pairing_hash_id missing from paired frame (peer isn't a client_mint)",
    });
    return;
  }

  const sig = await signMinterPayload({
    minterSecretKey,
    accountId,
    joinerPublicKeyB64: pubkey,
    preauthHashId: pairingHashId,
    nonce,
    exp,
  });
  reply({
    type: "mint_ready",
    minter_signature: sig,
    preauth_hash_id: pairingHashId,
    account_id: accountId,
  });
}
