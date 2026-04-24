import sodium from "libsodium-wrappers-sumo";
import {
  loadKnownHosts,
  isPublicHost,
  type KnownHost,
} from "./known-hosts.ts";
import { loadPublicAccount } from "../storage/public-account.ts";
import type { SecretStore } from "../storage/secret-store.ts";
import type { PublicTarget } from "./relay-client.ts";

/**
 * A resolved host — either self-hosted (has a token URL) or public-relay
 * (has a PublicTarget the caller can hand to the public-mode one-shots
 * in relay-client.ts).
 */
export type ResolvedHost =
  | { kind: "self"; label: string; url: string }
  | { kind: "public"; label: string; target: PublicTarget; role?: "daemon" | "client" };

/**
 * Resolve a `pty-relay <cmd> <host-label>` argument to either a token
 * URL (self-hosted) or a PublicTarget (public-relay). Used by every
 * session command so each can dispatch to the right transport without
 * duplicating the lookup + account-loading logic.
 *
 * Throws with a user-facing message when:
 *   - no host by that label exists
 *   - the label maps to a public host but this device has no
 *     public_account (can't sign the client_pair URL)
 */
export async function resolveHost(
  label: string,
  store: SecretStore
): Promise<ResolvedHost> {
  const hosts = await loadKnownHosts(store);
  const host = hosts.find((h) => h.label === label);
  if (!host) {
    throw new Error(
      `No known host "${label}". Run \`pty-relay ls\` to list hosts.`
    );
  }

  if (!isPublicHost(host)) {
    // Self-hosted: url must be set by loadKnownHosts's parser.
    return { kind: "self", label, url: (host as KnownHost).url! };
  }

  // Public-relay: we need the caller's own Ed25519 keys to sign the
  // client_pair connection. Those live in `public_account`.
  const account = await loadPublicAccount(store);
  if (!account) {
    throw new Error(
      `"${label}" is on a public relay but this device isn't enrolled. ` +
        `Run \`pty-relay client signin --email <addr>\` (account-wide) or \`pty-relay server join <url>\` (pinned) first.`
    );
  }
  if (account.relayUrl !== host.relayUrl) {
    throw new Error(
      `"${label}" is on relay ${host.relayUrl} but this device is enrolled on ${account.relayUrl}.`
    );
  }

  // Pair-to-daemon connections open as role=client_pair on the relay,
  // which requires the caller's key to be a client-role key. Fail fast
  // if this device enrolled as daemon only.
  const clientKey = account.clientKey;
  if (!clientKey) {
    throw new Error(
      `"${label}" is on a public relay but this device has no client key. ` +
        `Enroll this device as a client (\`pty-relay server join --role client <preauth-url>\`) from an enrolled daemon.`
    );
  }
  const accountKeys = {
    public: sodium.from_base64(
      clientKey.signingKeys.public,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
    secret: sodium.from_base64(
      clientKey.signingKeys.secret,
      sodium.base64_variants.URLSAFE_NO_PADDING
    ),
  };

  return {
    kind: "public",
    label,
    role: host.role,
    target: {
      relayUrl: host.relayUrl,
      targetPublicKeyB64: host.publicKey,
      accountKeys,
    },
  };
}
