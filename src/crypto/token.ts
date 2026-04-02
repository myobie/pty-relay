import sodium from "libsodium-wrappers-sumo";
import { createHash } from "node:crypto";

/**
 * Create a token URL from relay host, public key, and secret.
 *
 * Format: https://host/session#base64url(publicKey).base64url(secret)
 *         http://localhost:port/session#base64url(publicKey).base64url(secret)
 *
 * Security note: tokens are daemon-scoped, not session-scoped. The session
 * name in the URL path is a convenience default — the client can request any
 * session on the daemon after the encrypted tunnel is established. Anyone
 * with a valid token has full access to all pty sessions on that daemon.
 * Per-session access control is a future feature (accounts + ACLs).
 */
export function createToken(
  host: string,
  publicKey: Uint8Array,
  secret: Uint8Array,
  session?: string,
  clientToken?: string
): string {
  const keyB64 = sodium.to_base64(
    publicKey,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );
  const secretB64 = sodium.to_base64(
    secret,
    sodium.base64_variants.URLSAFE_NO_PADDING
  );

  const scheme = isLocalhost(host) ? "http" : "https";
  const sessionPath = session ? `/${session}` : "";

  let fragment = `${keyB64}.${secretB64}`;
  if (clientToken) {
    fragment += `.${clientToken}`;
  }

  return `${scheme}://${host}${sessionPath}#${fragment}`;
}

export interface ParsedToken {
  host: string;
  session: string | null;
  publicKey: Uint8Array;
  secret: Uint8Array;
  clientToken: string | null;
}

/**
 * Parse a token URL into its components.
 * Throws on invalid format.
 */
export function parseToken(tokenUrl: string): ParsedToken {
  let url: URL;
  try {
    url = new URL(tokenUrl);
  } catch {
    throw new Error(`Invalid token URL: ${tokenUrl}`);
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(
      `Invalid token URL scheme: ${url.protocol} (expected http: or https:)`
    );
  }

  const fragment = url.hash.slice(1); // remove leading #
  if (!fragment) {
    throw new Error("Token URL missing fragment (no # with key.secret)");
  }

  const parts = fragment.split(".");
  if (parts.length < 2 || parts.length > 3) {
    throw new Error(
      "Token URL fragment must contain two or three base64url values separated by ."
    );
  }

  const [keyB64, secretB64] = parts;
  const clientToken = parts.length === 3 ? parts[2] : null;

  let publicKey: Uint8Array;
  let secret: Uint8Array;

  try {
    publicKey = sodium.from_base64(
      keyB64,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
  } catch {
    throw new Error("Invalid base64url public key in token");
  }

  try {
    secret = sodium.from_base64(
      secretB64,
      sodium.base64_variants.URLSAFE_NO_PADDING
    );
  } catch {
    throw new Error("Invalid base64url secret in token");
  }

  if (publicKey.length !== 32) {
    throw new Error(
      `Public key must be 32 bytes, got ${publicKey.length}`
    );
  }

  if (secret.length !== 32) {
    throw new Error(`Secret must be 32 bytes, got ${secret.length}`);
  }

  const host = url.port ? `${url.hostname}:${url.port}` : url.hostname;

  // Session is the URL path, stripping leading /
  const pathStr = url.pathname.replace(/^\//, "");
  const session = pathStr.length > 0 ? pathStr : null;

  return { host, session, publicKey, secret, clientToken };
}

/**
 * Compute SHA-256 hash of the secret, returned as a 64-char hex string.
 * This is sent to the relay as the secret_hash query parameter.
 */
export function computeSecretHash(secret: Uint8Array): string {
  return createHash("sha256").update(secret).digest("hex");
}

/**
 * Derive the WebSocket URL from a parsed token.
 */
export function getWebSocketUrl(
  host: string,
  role: "daemon" | "client",
  secretHash: string,
  authParams?: { public_key: string; payload: string; sig: string },
  clientToken?: string
): string {
  const scheme = isLocalhost(host) ? "ws" : "wss";
  let url = `${scheme}://${host}/ws?role=${role}&secret_hash=${secretHash}`;
  if (authParams) {
    url += `&public_key=${encodeURIComponent(authParams.public_key)}`;
    url += `&payload=${encodeURIComponent(authParams.payload)}`;
    url += `&sig=${encodeURIComponent(authParams.sig)}`;
  }
  if (clientToken) {
    url += `&client_token=${encodeURIComponent(clientToken)}`;
  }
  return url;
}

function isLocalhost(host: string): boolean {
  const hostname = host.split(":")[0];
  return hostname === "localhost" || hostname === "127.0.0.1";
}
