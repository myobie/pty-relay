import {
  loadClients,
  saveClients,
  findTokenById,
  generateTokenId,
  signalDaemon,
  type ClientsData,
  type ClientToken,
} from "../relay/clients.ts";
import { loadDaemonConfig } from "../relay/config.ts";
import { createToken } from "../crypto/token.ts";
import { ready } from "../crypto/keys.ts";
import { openSecretStore } from "../storage/bootstrap.ts";

interface CmdOpts {
  configDir?: string;
  passphraseFile?: string;
}

/**
 * List all client tokens, sorted: pending first, then active, then revoked.
 * If `json` is true, emit newline-terminated JSON instead of a table.
 */
export async function clientsList(
  opts: CmdOpts & { json?: boolean } = {}
): Promise<void> {
  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });
  const data = await loadClients(store);

  // Sort: pending, active, revoked
  const order: Record<string, number> = { pending: 0, active: 1, revoked: 2 };
  const sorted = [...data.tokens].sort(
    (a, b) => (order[a.status] ?? 3) - (order[b.status] ?? 3)
  );

  if (opts.json) {
    // Output the full, unabridged ClientToken shape — IDs not truncated,
    // labels as-is, metadata preserved. Callers can do their own formatting.
    process.stdout.write(
      JSON.stringify({ tokens: sorted }, null, 2) + "\n"
    );
    return;
  }

  if (data.tokens.length === 0) {
    console.log("No client tokens.");
    return;
  }

  console.log("");
  console.log(
    padRight("ID", 10) +
    padRight("LABEL", 30) +
    padRight("STATUS", 10) +
    "CREATED"
  );
  console.log("-".repeat(70));

  for (const token of sorted) {
    const id = token.id.slice(0, 8);
    const label = formatLabel(token);
    const status = token.status;
    const created = token.created.slice(0, 16).replace("T", " ");
    console.log(
      padRight(id, 10) +
      padRight(label, 30) +
      padRight(status, 10) +
      created
    );

    // For pending tokens, print extra metadata indented under the row.
    if (token.status === "pending" && token.pending_meta) {
      const { remote_addr, user_agent } = token.pending_meta;
      if (remote_addr) {
        console.log(`            from: ${remote_addr}`);
      }
      if (user_agent) {
        const ua = summarizeUserAgent(user_agent);
        console.log(`            ua:   ${ua}`);
      }
    }
  }
  console.log("");
}

/**
 * Turn a raw `ClientToken` into a short identifying label for the list.
 * Falls back through:
 *  1. token.label (custom label, or backfilled after hello)
 *  2. pending_meta.remote_addr
 *  3. "(unnamed)"
 */
function formatLabel(token: ClientToken): string {
  if (token.label) {
    return token.label.length > 28
      ? token.label.slice(0, 27) + "…"
      : token.label;
  }
  if (token.status === "pending" && token.pending_meta?.remote_addr) {
    return `(pending from ${token.pending_meta.remote_addr})`;
  }
  return "(unnamed)";
}

/**
 * Extract a short, readable identifier from a user agent string.
 * The Chrome UA is 100+ chars and useless in a table; pick out the
 * platform or a "key phrase" if we can, fall back to truncation.
 */
function summarizeUserAgent(ua: string): string {
  // Common patterns, longest first
  const patterns: RegExp[] = [
    /Safari\/[\d.]+ ?\(?([^)]*)\)?/,
    /Chrome\/[\d.]+ ?\(?([^)]*)\)?/,
    /Firefox\/[\d.]+/,
    /Edg\/[\d.]+/,
  ];
  // Platform hint from the parenthetical
  const platformMatch = ua.match(/\(([^)]+)\)/);
  const platform = platformMatch ? platformMatch[1].split(";")[0].trim() : null;

  // Browser name from UA
  let browser: string | null = null;
  if (/Edg\//.test(ua)) browser = "Edge";
  else if (/Chrome\//.test(ua) && !/Edg\//.test(ua)) browser = "Chrome";
  else if (/Firefox\//.test(ua)) browser = "Firefox";
  else if (/Safari\//.test(ua)) browser = "Safari";
  else if (/node/i.test(ua)) browser = "Node";

  if (browser && platform) return `${browser} on ${platform}`;
  if (browser) return browser;
  if (platform) return platform;
  return ua.length > 60 ? ua.slice(0, 57) + "..." : ua;
}

/**
 * Approve a pending client token.
 */
export async function clientsApprove(
  idOrPrefix: string,
  opts: CmdOpts = {}
): Promise<void> {
  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });
  const data = await loadClients(store);
  const token = findTokenById(data, idOrPrefix);

  if (!token) {
    console.error(`No token found matching "${idOrPrefix}"`);
    process.exit(1);
  }

  if (token.status !== "pending") {
    console.error(`Token ${token.id.slice(0, 8)} is ${token.status}, not pending`);
    process.exit(1);
  }

  token.status = "active";
  token.client_id = null; // Clear the relay client_id
  await saveClients(data, store);

  const signaled = signalDaemon(opts.configDir);
  console.log(`Approved token ${token.id.slice(0, 8)}${signaled ? "" : " (daemon not running)"}`);
}

/**
 * Revoke a client token (active or pending).
 */
export async function clientsRevoke(
  idOrPrefix: string,
  opts: CmdOpts = {}
): Promise<void> {
  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });
  const data = await loadClients(store);
  const token = findTokenById(data, idOrPrefix);

  if (!token) {
    console.error(`No token found matching "${idOrPrefix}"`);
    process.exit(1);
  }

  if (token.status === "revoked") {
    console.error(`Token ${token.id.slice(0, 8)} is already revoked`);
    process.exit(1);
  }

  token.status = "revoked";
  token.revoked_at = new Date().toISOString();
  token.client_id = null;
  await saveClients(data, store);

  const signaled = signalDaemon(opts.configDir);
  console.log(`Revoked token ${token.id.slice(0, 8)}${signaled ? "" : " (daemon not running)"}`);
}

/**
 * Generate an invite URL with a pre-approved token.
 */
export async function clientsInvite(
  label?: string,
  opts: CmdOpts = {}
): Promise<void> {
  await ready();

  // Open the store once and reuse it for both loadDaemonConfig and saveClients.
  // loadDaemonConfig would open the store on its own, which (for passphrase
  // backend with interactive TTY) would cause a second prompt — avoid that by
  // opening once and reading the daemon config directly from this store.
  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });

  const tokenId = generateTokenId();
  const data = await loadClients(store);

  data.tokens.push({
    id: tokenId,
    label: label || null,
    status: "active",
    client_id: null,
    created: new Date().toISOString(),
    revoked_at: null,
  });
  await saveClients(data, store);

  try {
    const { setupConfig } = await import("../crypto/keys.ts");
    const { config } = await setupConfig(store);
    const url = createToken(
      "localhost:8099",
      config.publicKey,
      config.secret,
      undefined,
      tokenId
    );
    console.log(`Invite token: ${tokenId.slice(0, 8)}`);
    console.log(`Invite URL: ${url}`);
    if (label) {
      console.log(`Label: ${label}`);
    }
  } catch (err: any) {
    console.error(`Failed to build invite URL: ${err.message}`);
    console.log(`Token ID created: ${tokenId.slice(0, 8)} (full: ${tokenId})`);
  }
}

function padRight(str: string, width: number): string {
  return str.length >= width ? str : str + " ".repeat(width - str.length);
}
