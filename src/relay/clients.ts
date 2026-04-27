import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import type { SecretStore } from "../storage/secret-store.ts";
import { getSessionDir } from "@myobie/pty/client";
import { log } from "../log.ts";

export interface ClientToken {
  id: string;
  label: string | null;
  status: "active" | "revoked" | "pending";
  client_id: string | null;
  created: string;
  revoked_at: string | null;
  /**
   * Metadata captured from the network layer when the client first
   * connected (before the encrypted tunnel exists). Helpful for
   * identifying pending clients in `pty-relay clients list`.
   */
  pending_meta?: {
    remote_addr?: string | null;
    user_agent?: string | null;
    origin?: string | null;
  };
}

export interface ClientsData {
  tokens: ClientToken[];
}

function defaultConfigDir(): string {
  return path.join(getSessionDir(), "relay");
}

function daemonPidPath(configDir?: string): string {
  const dir = configDir ?? defaultConfigDir();
  return path.join(dir, "daemon.pid");
}

/**
 * Load the clients data from the store. Returns `{tokens:[]}` if nothing is
 * stored yet or the stored data is malformed.
 */
export async function loadClients(store: SecretStore): Promise<ClientsData> {
  try {
    const bytes = await store.load("clients");
    if (!bytes) return { tokens: [] };
    const data = JSON.parse(new TextDecoder().decode(bytes));
    if (data && Array.isArray(data.tokens)) {
      return data as ClientsData;
    }
    return { tokens: [] };
  } catch {
    return { tokens: [] };
  }
}

/**
 * Save the clients data to the store (atomic write at the store level).
 */
export async function saveClients(
  data: ClientsData,
  store: SecretStore
): Promise<void> {
  const bytes = new TextEncoder().encode(JSON.stringify(data, null, 2));
  await store.save("clients", bytes);
}

/**
 * Per-store mutation queue. Any `load → modify → save` sequence must go
 * through {@link updateClients} so concurrent connect/approve/revoke paths
 * cannot read stale snapshots and overwrite each other's writes. Without
 * this, a revocation racing against a new-client connection could resurrect
 * the revoked token when the stale snapshot gets re-saved.
 *
 * The queue is per-`SecretStore` via WeakMap; cross-process races between
 * the daemon and the `pty-relay clients` CLI are NOT handled here — for
 * those, the CLI must signal the daemon to do the write (the existing
 * `signalDaemon` / SIGUSR1 path).
 */
const clientsMutationQueue = new WeakMap<SecretStore, Promise<void>>();

export async function updateClients<T>(
  store: SecretStore,
  mutator: (data: ClientsData) => T | Promise<T>
): Promise<T> {
  const prev = clientsMutationQueue.get(store) ?? Promise.resolve();
  let result: T;
  const work = prev.then(async () => {
    const before = await loadClients(store);
    const beforeCount = before.tokens.length;
    result = await mutator(before);
    await saveClients(before, store);
    log("store", "clients mutated", {
      tokens: before.tokens.length,
      delta: before.tokens.length - beforeCount,
    });
  });
  // Swallow failures on the queue head so the next mutation can still run.
  // The original caller still sees the error via `await work` below.
  clientsMutationQueue.set(store, work.catch(() => {}));
  await work;
  return result!;
}

/**
 * Find a token by exact ID. This is the only safe lookup to use on the
 * network-facing auth path: the prefix-match convenience below must never
 * gate remote authentication, because the daemon logs 8-char token prefixes
 * at every connect, so a short prefix is trivially observable by anyone
 * reading the log or seeing the operator TUI.
 */
export function findTokenByExactId(
  data: ClientsData,
  id: string
): ClientToken | undefined {
  return data.tokens.find((t) => t.id === id);
}

/**
 * Find a token by full ID or unique prefix. For operator-CLI use only
 * (`pty-relay clients approve <prefix>`, `... revoke <prefix>`) — never
 * call this on a remote-supplied token.
 */
export function findTokenById(
  data: ClientsData,
  id: string
): ClientToken | undefined {
  // Exact match first
  const exact = findTokenByExactId(data, id);
  if (exact) return exact;

  // Prefix match — operator convenience only
  const matches = data.tokens.filter((t) => t.id.startsWith(id));
  if (matches.length === 1) return matches[0];

  return undefined;
}

/**
 * Find a pending token by relay client_id.
 */
export function findPendingByClientId(
  data: ClientsData,
  clientId: string
): ClientToken | undefined {
  return data.tokens.find(
    (t) => t.status === "pending" && t.client_id === clientId
  );
}

/**
 * Generate a random 24-char hex token ID.
 */
export function generateTokenId(): string {
  return crypto.randomBytes(12).toString("hex");
}

/**
 * Write the current process PID to daemon.pid (plaintext — not a secret).
 * Returns a cleanup function that deletes the file.
 */
export function saveDaemonPid(configDir?: string): () => void {
  const filePath = daemonPidPath(configDir);
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, String(process.pid), { mode: 0o600 });

  return () => {
    try {
      // Only delete if the file still contains our PID
      const content = fs.readFileSync(filePath, "utf-8").trim();
      if (content === String(process.pid)) {
        fs.unlinkSync(filePath);
      }
    } catch {
      // ignore
    }
  };
}

/**
 * Send SIGUSR1 to the daemon process (read PID from daemon.pid).
 * No-op if the file is missing or the process is dead.
 */
export function signalDaemon(configDir?: string): boolean {
  const filePath = daemonPidPath(configDir);
  try {
    const content = fs.readFileSync(filePath, "utf-8").trim();
    const pid = parseInt(content, 10);
    if (isNaN(pid)) return false;

    // Check if process exists (signal 0 doesn't send a signal but checks existence)
    process.kill(pid, 0);
    // Process exists, send SIGUSR1
    process.kill(pid, "SIGUSR1");
    log("serve", "signaled daemon", { pid });
    return true;
  } catch {
    return false;
  }
}
