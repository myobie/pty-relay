import type { SecretStore } from "../storage/secret-store.ts";
import { log } from "../log.ts";

/**
 * A saved relay host. Supports three flavors:
 *
 *   self-hosted: `{label, url}` where url is the classic `#pk.secret`
 *     token-url form. Used by `pty-relay connect <token-url>` and saved
 *     automatically on first use.
 *
 *   public-relay: `{label, relayUrl, publicKey, role?}` with no `url`.
 *     Used by `pty-relay server signin` / `server join` to record the
 *     account's own daemon, and by `pty-relay server hosts` to record
 *     peer daemons on the same account. Daily-use `connect <label>`
 *     opens a `role=client_pair` WS against the relay, targeting
 *     `publicKey`.
 *
 *   ssh: `{label, sshUrl}` where sshUrl is a `ssh://[user@]host[:port]`
 *     URL. Used by `pty-relay add ssh://…` for ssh-reachable hosts that
 *     don't need a relay daemon — `ls`/`peek`/`send`/etc. shell out to
 *     `ssh <host> pty <cmd>` directly. See `docs/ssh-transport.md`.
 *
 * `role` is informational for public-mode entries (daemon vs client) and
 * lets `ls` decide which rows to include in the session view.
 */
export interface KnownHost {
  label: string;
  /** Self-hosted `#pk.secret` URL. Omitted for non-self-hosted hosts. */
  url?: string;
  /** Public-relay origin, e.g. `http://localhost:4000`. */
  relayUrl?: string;
  /** Target daemon's Ed25519 pubkey (base64url). */
  publicKey?: string;
  /** Peer role on the account. */
  role?: "daemon" | "client";
  /** `ssh://[user@]host[:port]` URL for ssh-reachable peers. The host is
   *  reached by shelling out to `ssh <user@host> pty <op>`; no relay
   *  daemon required. */
  sshUrl?: string;
}

/** True iff this entry was registered via the public-relay flow. */
export function isPublicHost(h: KnownHost): h is KnownHost & {
  relayUrl: string;
  publicKey: string;
} {
  return typeof h.relayUrl === "string" && typeof h.publicKey === "string";
}

/** True iff this entry is an ssh:// peer (no relay daemon). */
export function isSshHost(h: KnownHost): h is KnownHost & { sshUrl: string } {
  return typeof h.sshUrl === "string";
}

function parseHost(item: unknown): KnownHost | null {
  if (!item || typeof item !== "object") return null;
  const o = item as Record<string, unknown>;
  if (typeof o.label !== "string") return null;

  const host: KnownHost = { label: o.label };
  if (typeof o.url === "string") host.url = o.url;
  if (typeof o.relayUrl === "string") host.relayUrl = o.relayUrl;
  if (typeof o.publicKey === "string") host.publicKey = o.publicKey;
  if (o.role === "daemon" || o.role === "client") host.role = o.role;
  if (typeof o.sshUrl === "string") host.sshUrl = o.sshUrl;

  // Reject entries that have no transport (neither self-hosted, public-
  // relay, nor ssh).
  if (
    !host.url &&
    !(host.relayUrl && host.publicKey) &&
    !host.sshUrl
  ) {
    return null;
  }
  return host;
}

/**
 * Load known hosts. Returns an empty array if the store is empty or its
 * contents are malformed; callers should never crash just because the
 * hosts file is bad.
 */
export async function loadKnownHosts(
  store: SecretStore
): Promise<KnownHost[]> {
  try {
    const bytes = await store.load("hosts");
    if (!bytes) {
      log("hosts", "load", { count: 0, source: "empty" });
      return [];
    }
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    if (!Array.isArray(parsed)) {
      log("hosts", "load malformed", { parsed: typeof parsed });
      return [];
    }

    const result: KnownHost[] = [];
    let skipped = 0;
    for (const item of parsed) {
      const host = parseHost(item);
      if (host) result.push(host);
      else skipped++;
    }
    log("hosts", "load", {
      count: result.length,
      skipped,
      publicCount: result.filter((h) => !!h.relayUrl).length,
      selfHostedCount: result.filter((h) => !!h.url).length,
    });
    return result;
  } catch (err: any) {
    log("hosts", "load failed", { error: err?.message ?? String(err) });
    return [];
  }
}

/**
 * Pick a label that doesn't collide with anything already in
 * `usedLabels`. If the wanted label is free we return it unchanged;
 * otherwise we suffix with a prefix of `distinguisher` (4 chars,
 * widening to 8, 12, … in steps of 4 until the result is unique).
 *
 *   `wanted="laptop"`, distinguisher="abcd1234…"  →  "laptop-abcd"
 *   if "laptop-abcd" is already used               →  "laptop-abcd1234"
 *
 * Callers supply the `distinguisher` from whatever stable identifier
 * they have — a token URL's host/pubkey, a public-relay pubkey, etc.
 * The 4-char step is small enough to stay readable while providing
 * enough entropy that ambiguity basically doesn't happen in practice
 * (4 hex chars = 16 bits).
 */
export function pickUniqueLabel(
  wanted: string,
  distinguisher: string,
  usedLabels: Set<string>
): string {
  if (!usedLabels.has(wanted)) return wanted;
  // First try increasingly-long prefixes of the distinguisher.
  let width = 4;
  let candidate = `${wanted}-${distinguisher.slice(0, width)}`;
  while (usedLabels.has(candidate) && width < distinguisher.length) {
    width += 4;
    candidate = `${wanted}-${distinguisher.slice(0, width)}`;
  }
  if (!usedLabels.has(candidate)) return candidate;
  // Distinguisher exhausted (short or all-colliding). Fall back to a
  // numeric counter. The base is whatever longest-prefix candidate we
  // ended up with — e.g. "laptop-pk-2", "laptop-pk-3", … — so callers
  // still see a deterministic, human-readable name.
  for (let n = 2; ; n++) {
    const numbered = `${candidate}-${n}`;
    if (!usedLabels.has(numbered)) return numbered;
  }
}

function urlHost(u: string): string | null {
  try { return new URL(u).host; } catch { return null; }
}

/**
 * Save a self-hosted host. The HOST (URL origin) is the unique key:
 * repeated saves for the same host — even with a rotated `#pk.secret`
 * fragment — update the entry in place. This matters when the remote
 * daemon's state is wiped and it comes back up with fresh key material:
 * connecting with the new token URL should overwrite the stale entry,
 * not append a second one. If the label collides with a DIFFERENT host
 * (different URL host / different public-relay entry), the new entry's
 * label gets a URL-derived suffix so both can coexist.
 *
 * The old behavior dedup'd on the full URL including the fragment,
 * which meant any pubkey/secret rotation left a stale entry alongside
 * the new one — and worse, the stale entry kept the original label,
 * so `connect <label>` would resolve to the stale row.
 */
export async function saveKnownHost(
  label: string,
  url: string,
  store: SecretStore
): Promise<void> {
  const existing = await loadKnownHosts(store);
  const incomingHost = urlHost(url);
  // Drop any prior self-hosted entry for the same host (this is the
  // identity key — same daemon, possibly rotated key material). Keep
  // public-relay entries (no url) and any entries whose stored url is
  // malformed (defensive — we can't decide what host they belong to).
  const kept = existing.filter((h) => {
    if (h.url == null) return true;
    const existingHost = urlHost(h.url);
    if (existingHost == null) return true;
    return existingHost !== incomingHost;
  });
  const usedLabels = new Set(kept.map((h) => h.label));
  const finalLabel = pickUniqueLabel(label, url, usedLabels);
  kept.push({ label: finalLabel, url });
  await persist(kept, store);
  log("hosts", "save self-hosted", { label: finalLabel, collidedWith: finalLabel !== label ? label : undefined });
}

/**
 * Save a public-relay host: a daemon on a remote account identified
 * by its Ed25519 pubkey, reachable via the relay at `relayUrl`. The
 * (relayUrl, publicKey) tuple is the unique key; a re-save with the
 * same tuple updates the label. Label collisions against unrelated
 * entries get the public-key-derived suffix too.
 */
export async function savePublicKnownHost(
  host: {
    label: string;
    relayUrl: string;
    publicKey: string;
    role?: "daemon" | "client";
  },
  store: SecretStore
): Promise<void> {
  const existing = await loadKnownHosts(store);
  // Drop any prior entry for this exact pubkey on this relay (updating
  // its label). Keep other entries with the SAME label but a different
  // pubkey/URL so the collision check below can see them.
  const kept = existing.filter(
    (h) => !(h.relayUrl === host.relayUrl && h.publicKey === host.publicKey)
  );
  const usedLabels = new Set(kept.map((h) => h.label));
  const finalLabel = pickUniqueLabel(host.label, host.publicKey, usedLabels);
  kept.push({
    label: finalLabel,
    relayUrl: host.relayUrl,
    publicKey: host.publicKey,
    role: host.role ?? "daemon",
  });
  await persist(kept, store);
  log("hosts", "save public", {
    label: finalLabel,
    collidedWith: finalLabel !== host.label ? host.label : undefined,
    relayUrl: host.relayUrl,
    role: host.role ?? "daemon",
    publicKeyPrefix: host.publicKey.slice(0, 8),
  });
}

/**
 * Save an ssh:// host: an ssh-reachable peer that runs `pty` locally.
 * The sshUrl tuple is the unique key — re-saving the same sshUrl
 * updates the label in place. Label collisions against unrelated
 * entries get a sshUrl-derived suffix.
 */
export async function saveSshKnownHost(
  host: { label: string; sshUrl: string },
  store: SecretStore,
): Promise<void> {
  const existing = await loadKnownHosts(store);
  const kept = existing.filter((h) => h.sshUrl !== host.sshUrl);
  const usedLabels = new Set(kept.map((h) => h.label));
  const finalLabel = pickUniqueLabel(host.label, host.sshUrl, usedLabels);
  kept.push({ label: finalLabel, sshUrl: host.sshUrl });
  await persist(kept, store);
  log("hosts", "save ssh", {
    label: finalLabel,
    collidedWith: finalLabel !== host.label ? host.label : undefined,
    sshUrl: host.sshUrl,
  });
}

/** Remove all known hosts with the given label. */
export async function removeKnownHost(
  label: string,
  store: SecretStore
): Promise<void> {
  const existing = await loadKnownHosts(store);
  const filtered = existing.filter((h) => h.label !== label);
  await persist(filtered, store);
  log("hosts", "remove", { label, removed: existing.length - filtered.length });
}

/** Rename an entry. Errors if `oldLabel` doesn't exist or `newLabel`
 *  is already taken by a DIFFERENT entry. The transport fields
 *  (url / relayUrl / publicKey / role) are untouched. */
export async function renameKnownHost(
  oldLabel: string,
  newLabel: string,
  store: SecretStore
): Promise<void> {
  if (oldLabel === newLabel) return;
  const existing = await loadKnownHosts(store);
  const target = existing.find((h) => h.label === oldLabel);
  if (!target) {
    throw new Error(`No known host labeled "${oldLabel}".`);
  }
  if (existing.some((h) => h.label === newLabel)) {
    throw new Error(
      `Label "${newLabel}" is already in use. Pick a different name or \`forget\` the conflicting entry first.`
    );
  }
  target.label = newLabel;
  await persist(existing, store);
}

async function persist(hosts: KnownHost[], store: SecretStore): Promise<void> {
  await store.save(
    "hosts",
    new TextEncoder().encode(JSON.stringify(hosts))
  );
}

/**
 * Read entries from BOTH the encrypted store and the declarative
 * peers file (see `peers-file.ts`), merging on label. Encrypted-store
 * entries WIN on collisions — the operator explicitly saved them via
 * `connect` / `add` / `server signin`, so an accidental peers-file
 * line with the same label shouldn't shadow them. peers-file entries
 * that collide get a `-2`/`-3`/… numeric suffix so they remain
 * reachable.
 *
 * Read every time so a freshly-dropped peers file works with zero
 * setup — no daemon restart, no cache invalidation. The encrypted
 * load is already the bottleneck (sodium decrypt); a few extra
 * stat()s for the peers file are negligible.
 *
 * Every read-only consumer (`ls`, `peek`, `send`, `tag`, `events`,
 * `connect`, `resolveHost`) should use this. Write paths (save /
 * remove / rename) keep using `loadKnownHosts` since they only
 * touch the encrypted store.
 */
export async function loadAllKnownHosts(
  store: SecretStore,
): Promise<KnownHost[]> {
  // Imported lazily so the encrypted-store-only path doesn't need to
  // pull in the peers-file module for write operations.
  const { loadPeersFile } = await import("./peers-file.ts");
  const stored = await loadKnownHosts(store);
  const fromFile = loadPeersFile();
  if (fromFile.length === 0) return stored;

  const storedLabels = new Set(stored.map((h) => h.label));
  const merged: KnownHost[] = [...stored];
  let shadowed = 0;
  let renamed = 0;

  for (const candidate of fromFile) {
    if (storedLabels.has(candidate.label)) {
      // Same label as an explicit store entry. Keep the store row,
      // skip the file row entirely — the operator probably forgot to
      // remove a peers-file line for a host they later added via the
      // imperative flow. Surfacing both is worse than silently
      // preferring the explicit one.
      shadowed++;
      continue;
    }
    // Numeric suffix to avoid collisions between MULTIPLE peers-file
    // entries that happen to share a label (rare but possible when
    // explicit labels are used).
    let label = candidate.label;
    if (merged.some((h) => h.label === label)) {
      let n = 2;
      while (merged.some((h) => h.label === `${candidate.label}-${n}`)) n++;
      label = `${candidate.label}-${n}`;
      renamed++;
    }
    merged.push({ ...candidate, label });
  }

  log("hosts", "load merged", {
    stored: stored.length,
    file: fromFile.length,
    shadowed,
    renamed,
    total: merged.length,
  });
  return merged;
}
