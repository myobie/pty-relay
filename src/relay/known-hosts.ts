import type { SecretStore } from "../storage/secret-store.ts";
import { log } from "../log.ts";

/**
 * A saved relay host. Supports two flavors:
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
 * `role` is informational for public-mode entries (daemon vs client) and
 * lets `ls` decide which rows to include in the session view.
 */
export interface KnownHost {
  label: string;
  /** Self-hosted `#pk.secret` URL. Omitted for public-relay hosts. */
  url?: string;
  /** Public-relay origin, e.g. `http://localhost:4000`. */
  relayUrl?: string;
  /** Target daemon's Ed25519 pubkey (base64url). */
  publicKey?: string;
  /** Peer role on the account. */
  role?: "daemon" | "client";
}

/** True iff this entry was registered via the public-relay flow. */
export function isPublicHost(h: KnownHost): h is KnownHost & {
  relayUrl: string;
  publicKey: string;
} {
  return typeof h.relayUrl === "string" && typeof h.publicKey === "string";
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

  // Reject entries that are neither self-hosted nor public-relay.
  if (!host.url && !(host.relayUrl && host.publicKey)) return null;
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

/**
 * Save a self-hosted host. The URL is the unique key: repeated saves
 * of the same URL update the label in place. If the label collides
 * with a DIFFERENT host (different URL / different public-relay
 * entry), the new entry's label gets a URL-derived suffix so both
 * can coexist. This is a recent change — previously a label collision
 * silently evicted the older entry.
 */
export async function saveKnownHost(
  label: string,
  url: string,
  store: SecretStore
): Promise<void> {
  const existing = await loadKnownHosts(store);
  // Drop any prior entry for this URL (updating its label); keep
  // entries with the SAME label but a different URL so we can resolve
  // the collision below.
  const kept = existing.filter((h) => h.url !== url);
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
