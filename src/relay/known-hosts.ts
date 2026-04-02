import type { SecretStore } from "../storage/secret-store.ts";

export interface KnownHost {
  label: string;
  url: string;
}

/**
 * Load known hosts from the store. Returns an empty array if nothing is
 * stored or the stored data is invalid.
 */
export async function loadKnownHosts(
  store: SecretStore
): Promise<KnownHost[]> {
  try {
    const bytes = await store.load("hosts");
    if (!bytes) return [];
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    if (!Array.isArray(parsed)) return [];

    const result: KnownHost[] = [];
    for (const item of parsed) {
      if (
        item &&
        typeof item === "object" &&
        typeof item.label === "string" &&
        typeof item.url === "string"
      ) {
        result.push({ label: item.label, url: item.url });
      }
    }
    return result;
  } catch {
    return [];
  }
}

/**
 * Save a host. If the URL already exists, the label is updated. If the label
 * already exists with a different URL, the new URL wins.
 */
export async function saveKnownHost(
  label: string,
  url: string,
  store: SecretStore
): Promise<void> {
  const existing = await loadKnownHosts(store);
  // Remove any entries sharing the URL or the label (one entry per host)
  const filtered = existing.filter((h) => h.url !== url && h.label !== label);
  filtered.push({ label, url });

  await store.save(
    "hosts",
    new TextEncoder().encode(JSON.stringify(filtered))
  );
}

/**
 * Remove all known hosts with the given label.
 */
export async function removeKnownHost(
  label: string,
  store: SecretStore
): Promise<void> {
  const existing = await loadKnownHosts(store);
  const filtered = existing.filter((h) => h.label !== label);
  await store.save(
    "hosts",
    new TextEncoder().encode(JSON.stringify(filtered))
  );
}
