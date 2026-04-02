export type SecretName = "config" | "clients" | "hosts" | "auth";

export interface SecretStore {
  readonly backend: "keychain" | "passphrase";
  /**
   * Load the plaintext stored under this name, or null if nothing has been
   * saved under that name yet.
   */
  load(name: SecretName): Promise<Uint8Array | null>;
  /**
   * Save plaintext under this name, encrypted with the store's master key.
   * Durable (atomic write).
   */
  save(name: SecretName, plaintext: Uint8Array): Promise<void>;
  /**
   * Delete whatever is stored under this name. No-op if nothing is stored.
   */
  delete(name: SecretName): Promise<void>;
}

/**
 * Map a logical secret name to an on-disk filename.
 *
 * We keep the original filenames for `config`, `clients`, and `hosts` so the
 * layout matches what users see today. `auth` → `auth.json`.
 */
export function secretFilename(name: SecretName): string {
  switch (name) {
    case "config":
      return "config.json";
    case "clients":
      return "clients.json";
    case "hosts":
      return "hosts";
    case "auth":
      return "auth.json";
  }
}
