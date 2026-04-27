import {
  ready,
  setupConfig,
  createToken,
  computeSecretHash,
} from "../crypto/index.ts";
import type { Config } from "../crypto/index.ts";
import type { SecretStore } from "../storage/secret-store.ts";
import { openSecretStore, type BootstrapOpts } from "../storage/bootstrap.ts";
import { log, now, sinceMs } from "../log.ts";

export interface DaemonConfig {
  config: Config;
  relay: string;
  secretHash: string;
  store: SecretStore;
  passphrase?: string;
}

/**
 * Open the secret store for the daemon and ensure a Config is present.
 */
export async function loadDaemonConfig(
  relay: string,
  configDir?: string,
  bootstrapOpts?: BootstrapOpts
): Promise<DaemonConfig> {
  await ready();
  const t0 = now();

  const { store, passphrase } = await openSecretStore(configDir, bootstrapOpts);
  const { config } = await setupConfig(store);
  const secretHash = computeSecretHash(config.secret);
  log("account", "loaded daemon config", {
    relay,
    backend: store.backend,
    ms: sinceMs(t0),
  });

  return { config, relay, secretHash, store, passphrase };
}

export function getTokenUrl(
  relay: string,
  config: Config,
  session?: string
): string {
  return createToken(relay, config.publicKey, config.secret, session);
}

/** Save a custom daemon label under the "auth" secret name. */
export async function saveLabel(
  label: string,
  store: SecretStore
): Promise<void> {
  let existing: Record<string, unknown> = {};
  try {
    const bytes = await store.load("auth");
    if (bytes) {
      const parsed = JSON.parse(new TextDecoder().decode(bytes));
      if (parsed && typeof parsed === "object") {
        existing = parsed as Record<string, unknown>;
      }
    }
  } catch {
    // If it's corrupted, overwrite.
  }

  const data = { ...existing, label };
  await store.save(
    "auth",
    new TextEncoder().encode(JSON.stringify(data, null, 2))
  );
}

/** Load the custom daemon label from the "auth" secret. */
export async function loadLabel(store: SecretStore): Promise<string | null> {
  try {
    const bytes = await store.load("auth");
    if (!bytes) return null;
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    return typeof parsed?.label === "string" ? parsed.label : null;
  } catch {
    return null;
  }
}
