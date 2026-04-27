import { ready } from "../../crypto/index.ts";
import { openSecretStore } from "../../storage/bootstrap.ts";
import { log } from "../../log.ts";
import {
  loadPublicAccount,
  type KeyIdentity,
} from "../../storage/public-account.ts";

/** `pty-relay server status` — print this device's public-relay enrollment. */
export async function statusCommand(opts: {
  json?: boolean;
  configDir?: string;
  passphraseFile?: string;
}): Promise<void> {
  await ready();
  log("cli", "server status begin", { json: !!opts.json });
  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });
  const account = await loadPublicAccount(store);

  if (!account) {
    if (opts.json) {
      console.log(JSON.stringify({ enrolled: false }));
    } else {
      console.log("Not enrolled on any public relay.");
      console.log("Run `pty-relay server signin --email <addr>` to begin.");
    }
    return;
  }

  if (opts.json) {
    // Redact secret material — the status output is the kind of thing
    // that might land in a bug report or log.
    console.log(
      JSON.stringify(
        {
          enrolled: true,
          relayUrl: account.relayUrl,
          email: account.email,
          accountId: account.accountId,
          label: account.label,
          totpConfigured: !!account.totpSecretB32,
          daemonKey: summarizeKeyJson(account.daemonKey),
          clientKey: summarizeKeyJson(account.clientKey),
        },
        null,
        2
      )
    );
    return;
  }

  console.log(`Enrolled on ${account.relayUrl}`);
  console.log(`  Label:       ${account.label}`);
  console.log(`  Email:       ${account.email || "(unset)"}`);
  console.log(`  Account id:  ${account.accountId || "(unknown)"}`);
  console.log(
    `  TOTP:        ${account.totpSecretB32 ? "configured locally" : "managed elsewhere"}`
  );
  printKey("Daemon key", account.daemonKey);
  printKey("Client key", account.clientKey);
}

function summarizeKeyJson(key: KeyIdentity | undefined): null | {
  publicKey: string;
  registeredKeyId: string;
  enrolledAt: string;
  rotationPending: boolean;
  pin: null | {
    daemonIdentityId: string;
    daemonLabel: string;
    daemonPublicKey: string;
  };
} {
  if (!key) return null;
  return {
    publicKey: key.signingKeys.public,
    registeredKeyId: key.registeredKeyId,
    enrolledAt: key.enrolledAt,
    rotationPending: !!key.pendingRotation,
    pin: key.pin ?? null,
  };
}

function printKey(label: string, key: KeyIdentity | undefined): void {
  if (!key) {
    console.log(`  ${label}:  (none)`);
    return;
  }
  console.log(`  ${label}:`);
  console.log(`    Public key:  ${key.signingKeys.public}`);
  console.log(`    Enrolled at: ${key.enrolledAt}`);
  if (key.pin) {
    // Preauth-claimed client keys are pinned to a single daemon. Tell
    // the operator which one — otherwise a future pair failure reads
    // mysteriously ("why can't my phone reach laptop-b?").
    console.log(
      `    Pinned to:   ${key.pin.daemonLabel} (daemon_identity_id=${key.pin.daemonIdentityId})`
    );
  }
  if (key.pendingRotation) {
    console.log(`    Rotation:    pending since ${key.pendingRotation.startedAt}`);
  }
}
