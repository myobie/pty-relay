import { matchesAllTags } from "@myobie/pty/client";
import { ready } from "../crypto/index.ts";
import { loadKnownHosts, isPublicHost } from "../relay/known-hosts.ts";
import {
  listRemoteSessions,
  listPublicRemoteSessions,
  type RemoteSession,
} from "../relay/relay-client.ts";
import { loadPublicAccount } from "../storage/public-account.ts";
import { openSecretStore } from "../storage/bootstrap.ts";
import sodium from "libsodium-wrappers-sumo";

interface HostResult {
  label: string;
  url: string;
  sessions: RemoteSession[];
  spawn_enabled: boolean;
  error: string | null;
}

export function renderTags(tags: Record<string, string> | undefined): string {
  if (!tags) return "";
  const entries = Object.entries(tags).filter(([k]) =>
    k !== "ptyfile" && k !== "ptyfile.session" && k !== "ptyfile.tags" && k !== "supervisor.status" && k !== "strategy"
  );
  return entries.length > 0 ? " " + entries.map(([k, v]) => `#${k}=${v}`).join(" ") : "";
}

export async function ls(
  configDir?: string,
  json = false,
  opts?: { passphraseFile?: string; filterTags?: Record<string, string> }
): Promise<void> {
  await ready();

  const { store } = await openSecretStore(configDir, {
    interactive: true,
    passphraseFile: opts?.passphraseFile,
  });
  const hosts = await loadKnownHosts(store);
  const filterTags = opts?.filterTags ?? {};
  const hasFilter = Object.keys(filterTags).length > 0;

  if (hosts.length === 0) {
    if (json) {
      console.log(JSON.stringify([]));
    } else {
      console.log("No known hosts.");
      console.log("Connect to a daemon first:");
      console.log("  pty-relay connect <token-url>");
    }
    return;
  }

  // Lazily load the public-account (needed to sign client_pair URLs).
  // Only loaded if we actually have a public-mode host to talk to.
  const publicHosts = hosts.filter(isPublicHost);
  const account = publicHosts.length > 0 ? await loadPublicAccount(store) : null;
  // `ls` opens role=client_pair, which requires a client-role key on the
  // relay. Fall back to undefined (→ "enrolled but no client key" error
  // downstream) rather than mis-signing with a daemon key and getting 403.
  const clientKey = account?.clientKey;
  const accountKeys =
    clientKey
      ? {
          public: sodium.from_base64(
            clientKey.signingKeys.public,
            sodium.base64_variants.URLSAFE_NO_PADDING
          ),
          secret: sodium.from_base64(
            clientKey.signingKeys.secret,
            sodium.base64_variants.URLSAFE_NO_PADDING
          ),
        }
      : null;

  // Fetch sessions from all hosts in parallel. Self-hosted uses the
  // #pk.secret token URL; public-relay uses a signed role=client_pair
  // connection against the same relay the operator is enrolled on.
  const results: HostResult[] = await Promise.all(
    hosts.map(async (h) => {
      if (isPublicHost(h)) {
        const url = `${h.relayUrl}@${h.publicKey.slice(0, 8)}`;
        if (!account) {
          return {
            label: h.label,
            url,
            sessions: [],
            spawn_enabled: false,
            error: "public-relay host but this device isn't enrolled",
          };
        }
        if (!accountKeys) {
          return {
            label: h.label,
            url,
            sessions: [],
            spawn_enabled: false,
            error: "this device has no client key on this account (run `pty-relay server join --role client` from an enrolled daemon to get one)",
          };
        }
        if (account.relayUrl !== h.relayUrl) {
          return {
            label: h.label,
            url,
            sessions: [],
            spawn_enabled: false,
            error: `enrolled on ${account.relayUrl}, host is on ${h.relayUrl}`,
          };
        }
        try {
          const result = await listPublicRemoteSessions(
            {
              relayUrl: h.relayUrl,
              targetPublicKeyB64: h.publicKey,
              accountKeys,
            },
            10000
          );
          const sessions = hasFilter
            ? result.sessions.filter((s) => matchesAllTags(s.tags, filterTags))
            : result.sessions;
          return {
            label: h.label,
            url,
            sessions,
            spawn_enabled: result.spawnEnabled,
            error: null,
          };
        } catch (err: any) {
          return {
            label: h.label,
            url,
            sessions: [],
            spawn_enabled: false,
            error: err.message || "connection failed",
          };
        }
      }
      const url = h.url!;
      try {
        const result = await listRemoteSessions(url, 10000);
        const sessions = hasFilter
          ? result.sessions.filter((s) => matchesAllTags(s.tags, filterTags))
          : result.sessions;
        return { label: h.label, url, sessions, spawn_enabled: result.spawnEnabled, error: null };
      } catch (err: any) {
        return { label: h.label, url, sessions: [], spawn_enabled: false, error: err.message || "connection failed" };
      }
    })
  );

  if (json) {
    console.log(JSON.stringify(results, null, 2));
    return;
  }

  for (const host of results) {
    if (host.error) {
      console.log(`\x1b[1m${host.label}\x1b[0m  \x1b[31m${host.error}\x1b[0m`);
    } else if (host.sessions.length === 0) {
      const msg = hasFilter ? "no sessions match filter" : "no running sessions";
      console.log(`\x1b[1m${host.label}\x1b[0m  \x1b[90m${msg}\x1b[0m`);
    } else {
      console.log(`\x1b[1m${host.label}\x1b[0m`);
      for (const s of host.sessions) {
        const cmd = s.command || "";
        const tagStr = renderTags(s.tags);
        // Mirror pty's own list convention: when a session has a displayName
        // lead with it and show the stable id in dimmed parens; otherwise
        // show just the id. Keeps typing-by-either-name working and matches
        // what the user sees in `pty list`. Compute padding from the plain
        // (non-ANSI) text so displayed-width stays consistent.
        const plainLabel = s.displayName
          ? `${s.displayName} (${s.name})`
          : s.name;
        const label = s.displayName
          ? `${s.displayName} \x1b[2m(${s.name})\x1b[0m`
          : s.name;
        const pad = " ".repeat(Math.max(1, 40 - plainLabel.length));
        console.log(`  ${label}${pad}${cmd.padEnd(20)} ${s.status}${tagStr}`);
      }
    }
  }
}
