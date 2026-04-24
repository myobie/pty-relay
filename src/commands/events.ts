import type { EventRecord } from "@myobie/pty/client";
import { ready } from "../crypto/index.ts";
import {
  subscribeRemoteEvents,
  subscribePublicRemoteEvents,
  type SubscribeRemoteEventsOptions,
  type RemoteEventsSubscription,
} from "../relay/events-client.ts";
import { resolveHost } from "../relay/host-resolve.ts";
import { openSecretStore } from "../storage/bootstrap.ts";

// NOTE: `--recent` (one-shot historical events for a session) is deliberately
// not implemented yet — it needs its own server handler to read from the
// session's events.jsonl tail. Users who want to scan recent events can run
// `pty events --recent <name>` directly on the host, or attach in follow mode
// and wait for new entries. Tracked as a follow-up.

interface EventsOpts {
  session?: string;
  json?: boolean;
  configDir?: string;
  passphraseFile?: string;
}

/**
 * Follow events from a remote daemon. Runs until the process is interrupted.
 * With `json`, each event becomes a single JSONL line on stdout for scripting.
 * Without, events are printed in a human-readable one-line form.
 *
 * Works over both self-hosted (`#pk.secret` token) and public-relay
 * (`{relayUrl, publicKey}`) hosts — resolveHost picks the transport.
 */
export async function follow(hostLabel: string, opts: EventsOpts): Promise<void> {
  await ready();

  const { store } = await openSecretStore(opts.configDir, {
    interactive: true,
    passphraseFile: opts.passphraseFile,
  });

  let resolved;
  try {
    resolved = await resolveHost(hostLabel, store);
  } catch (err: any) {
    console.error(err?.message ?? err);
    process.exit(1);
  }

  const sessionFilter = opts.session;

  const printHuman = (evt: EventRecord): void => {
    const ts = new Date(evt.ts).toISOString();
    // Produce a compact "ts type session extras" line. We don't use pty's
    // formatEvent here because its output assumes a single-session context;
    // remote streams are cross-session and benefit from showing the name.
    const base = `${ts}  ${evt.type.padEnd(18)} ${evt.session}`;
    const extra: string[] = [];
    for (const [k, v] of Object.entries(evt)) {
      if (k === "type" || k === "session" || k === "ts") continue;
      extra.push(`${k}=${typeof v === "string" ? v : JSON.stringify(v)}`);
    }
    process.stdout.write(extra.length > 0 ? `${base}  ${extra.join(" ")}\n` : `${base}\n`);
  };

  const subOpts: SubscribeRemoteEventsOptions = {
    onSnapshot: () => {
      // Streaming mode doesn't re-print the snapshot; a JSON consumer that
      // wants the current list should call `pty-relay ls --json`. But do
      // note reconnects on stderr so operators can tell when the feed dropped.
    },
    onEvent: (evt) => {
      if (sessionFilter && evt.session !== sessionFilter) return;
      if (opts.json) {
        process.stdout.write(JSON.stringify(evt) + "\n");
      } else {
        printHuman(evt);
      }
    },
    onError: (err) => {
      process.stderr.write(`[events] error: ${err.message}\n`);
    },
    onReconnecting: (attempt) => {
      process.stderr.write(`[events] reconnecting (attempt ${attempt})…\n`);
    },
    onGaveUp: () => {
      process.stderr.write(`[events] gave up reconnecting\n`);
      process.exit(1);
    },
  };

  const subscription: RemoteEventsSubscription =
    resolved.kind === "public"
      ? subscribePublicRemoteEvents(resolved.target, subOpts)
      : subscribeRemoteEvents(resolved.url, subOpts);

  // Keep the process alive until Ctrl+C.
  process.on("SIGINT", () => {
    subscription.close();
    process.exit(0);
  });
  // Awaiting a never-resolving promise pins the event loop; Node would
  // otherwise exit once all sync code is done.
  await new Promise<void>(() => {});
}
