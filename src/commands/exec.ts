import * as os from "node:os";
import { ready, parseToken, computeSecretHash, getWebSocketUrl, NK } from "../crypto/index.ts";
import { ClientRelayConnection } from "../terminal/client-connection.ts";
import { ChannelConnection } from "../relay/channel-connection.ts";
import { openSecretStore } from "../storage/bootstrap.ts";
import { recordHostFromParsed } from "./connect.ts";
import {
  SUBSTREAM,
  FRAME_TYPE,
  wrapSubstream,
  unwrapSubstream,
} from "../relay/channel-framing.ts";
import type { ChannelHandler } from "../relay/channel-registry.ts";
import { log } from "../log.ts";

/**
 * Low-level remote-exec command. Connects to <target> (token URL or
 * known-hosts label), opens an `exec` channel with the given argv,
 * and proxies local stdin/stdout/stderr through the channel until the
 * remote process exits.
 *
 * Designed as a drop-in replacement for ssh in rsync's `-e` flag.
 * rsync invokes the transport with `<command> <host> rsync --server …`,
 * so the shape is:
 *
 *   pty-relay exec <target> rsync --server …
 *
 * Process exit code mirrors the remote process's exit code (or 128 +
 * signal number on signal kill, matching ssh's convention).
 */

const CHANNEL_ID = 1; // single exec channel per process; allocated client-side.

export interface ExecOptions {
  configDir?: string;
  passphraseFile?: string;
}

export async function execCommand(
  target: string,
  argv: string[],
  options: ExecOptions = {},
): Promise<void> {
  if (argv.length === 0) {
    process.stderr.write("Usage: pty-relay exec <target> <argv...>\n");
    process.exit(1);
  }

  await ready();
  log("cli", "exec begin", { target, argv0: argv[0], argvLen: argv.length });

  // For now we only support self-hosted targets via raw token URL.
  // Label resolution + public-relay can layer on in a follow-up.
  if (!target.startsWith("http://") && !target.startsWith("https://")) {
    process.stderr.write(
      "Only token URLs are supported in this build of `pty-relay exec`.\n" +
        "Public-relay label resolution is a follow-up.\n",
    );
    process.exit(1);
  }

  const parsed = parseToken(target);
  const secretHash = computeSecretHash(parsed.secret);
  const wsUrl = getWebSocketUrl(parsed.host, "client", secretHash, undefined, parsed.clientToken ?? undefined);

  const { store, passphrase } = await openSecretStore(options.configDir, {
    interactive: false,
    passphraseFile: options.passphraseFile,
  });
  if (passphrase && !process.env.PTY_RELAY_PASSPHRASE) {
    process.env.PTY_RELAY_PASSPHRASE = passphrase;
  }

  let exitCode: number | null = null;
  let signal: string | null = null;

  // Wire stdin: forward to the channel as STDIN substream bytes; on
  // local EOF, send an empty STDIN frame to signal remote EOF.
  let stdinClosed = false;

  await new Promise<void>((resolve, reject) => {
    let channel: ChannelConnection | null = null;
    let opened = false;

    const connection = new ClientRelayConnection(wsUrl, {
      pattern: NK,
      daemonPublicKey: parsed.publicKey,
    }, {
      onReady: () => {
        recordHostFromParsed(parsed, store);
        // Identify the client + open the exec channel.
        channel?.sendApp({
          type: "hello",
          client: "exec",
          os: process.platform,
          label: os.hostname(),
        });
        channel?.sendApp({
          type: "channel_open",
          id: CHANNEL_ID,
          mode: "exec",
          argv,
        });
      },

      onEncryptedMessage: (plaintext: Uint8Array) => {
        channel?.handlePlaintext(plaintext);
      },

      onWaitingForApproval: () => {
        process.stderr.write("Waiting for operator approval...\n");
      },

      onPeerDisconnected: () => reject(new Error("Daemon disconnected")),
      onError: (err: Error) => reject(err),
      onClose: () => {
        if (opened) {
          // Normal teardown after channel_close; resolve so we can
          // exit with the captured code.
          resolve();
        } else {
          reject(new Error("Connection closed before channel opened"));
        }
      },
    });

    const execHandler: ChannelHandler = {
      mode: "exec",
      onFrame: (type: number, payload: Uint8Array) => {
        if (type !== FRAME_TYPE.DATA) return;
        const unwrapped = unwrapSubstream(payload);
        if (!unwrapped) return;
        if (unwrapped.substream === SUBSTREAM.STDOUT) {
          process.stdout.write(Buffer.from(unwrapped.bytes));
        } else if (unwrapped.substream === SUBSTREAM.STDERR) {
          process.stderr.write(Buffer.from(unwrapped.bytes));
        }
        // STDIN from daemon is a protocol violation; ignore (the
        // daemon-side bridge enforces direction).
      },
      close: () => {},
    };

    channel = new ChannelConnection(
      (frame) => connection.send(frame),
      {
        onApp: (_type, json) => {
          if (json.type === "approved") return;
          if (json.type === "hello") return; // shouldn't arrive but harmless
        },
        onControl: (msg) => {
          if (msg.type === "channel_open_ack" && msg.id === CHANNEL_ID) {
            opened = true;
            channel?.registry.open(CHANNEL_ID, execHandler);
            wireStdin();
            return;
          }
          if (msg.type === "channel_open_error" && msg.id === CHANNEL_ID) {
            process.stderr.write(`exec rejected: ${msg.code} ${msg.message}\n`);
            try { connection.close(); } catch {}
            reject(new Error(`channel_open_error: ${msg.code}`));
            return;
          }
          if (msg.type === "channel_exit" && msg.id === CHANNEL_ID) {
            exitCode = msg.exit_code;
            signal = msg.signal;
            return;
          }
          if (msg.type === "channel_close" && msg.id === CHANNEL_ID) {
            try { connection.close(); } catch {}
            return;
          }
        },
        onFatal: (code, message) => {
          try { connection.close(); } catch {}
          reject(new Error(`protocol ${code}: ${message}`));
        },
      },
    );

    function wireStdin(): void {
      if (process.stdin.isTTY) {
        try { process.stdin.setRawMode(false); } catch {}
      }
      process.stdin.on("data", (chunk: Buffer) => {
        if (stdinClosed) return;
        channel?.sendChannelData(
          CHANNEL_ID,
          wrapSubstream(SUBSTREAM.STDIN, new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength)),
        );
      });
      process.stdin.on("end", () => {
        if (stdinClosed) return;
        stdinClosed = true;
        // Empty STDIN payload = EOF marker.
        channel?.sendChannelData(
          CHANNEL_ID,
          wrapSubstream(SUBSTREAM.STDIN, new Uint8Array(0)),
        );
      });
      process.stdin.resume();
    }

    connection.connect();
  });

  // ssh-compatible exit semantics: 128 + signal-number on signal,
  // exit code otherwise. Default to 1 if neither was captured.
  if (signal !== null) {
    process.exit(128 + signalNameToNumber(signal));
  }
  process.exit(exitCode ?? 1);
}

function signalNameToNumber(name: string): number {
  // Tiny table for the signals our bridge whitelists.
  switch (name) {
    case "SIGHUP": return 1;
    case "SIGINT": return 2;
    case "SIGTERM": return 15;
    default: return 0;
  }
}
