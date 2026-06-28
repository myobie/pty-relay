/**
 * Exec channel handler — see `docs/channel-protocol.md` § "Mode `exec`".
 *
 * Spawns a non-PTY child process on the daemon, forwards stdin from
 * the client via the `exec` channel's DATA frames, and ships the
 * child's stdout + stderr back as DATA frames with a 1-byte sub-stream
 * prefix (`0=stdin`, `1=stdout`, `2=stderr`).
 *
 * Spawn is injected via the constructor so unit tests can drive the
 * full lifecycle without forking a real process:
 *
 *   const fakeChild = makeFakeChild();
 *   const bridge = new ExecBridge(
 *     channelId, sendFrame, () => fakeChild,
 *     {argv: ["rsync","--server"], env: {}, cwd: null},
 *   );
 *   bridge.start();
 *   fakeChild.emitStdout(Buffer.from("hello"));    // → DATA frame on this channel
 *   bridge.onFrame(DATA, [STDIN, ...bytes]);       // → fakeChild.stdin.write
 *   fakeChild.exit(0);                              // → channel_exit + channel_close
 *
 * The bridge does NOT consult the allow-list — that's the daemon's
 * decision before constructing the bridge (so a rejected channel never
 * spawns anything). Same with the `--allow-exec` flag.
 */

import { Buffer } from "node:buffer";
import { spawn as nodeSpawn } from "node:child_process";
import type { ChannelHandler } from "./channel-registry.ts";
import {
  FRAME_TYPE,
  SUBSTREAM,
  wrapSubstream,
  unwrapSubstream,
} from "./channel-framing.ts";
import { log } from "../log.ts";

/**
 * The subset of `child_process.ChildProcess` we actually depend on. A
 * fake child for tests implements this and nothing else.
 */
export interface ExecChild {
  stdin: {
    write(chunk: Buffer | Uint8Array): boolean | void;
    end(): void;
  } | null;
  stdout: NodeJS.EventEmitter | null;
  stderr: NodeJS.EventEmitter | null;
  kill(signal?: NodeJS.Signals): boolean;
  on(event: "exit", listener: (code: number | null, signal: NodeJS.Signals | null) => void): this;
  on(event: "error", listener: (err: Error) => void): this;
}

export interface ExecSpawnOptions {
  argv: string[];
  env?: Record<string, string> | null;
  cwd?: string | null;
}

/** Signal we may relay client → child. Other signals are silently
 *  dropped. Keep this list short — clients shouldn't be able to e.g.
 *  SIGKILL anything they want. */
const ALLOWED_SIGNALS = new Set<string>(["SIGINT", "SIGTERM", "SIGHUP"]);

/** Callback the bridge uses to ship its own outbound channel-control
 *  messages (`channel_exit` + `channel_close`). Owned by the daemon-side
 *  glue that constructs the bridge — typically a thin wrapper around
 *  `dispatcher.sendControl({...})`. */
export type SendControl = (msg: Record<string, unknown>) => void;

/** Callback the bridge uses to ship outbound DATA frames on its own
 *  channel. Typically `(payload) => dispatcher.sendData(channelId, DATA, payload)`. */
export type SendData = (payload: Uint8Array) => void;

export type SpawnFn = (opts: ExecSpawnOptions) => ExecChild;

export class ExecBridge implements ChannelHandler {
  readonly mode = "exec" as const;

  private readonly channelId: number;
  private readonly sendData: SendData;
  private readonly sendControl: SendControl;
  private readonly spawnFn: SpawnFn;
  private readonly opts: ExecSpawnOptions;

  private child: ExecChild | null = null;
  private stdinClosed = false;
  /** Set when we've already announced exit (either via channel_exit or
   *  because close() was called externally). Prevents double-sends. */
  private finalized = false;

  constructor(
    channelId: number,
    sendData: SendData,
    sendControl: SendControl,
    spawnFn: SpawnFn,
    opts: ExecSpawnOptions,
  ) {
    this.channelId = channelId;
    this.sendData = sendData;
    this.sendControl = sendControl;
    this.spawnFn = spawnFn;
    this.opts = opts;
  }

  /**
   * Spawn the child via the injected spawn fn and wire its three pipes
   * to the relay channel. Throws on spawn failure; callers catch and
   * translate into `channel_open_error{code:"spawn_failed"}`.
   *
   * Calling start() twice is a programmer error and throws.
   */
  start(): void {
    if (this.child) throw new Error("ExecBridge.start() already called");
    this.child = this.spawnFn(this.opts);

    this.child.stdout?.on("data", (chunk: Buffer) => {
      this.sendData(wrapSubstream(SUBSTREAM.STDOUT, new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength)));
    });
    this.child.stderr?.on("data", (chunk: Buffer) => {
      this.sendData(wrapSubstream(SUBSTREAM.STDERR, new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength)));
    });
    this.child.on("exit", (code, signal) => {
      if (this.finalized) return;
      this.finalized = true;
      log("exec", "child exited", {
        channelId: this.channelId,
        argv0: this.opts.argv[0],
        code,
        signal,
      });
      this.sendControl({
        type: "channel_exit",
        id: this.channelId,
        exit_code: code,
        signal,
      });
      this.sendControl({
        type: "channel_close",
        id: this.channelId,
        reason: "exit",
      });
    });
    this.child.on("error", (err: Error) => {
      // Spawn-after-error path: e.g. ENOENT on a binary we thought was
      // installed. Surface as channel_exit{exit_code:-1, signal:null}
      // then close. The channel_open_ack has already been sent, so we
      // can't use channel_open_error here — that's open-time only.
      if (this.finalized) return;
      this.finalized = true;
      log("exec", "child spawn/run error", {
        channelId: this.channelId,
        argv0: this.opts.argv[0],
        error: err.message,
      });
      this.sendControl({
        type: "channel_exit",
        id: this.channelId,
        exit_code: -1,
        signal: null,
      });
      this.sendControl({
        type: "channel_close",
        id: this.channelId,
        reason: "exit",
      });
    });
  }

  /**
   * `ChannelHandler.onFrame` — inbound frames on this channel.
   *
   * `type = DATA`:    payload = [sub-stream u8, …bytes]
   *                   sub-stream MUST be `STDIN` from the client; the
   *                   bridge writes the bytes (or, on empty payload,
   *                   closes the child's stdin via end()).
   *
   * `type = SIGNAL`:  payload = ASCII signal name (`"SIGINT"`).
   *                   Forwarded to the child if it's in the allow-list
   *                   and the child is still alive.
   *
   * Other types are protocol-violation; close the channel.
   */
  onFrame(type: number, payload: Uint8Array): void {
    if (!this.child || this.finalized) return;

    if (type === FRAME_TYPE.SIGNAL) {
      this.handleSignal(payload);
      return;
    }

    if (type !== FRAME_TYPE.DATA) {
      log("exec", "channel-close on unknown frame type", {
        channelId: this.channelId,
        type,
      });
      this.tearDown("protocol_error");
      return;
    }

    const unwrapped = unwrapSubstream(payload);
    if (unwrapped === null) {
      log("exec", "channel-close on empty data frame (no substream byte)", {
        channelId: this.channelId,
      });
      this.tearDown("protocol_error");
      return;
    }
    if (unwrapped.substream !== SUBSTREAM.STDIN) {
      log("exec", "channel-close on wrong-direction substream", {
        channelId: this.channelId,
        substream: unwrapped.substream,
      });
      this.tearDown("protocol_error");
      return;
    }

    if (this.stdinClosed) {
      // A STDIN frame after EOF is a protocol violation.
      log("exec", "channel-close on stdin after EOF", {
        channelId: this.channelId,
      });
      this.tearDown("protocol_error");
      return;
    }

    if (unwrapped.bytes.length === 0) {
      // Empty STDIN payload = EOF marker.
      this.stdinClosed = true;
      this.child.stdin?.end();
      return;
    }

    this.child.stdin?.write(Buffer.from(unwrapped.bytes));
  }

  /**
   * `ChannelHandler.close` — called by the registry's cascade-close or
   * an explicit peer-initiated `channel_close`. Kills the child if
   * still alive. Idempotent.
   */
  close(reason: string): void {
    if (this.finalized) return;
    this.finalized = true;
    log("exec", "bridge close", { channelId: this.channelId, reason });
    if (this.child) {
      try {
        this.child.kill("SIGTERM");
      } catch {
        // Already dead; nothing to do.
      }
    }
  }

  private tearDown(reason: string): void {
    if (this.finalized) return;
    this.sendControl({
      type: "channel_close",
      id: this.channelId,
      reason,
    });
    this.close(reason);
  }

  private handleSignal(payload: Uint8Array): void {
    let name: string;
    try {
      name = new TextDecoder("utf-8", { fatal: true }).decode(payload).trim();
    } catch {
      // Malformed signal name; drop silently.
      return;
    }
    if (!ALLOWED_SIGNALS.has(name)) return;
    try {
      this.child?.kill(name as NodeJS.Signals);
    } catch {
      // Already exited; nothing to do.
    }
  }
}

/**
 * Real (production) spawn — wraps `child_process.spawn` with the
 * shape ExecBridge expects. The daemon's openChannel handler binds
 * this when it constructs a bridge.
 */
export function realSpawn(opts: ExecSpawnOptions): ExecChild {
  return nodeSpawn(opts.argv[0], opts.argv.slice(1), {
    stdio: ["pipe", "pipe", "pipe"],
    env: opts.env ?? undefined,
    cwd: opts.cwd ?? undefined,
  }) as unknown as ExecChild;
}
