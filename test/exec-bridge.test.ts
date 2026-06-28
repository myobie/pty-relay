import { describe, it, expect, vi } from "vitest";
import { EventEmitter } from "node:events";
import { Buffer } from "node:buffer";
import {
  ExecBridge,
  type ExecChild,
  type SpawnFn,
} from "../src/relay/exec-bridge.ts";
import {
  decodeFrame,
  encodeFrame,
  FRAME_TYPE,
  SUBSTREAM,
  wrapSubstream,
} from "../src/relay/channel-framing.ts";

/**
 * Fake child that mimics the small slice of `ChildProcess` ExecBridge
 * touches. Lets tests synchronously emit stdout/stderr/exit and capture
 * what was written to stdin.
 */
class FakeChild extends EventEmitter implements ExecChild {
  readonly stdout: EventEmitter;
  readonly stderr: EventEmitter;
  readonly stdin: { write: (buf: Buffer | Uint8Array) => boolean; end: () => void };
  readonly stdinWrites: Buffer[] = [];
  stdinEnded = false;
  killCalls: NodeJS.Signals[] = [];

  constructor() {
    super();
    this.stdout = new EventEmitter();
    this.stderr = new EventEmitter();
    this.stdin = {
      write: (buf) => {
        this.stdinWrites.push(Buffer.from(buf));
        return true;
      },
      end: () => {
        this.stdinEnded = true;
      },
    };
  }

  kill(signal: NodeJS.Signals = "SIGTERM"): boolean {
    this.killCalls.push(signal);
    return true;
  }

  emitStdout(bytes: Buffer | Uint8Array): void {
    this.stdout.emit("data", Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes));
  }

  emitStderr(bytes: Buffer | Uint8Array): void {
    this.stderr.emit("data", Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes));
  }

  exit(code: number | null, signal: NodeJS.Signals | null = null): void {
    this.emit("exit", code, signal);
  }

  failSpawn(err: Error): void {
    this.emit("error", err);
  }
}

/** Construct a wired ExecBridge with capture arrays for outbound
 *  frames + control messages. */
function makeBridge(opts: {
  channelId?: number;
  argv?: string[];
  spawnImpl?: () => ExecChild;
} = {}) {
  const data: Uint8Array[] = [];
  const control: Record<string, unknown>[] = [];
  const child = opts.spawnImpl ? null : new FakeChild();
  const spawn: SpawnFn = opts.spawnImpl
    ? opts.spawnImpl
    : () => child as ExecChild;
  const bridge = new ExecBridge(
    opts.channelId ?? 7,
    (payload) => data.push(payload),
    (msg) => control.push(msg),
    spawn,
    { argv: opts.argv ?? ["rsync", "--server"], env: null, cwd: null },
  );
  return { bridge, data, control, child: child as FakeChild | null };
}

describe("ExecBridge — outbound stdout/stderr", () => {
  it("wraps stdout bytes in a STDOUT-prefixed data payload", () => {
    const { bridge, data, child } = makeBridge();
    bridge.start();
    child!.emitStdout(Buffer.from([0xaa, 0xbb]));
    expect(data).toHaveLength(1);
    expect(data[0][0]).toBe(SUBSTREAM.STDOUT);
    expect(data[0][1]).toBe(0xaa);
    expect(data[0][2]).toBe(0xbb);
  });

  it("wraps stderr bytes in a STDERR-prefixed data payload", () => {
    const { bridge, data, child } = makeBridge();
    bridge.start();
    child!.emitStderr(Buffer.from("err"));
    expect(data).toHaveLength(1);
    expect(data[0][0]).toBe(SUBSTREAM.STDERR);
    expect(new TextDecoder().decode(data[0].slice(1))).toBe("err");
  });

  it("interleaves stdout + stderr cleanly", () => {
    const { bridge, data, child } = makeBridge();
    bridge.start();
    child!.emitStdout(Buffer.from("o1"));
    child!.emitStderr(Buffer.from("e1"));
    child!.emitStdout(Buffer.from("o2"));
    expect(data.map((p) => p[0])).toEqual([
      SUBSTREAM.STDOUT,
      SUBSTREAM.STDERR,
      SUBSTREAM.STDOUT,
    ]);
  });
});

describe("ExecBridge — inbound stdin", () => {
  it("writes payload bytes to child.stdin after stripping the substream prefix", () => {
    const { bridge, child } = makeBridge();
    bridge.start();
    bridge.onFrame(FRAME_TYPE.DATA, wrapSubstream(SUBSTREAM.STDIN, new Uint8Array([1, 2, 3])));
    expect(child!.stdinWrites).toHaveLength(1);
    expect(Array.from(child!.stdinWrites[0])).toEqual([1, 2, 3]);
  });

  it("treats an empty STDIN payload as EOF (child.stdin.end)", () => {
    const { bridge, child } = makeBridge();
    bridge.start();
    bridge.onFrame(FRAME_TYPE.DATA, wrapSubstream(SUBSTREAM.STDIN, new Uint8Array(0)));
    expect(child!.stdinEnded).toBe(true);
    expect(child!.stdinWrites).toHaveLength(0);
  });

  it("closes the channel on STDIN after EOF (protocol violation)", () => {
    const { bridge, control, child } = makeBridge();
    bridge.start();
    bridge.onFrame(FRAME_TYPE.DATA, wrapSubstream(SUBSTREAM.STDIN, new Uint8Array(0)));
    bridge.onFrame(FRAME_TYPE.DATA, wrapSubstream(SUBSTREAM.STDIN, new Uint8Array([0xff])));
    expect(control.some((m) => m.type === "channel_close" && m.reason === "protocol_error")).toBe(true);
    expect(child!.killCalls).toContain("SIGTERM");
  });

  it("closes the channel on STDOUT from the client (wrong direction)", () => {
    const { bridge, control, child } = makeBridge();
    bridge.start();
    bridge.onFrame(FRAME_TYPE.DATA, wrapSubstream(SUBSTREAM.STDOUT, new Uint8Array([1])));
    expect(control.some((m) => m.type === "channel_close" && m.reason === "protocol_error")).toBe(true);
    expect(child!.killCalls).toContain("SIGTERM");
  });

  it("closes the channel on DATA with empty payload (no substream byte)", () => {
    const { bridge, control } = makeBridge();
    bridge.start();
    bridge.onFrame(FRAME_TYPE.DATA, new Uint8Array(0));
    expect(control.some((m) => m.type === "channel_close" && m.reason === "protocol_error")).toBe(true);
  });

  it("closes the channel on an unknown frame type", () => {
    const { bridge, control } = makeBridge();
    bridge.start();
    bridge.onFrame(0xff, new Uint8Array([1, 2]));
    expect(control.some((m) => m.type === "channel_close" && m.reason === "protocol_error")).toBe(true);
  });
});

describe("ExecBridge — exit lifecycle", () => {
  it("emits channel_exit + channel_close on normal exit", () => {
    const { bridge, control, child } = makeBridge();
    bridge.start();
    child!.exit(0);
    expect(control).toEqual([
      { type: "channel_exit", id: 7, exit_code: 0, signal: null },
      { type: "channel_close", id: 7, reason: "exit" },
    ]);
  });

  it("emits channel_exit with signal name on signal kill", () => {
    const { bridge, control, child } = makeBridge();
    bridge.start();
    child!.exit(null, "SIGTERM");
    expect(control[0]).toEqual({
      type: "channel_exit",
      id: 7,
      exit_code: null,
      signal: "SIGTERM",
    });
  });

  it("emits channel_exit{-1,null} on spawn 'error' event", () => {
    const { bridge, control, child } = makeBridge();
    bridge.start();
    child!.failSpawn(new Error("ENOENT"));
    expect(control[0]).toEqual({
      type: "channel_exit",
      id: 7,
      exit_code: -1,
      signal: null,
    });
  });

  it("doesn't double-emit when both exit and error fire", () => {
    const { bridge, control, child } = makeBridge();
    bridge.start();
    child!.exit(2);
    child!.failSpawn(new Error("ignored"));
    expect(control.filter((m) => m.type === "channel_exit")).toHaveLength(1);
  });
});

describe("ExecBridge — signal forwarding", () => {
  it("forwards SIGINT in the allow-list to the child", () => {
    const { bridge, child } = makeBridge();
    bridge.start();
    bridge.onFrame(FRAME_TYPE.SIGNAL, new TextEncoder().encode("SIGINT"));
    expect(child!.killCalls).toEqual(["SIGINT"]);
  });

  it("forwards SIGTERM and SIGHUP", () => {
    const { bridge, child } = makeBridge();
    bridge.start();
    bridge.onFrame(FRAME_TYPE.SIGNAL, new TextEncoder().encode("SIGTERM"));
    bridge.onFrame(FRAME_TYPE.SIGNAL, new TextEncoder().encode("SIGHUP"));
    expect(child!.killCalls).toEqual(["SIGTERM", "SIGHUP"]);
  });

  it("drops SIGKILL silently (not in the allow-list)", () => {
    const { bridge, child } = makeBridge();
    bridge.start();
    bridge.onFrame(FRAME_TYPE.SIGNAL, new TextEncoder().encode("SIGKILL"));
    expect(child!.killCalls).toEqual([]);
  });

  it("drops garbage signal names silently", () => {
    const { bridge, child } = makeBridge();
    bridge.start();
    bridge.onFrame(FRAME_TYPE.SIGNAL, new TextEncoder().encode("not_a_signal"));
    expect(child!.killCalls).toEqual([]);
  });

  it("drops non-UTF8 signal payload silently", () => {
    const { bridge, child } = makeBridge();
    bridge.start();
    bridge.onFrame(FRAME_TYPE.SIGNAL, new Uint8Array([0xff, 0xfe]));
    expect(child!.killCalls).toEqual([]);
  });
});

describe("ExecBridge — close + idempotence", () => {
  it("close() kills the child if still alive", () => {
    const { bridge, child } = makeBridge();
    bridge.start();
    bridge.close("operator_close");
    expect(child!.killCalls).toEqual(["SIGTERM"]);
  });

  it("close() is idempotent (registry cascade-close safety)", () => {
    const { bridge, child } = makeBridge();
    bridge.start();
    bridge.close("first");
    bridge.close("second");
    expect(child!.killCalls).toEqual(["SIGTERM"]);
  });

  it("close() after the child already exited is a no-op", () => {
    const { bridge, child } = makeBridge();
    bridge.start();
    child!.exit(0);
    expect(child!.killCalls).toEqual([]);
    bridge.close("operator_close");
    expect(child!.killCalls).toEqual([]); // bridge knew child was finalized
  });

  it("onFrame after close() is dropped silently", () => {
    const { bridge, child } = makeBridge();
    bridge.start();
    bridge.close("operator_close");
    bridge.onFrame(FRAME_TYPE.DATA, wrapSubstream(SUBSTREAM.STDIN, new Uint8Array([1])));
    expect(child!.stdinWrites).toHaveLength(0);
  });

  it("calling start() twice throws", () => {
    const { bridge } = makeBridge();
    bridge.start();
    expect(() => bridge.start()).toThrow(/already called/);
  });
});

describe("ExecBridge — error during spawn (synchronous throw)", () => {
  it("propagates a synchronous spawn-fn throw so the caller can translate to channel_open_error", () => {
    const { bridge } = makeBridge({
      spawnImpl: () => {
        throw new Error("ENOENT");
      },
    });
    expect(() => bridge.start()).toThrow(/ENOENT/);
  });
});
