import { describe, it, expect, vi } from "vitest";
import { EventEmitter } from "node:events";
import { Buffer } from "node:buffer";
import { ChannelConnection } from "../src/relay/channel-connection.ts";
import { handleChannelOpenControl } from "../src/relay/channel-open-handler.ts";
import {
  decodeFrame,
  CONTROL_CHANNEL_ID,
  FRAME_TYPE,
} from "../src/relay/channel-framing.ts";
import { parseControlMessage } from "../src/relay/channel-control.ts";
import type { ExecChild, SpawnFn } from "../src/relay/exec-bridge.ts";

/** Fake child reused from exec-bridge tests, inlined here for
 *  isolation. */
class FakeChild extends EventEmitter implements ExecChild {
  readonly stdout: EventEmitter;
  readonly stderr: EventEmitter;
  readonly stdin: { write: (b: Buffer | Uint8Array) => boolean; end: () => void };
  readonly stdinWrites: Buffer[] = [];
  stdinEnded = false;
  killCalls: NodeJS.Signals[] = [];

  constructor() {
    super();
    this.stdout = new EventEmitter();
    this.stderr = new EventEmitter();
    this.stdin = {
      write: (b) => {
        this.stdinWrites.push(Buffer.from(b));
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

  emitStdout(b: Uint8Array): void {
    this.stdout.emit("data", Buffer.from(b));
  }

  exit(code: number | null, signal: NodeJS.Signals | null = null): void {
    this.emit("exit", code, signal);
  }
}

function makeConn() {
  const sent: Uint8Array[] = [];
  const appCalls: Array<{ type: string; json: Record<string, unknown> }> = [];
  const conn = new ChannelConnection(
    (frame) => sent.push(frame),
    {
      onApp: (type, json) => appCalls.push({ type, json }),
      onFatal: () => {},
    },
  );
  return { conn, sent, appCalls };
}

/** Decode every channel-0 control frame the connection has sent. */
function controlMessages(sent: Uint8Array[]): Record<string, unknown>[] {
  return sent
    .map((bytes) => decodeFrame(bytes))
    .filter((d): d is Extract<typeof d, { ok: true }> => d.ok)
    .filter((d) => d.frame.channelId === CONTROL_CHANNEL_ID && d.frame.type === FRAME_TYPE.DATA)
    .map((d) => {
      const parsed = parseControlMessage(d.frame.payload);
      if (parsed.ok && parsed.kind === "control") return parsed.msg as unknown as Record<string, unknown>;
      if (parsed.ok && parsed.kind === "app") return parsed.json;
      return null;
    })
    .filter((m): m is Record<string, unknown> => m !== null);
}

describe("handleChannelOpenControl — pty mode", () => {
  it("rejects channel_open mode:pty (not yet wired)", () => {
    const { conn, sent } = makeConn();
    handleChannelOpenControl(
      conn,
      { type: "channel_open", id: 3, mode: "pty", session: "demo" },
      { allowExec: true },
    );
    const msgs = controlMessages(sent);
    expect(msgs).toHaveLength(1);
    expect(msgs[0].type).toBe("channel_open_error");
    expect(msgs[0].code).toBe("mode_not_enabled");
    expect(msgs[0].id).toBe(3);
  });
});

describe("handleChannelOpenControl — exec mode gating", () => {
  it("rejects channel_open mode:exec when --allow-exec is off", () => {
    const { conn, sent } = makeConn();
    handleChannelOpenControl(
      conn,
      { type: "channel_open", id: 2, mode: "exec", argv: ["rsync", "--server"] },
      { allowExec: false },
    );
    const msgs = controlMessages(sent);
    expect(msgs[0].type).toBe("channel_open_error");
    expect(msgs[0].code).toBe("mode_not_enabled");
  });

  it("rejects argv[0] not in the allow-list", () => {
    const { conn, sent } = makeConn();
    handleChannelOpenControl(
      conn,
      { type: "channel_open", id: 2, mode: "exec", argv: ["curl", "--help"] },
      { allowExec: true, spawnFn: () => new FakeChild() },
    );
    const msgs = controlMessages(sent);
    expect(msgs[0].type).toBe("channel_open_error");
    expect(msgs[0].code).toBe("argv_not_allowed");
  });

  it("accepts and ack's when --allow-exec and argv is allowed", () => {
    const { conn, sent } = makeConn();
    const child = new FakeChild();
    handleChannelOpenControl(
      conn,
      { type: "channel_open", id: 2, mode: "exec", argv: ["rsync", "--server"] },
      { allowExec: true, spawnFn: () => child },
    );
    const msgs = controlMessages(sent);
    expect(msgs[0]).toEqual({ type: "channel_open_ack", id: 2 });
    expect(conn.registry.has(2)).toBe(true);
  });

  it("ack accepts git too (day-1 allow-list)", () => {
    const { conn, sent } = makeConn();
    handleChannelOpenControl(
      conn,
      { type: "channel_open", id: 5, mode: "exec", argv: ["git", "upload-pack"] },
      { allowExec: true, spawnFn: () => new FakeChild() },
    );
    const msgs = controlMessages(sent);
    expect(msgs[0]).toEqual({ type: "channel_open_ack", id: 5 });
  });

  it("rolls back the registry and replies channel_open_error on spawn failure", () => {
    const { conn, sent } = makeConn();
    const spawnFn: SpawnFn = () => {
      throw new Error("ENOENT");
    };
    handleChannelOpenControl(
      conn,
      { type: "channel_open", id: 9, mode: "exec", argv: ["rsync"] },
      { allowExec: true, spawnFn },
    );
    const msgs = controlMessages(sent);
    expect(msgs[0].type).toBe("channel_open_error");
    expect(msgs[0].code).toBe("spawn_failed");
    expect(conn.registry.has(9)).toBe(false);
  });

  it("rejects an id_collision when the channel id is already open", () => {
    const { conn, sent } = makeConn();
    // Pre-occupy id 4.
    conn.registry.open(4, {
      mode: "pty",
      onFrame: vi.fn(),
      close: vi.fn(),
    });
    handleChannelOpenControl(
      conn,
      { type: "channel_open", id: 4, mode: "exec", argv: ["rsync"] },
      { allowExec: true, spawnFn: () => new FakeChild() },
    );
    const msgs = controlMessages(sent);
    expect(msgs[0].type).toBe("channel_open_error");
    expect(msgs[0].code).toBe("id_collision");
  });
});

describe("handleChannelOpenControl — channel_close", () => {
  it("closes the registered handler on inbound channel_close", () => {
    const { conn } = makeConn();
    const close = vi.fn();
    conn.registry.open(11, {
      mode: "pty",
      onFrame: vi.fn(),
      close,
    });
    handleChannelOpenControl(
      conn,
      { type: "channel_close", id: 11, reason: "client_detach" },
      { allowExec: false },
    );
    expect(close).toHaveBeenCalledWith("client_detach");
    expect(conn.registry.has(11)).toBe(false);
  });
});

describe("handleChannelOpenControl — end-to-end exec lifecycle", () => {
  it("ack → stdout → exit → close", () => {
    const { conn, sent } = makeConn();
    const child = new FakeChild();
    handleChannelOpenControl(
      conn,
      { type: "channel_open", id: 8, mode: "exec", argv: ["rsync", "--server"] },
      { allowExec: true, spawnFn: () => child },
    );
    child.emitStdout(new Uint8Array([0xaa, 0xbb]));
    child.exit(0);

    const msgs = controlMessages(sent);
    expect(msgs.map((m) => m.type)).toContain("channel_open_ack");
    expect(msgs.map((m) => m.type)).toContain("channel_exit");
    expect(msgs.map((m) => m.type)).toContain("channel_close");
    // The DATA frame for stdout should be in the byte stream too.
    const dataFrames = sent
      .map((b) => decodeFrame(b))
      .filter((d): d is Extract<typeof d, { ok: true }> => d.ok)
      .filter((d) => d.frame.channelId === 8);
    expect(dataFrames.length).toBeGreaterThan(0);
  });
});
