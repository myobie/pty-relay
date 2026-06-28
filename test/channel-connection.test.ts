import { describe, it, expect, vi } from "vitest";
import { ChannelConnection } from "../src/relay/channel-connection.ts";
import {
  encodeFrame,
  decodeFrame,
  CONTROL_CHANNEL_ID,
  DEFAULT_PTY_CHANNEL_ID,
  FRAME_TYPE,
  MIN_FRAME_BYTES,
} from "../src/relay/channel-framing.ts";
import type { ChannelHandler } from "../src/relay/channel-registry.ts";
import { parseControlMessage } from "../src/relay/channel-control.ts";

/** Tiny capture-everything fixture. */
function makeConn() {
  const sent: Uint8Array[] = [];
  const app: Array<{ type: string; json: Record<string, unknown> }> = [];
  const fatal: Array<{ code: string; message: string }> = [];
  const conn = new ChannelConnection(
    (frame) => sent.push(frame),
    {
      onApp: (type, json) => app.push({ type, json }),
      onFatal: (code, message) => fatal.push({ code, message }),
    },
  );
  return { conn, sent, app, fatal };
}

describe("ChannelConnection — outbound", () => {
  it("sendApp wraps the JSON object in a channel-0 DATA frame", () => {
    const { conn, sent } = makeConn();
    conn.sendApp({ type: "hello", client: "cli", label: "laptop" });
    expect(sent).toHaveLength(1);
    const decoded = decodeFrame(sent[0]);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.frame.channelId).toBe(CONTROL_CHANNEL_ID);
    expect(decoded.frame.type).toBe(FRAME_TYPE.DATA);
    const parsed = parseControlMessage(decoded.frame.payload);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok || parsed.kind !== "app") return;
    expect(parsed.type).toBe("hello");
    expect(parsed.json).toEqual({ type: "hello", client: "cli", label: "laptop" });
  });

  it("sendBridgeData wraps pty bytes on DEFAULT_PTY_CHANNEL_ID", () => {
    const { conn, sent } = makeConn();
    conn.sendBridgeData(new Uint8Array([0xaa, 0xbb, 0xcc]));
    expect(sent).toHaveLength(1);
    const decoded = decodeFrame(sent[0]);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.frame.channelId).toBe(DEFAULT_PTY_CHANNEL_ID);
    expect(decoded.frame.type).toBe(FRAME_TYPE.DATA);
    expect(Array.from(decoded.frame.payload)).toEqual([0xaa, 0xbb, 0xcc]);
  });

  it("sendBridgeData accepts an empty payload (used for stdin EOF at exec mode)", () => {
    const { conn, sent } = makeConn();
    conn.sendBridgeData(new Uint8Array(0));
    expect(sent).toHaveLength(1);
    expect(sent[0].length).toBe(MIN_FRAME_BYTES);
  });
});

describe("ChannelConnection — inbound dispatch", () => {
  it("routes a framed v1 JSON RPC to onApp", () => {
    const { conn, app } = makeConn();
    const payload = new TextEncoder().encode(
      JSON.stringify({ type: "list" }),
    );
    conn.handlePlaintext(encodeFrame(CONTROL_CHANNEL_ID, FRAME_TYPE.DATA, payload));
    expect(app).toHaveLength(1);
    expect(app[0].type).toBe("list");
    expect(app[0].json).toEqual({ type: "list" });
  });

  it("routes a framed pty packet to the attached bridge handler", () => {
    const { conn } = makeConn();
    const onFrame = vi.fn();
    const close = vi.fn();
    const handler: ChannelHandler = { mode: "pty", onFrame, close };
    conn.attachBridge(handler);

    conn.handlePlaintext(
      encodeFrame(DEFAULT_PTY_CHANNEL_ID, FRAME_TYPE.DATA, new Uint8Array([1, 2, 3])),
    );
    expect(onFrame).toHaveBeenCalledTimes(1);
    const [type, payload] = onFrame.mock.calls[0];
    expect(type).toBe(FRAME_TYPE.DATA);
    expect(Array.from(payload as Uint8Array)).toEqual([1, 2, 3]);
  });

  it("attachBridge replaces an existing bridge cleanly", () => {
    const { conn } = makeConn();
    const close1 = vi.fn();
    const onFrame1 = vi.fn();
    const close2 = vi.fn();
    const onFrame2 = vi.fn();
    conn.attachBridge({ mode: "pty", onFrame: onFrame1, close: close1 });
    conn.attachBridge({ mode: "pty", onFrame: onFrame2, close: close2 });

    // The first handler should have been closed when the second
    // arrived; the second should be the live one.
    expect(close1).toHaveBeenCalledTimes(1);
    expect(close2).not.toHaveBeenCalled();

    conn.handlePlaintext(
      encodeFrame(DEFAULT_PTY_CHANNEL_ID, FRAME_TYPE.DATA, new Uint8Array([7])),
    );
    expect(onFrame1).not.toHaveBeenCalled();
    expect(onFrame2).toHaveBeenCalledTimes(1);
  });

  it("attachBridge is idempotent on the same handler", () => {
    const { conn } = makeConn();
    const close = vi.fn();
    const handler: ChannelHandler = { mode: "pty", onFrame: vi.fn(), close };
    conn.attachBridge(handler);
    conn.attachBridge(handler);
    // No re-open / re-close churn.
    expect(close).not.toHaveBeenCalled();
  });

  it("detachBridge removes the registered bridge and is no-op-safe", () => {
    const { conn } = makeConn();
    const close = vi.fn();
    conn.attachBridge({ mode: "pty", onFrame: vi.fn(), close });
    conn.detachBridge("client_detach");
    expect(close).toHaveBeenCalledWith("client_detach");
    // Calling again must not throw.
    expect(() => conn.detachBridge("client_detach")).not.toThrow();
  });

  it("closeAll cascades to every registered bridge", () => {
    const { conn } = makeConn();
    const close = vi.fn();
    conn.attachBridge({ mode: "pty", onFrame: vi.fn(), close });
    conn.closeAll("peer_lost");
    expect(close).toHaveBeenCalledWith("peer_lost");
  });

  it("surfaces a malformed frame as onFatal", () => {
    const { conn, fatal } = makeConn();
    conn.handlePlaintext(new Uint8Array(2));
    expect(fatal).toHaveLength(1);
    expect(fatal[0].code).toBe("frame_too_short");
  });
});
