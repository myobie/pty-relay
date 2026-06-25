import { describe, it, expect, vi } from "vitest";
import { ChannelDispatcher } from "../src/relay/channel-dispatcher.ts";
import {
  ChannelRegistry,
  type ChannelHandler,
} from "../src/relay/channel-registry.ts";
import {
  encodeFrame,
  CONTROL_CHANNEL_ID,
  FRAME_TYPE,
  MAX_FRAME_BYTES,
  MIN_FRAME_BYTES,
} from "../src/relay/channel-framing.ts";
import {
  encodeControlMessage,
  parseControlMessage,
  type ControlMessage,
} from "../src/relay/channel-control.ts";

/** Construct a dispatcher wired to a fresh registry + capture arrays. */
function makeDispatcher() {
  const registry = new ChannelRegistry();
  const sent: Uint8Array[] = [];
  const control: ControlMessage[] = [];
  const fatal: Array<{ code: string; message: string }> = [];
  const dispatcher = new ChannelDispatcher(
    registry,
    (bytes) => sent.push(bytes),
    {
      onControlMessage: (msg) => control.push(msg),
      onFatalError: (code, message) => fatal.push({ code, message }),
    },
  );
  return { dispatcher, registry, sent, control, fatal };
}

function encodeControlFrame(msg: ControlMessage): Uint8Array {
  return encodeFrame(
    CONTROL_CHANNEL_ID,
    FRAME_TYPE.DATA,
    encodeControlMessage(msg),
  );
}

describe("ChannelDispatcher — control channel", () => {
  it("routes a well-formed channel_open to onControlMessage", () => {
    const { dispatcher, control, fatal } = makeDispatcher();
    dispatcher.handlePlaintext(
      encodeControlFrame({
        type: "channel_open",
        id: 1,
        mode: "pty",
        session: "demo",
      }),
    );
    expect(fatal).toHaveLength(0);
    expect(control).toHaveLength(1);
    if (control[0].type !== "channel_open") return;
    expect(control[0]).toMatchObject({ id: 1, mode: "pty", session: "demo" });
  });

  it("flags a non-DATA frame type on channel 0 as control_frame_type", () => {
    const { dispatcher, control, fatal } = makeDispatcher();
    // Hand-build a channel-0 frame with type=SIGNAL.
    dispatcher.handlePlaintext(
      encodeFrame(CONTROL_CHANNEL_ID, FRAME_TYPE.SIGNAL, new Uint8Array(0)),
    );
    expect(control).toHaveLength(0);
    expect(fatal).toHaveLength(1);
    expect(fatal[0].code).toBe("control_frame_type");
  });

  it("flags garbage JSON on channel 0 as control_frame_json", () => {
    const { dispatcher, fatal } = makeDispatcher();
    dispatcher.handlePlaintext(
      encodeFrame(
        CONTROL_CHANNEL_ID,
        FRAME_TYPE.DATA,
        new TextEncoder().encode("{not-json"),
      ),
    );
    expect(fatal).toHaveLength(1);
    expect(fatal[0].code).toBe("control_frame_json");
  });

  it("flags unknown control type as unknown_control_type", () => {
    const { dispatcher, fatal } = makeDispatcher();
    dispatcher.handlePlaintext(
      encodeFrame(
        CONTROL_CHANNEL_ID,
        FRAME_TYPE.DATA,
        new TextEncoder().encode(JSON.stringify({ type: "from_the_future" })),
      ),
    );
    expect(fatal).toHaveLength(1);
    expect(fatal[0].code).toBe("unknown_control_type");
  });
});

describe("ChannelDispatcher — frame-level failures", () => {
  it("flags a too-short frame", () => {
    const { dispatcher, fatal } = makeDispatcher();
    dispatcher.handlePlaintext(new Uint8Array(2));
    expect(fatal).toHaveLength(1);
    expect(fatal[0].code).toBe("frame_too_short");
  });

  it("flags a too-large frame", () => {
    const { dispatcher, fatal } = makeDispatcher();
    dispatcher.handlePlaintext(new Uint8Array(MAX_FRAME_BYTES + 1));
    expect(fatal).toHaveLength(1);
    expect(fatal[0].code).toBe("frame_too_large");
  });

  it("a minimum-size empty frame on channel 0 is rejected only at parse layer", () => {
    // 5-byte frame: channel 0, type=DATA, empty payload. Decoded shape
    // is valid, but the empty payload fails JSON parse → control_frame_json.
    const { dispatcher, fatal } = makeDispatcher();
    dispatcher.handlePlaintext(new Uint8Array(MIN_FRAME_BYTES));
    expect(fatal).toHaveLength(1);
    expect(fatal[0].code).toBe("control_frame_json");
  });
});

describe("ChannelDispatcher — data routing", () => {
  it("routes a data frame on a known channel to its handler", () => {
    const { dispatcher, registry, fatal } = makeDispatcher();
    const onFrame = vi.fn();
    const close = vi.fn();
    const handler: ChannelHandler = { mode: "pty", onFrame, close };
    registry.open(1, handler);

    dispatcher.handlePlaintext(
      encodeFrame(1, FRAME_TYPE.DATA, new Uint8Array([0xaa, 0xbb, 0xcc])),
    );
    expect(fatal).toHaveLength(0);
    expect(onFrame).toHaveBeenCalledTimes(1);
    const [type, payload] = onFrame.mock.calls[0];
    expect(type).toBe(FRAME_TYPE.DATA);
    expect(Array.from(payload as Uint8Array)).toEqual([0xaa, 0xbb, 0xcc]);
  });

  it("drops a frame for an unknown channel id (no throw, no fatal)", () => {
    const { dispatcher, fatal, control } = makeDispatcher();
    expect(() =>
      dispatcher.handlePlaintext(
        encodeFrame(42, FRAME_TYPE.DATA, new Uint8Array([0])),
      ),
    ).not.toThrow();
    expect(fatal).toHaveLength(0);
    expect(control).toHaveLength(0);
  });

  it("routes SIGNAL frames the same way DATA frames are routed (handler decides)", () => {
    const { dispatcher, registry } = makeDispatcher();
    const onFrame = vi.fn();
    registry.open(7, { mode: "exec", onFrame, close: vi.fn() });
    dispatcher.handlePlaintext(
      encodeFrame(7, FRAME_TYPE.SIGNAL, new TextEncoder().encode("SIGINT")),
    );
    expect(onFrame).toHaveBeenCalledWith(FRAME_TYPE.SIGNAL, expect.any(Uint8Array));
  });
});

describe("ChannelDispatcher — outbound helpers", () => {
  it("sendControl encodes a control message to a channel-0 frame", () => {
    const { dispatcher, sent } = makeDispatcher();
    dispatcher.sendControl({ type: "keepalive" });
    expect(sent).toHaveLength(1);
    const bytes = sent[0];
    // Channel id 0, type DATA.
    expect(bytes[0]).toBe(0);
    expect(bytes[1]).toBe(0);
    expect(bytes[2]).toBe(0);
    expect(bytes[3]).toBe(0);
    expect(bytes[4]).toBe(FRAME_TYPE.DATA);
    // Payload is JSON of the message.
    const payload = bytes.slice(5);
    const parsed = parseControlMessage(payload);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.msg).toEqual({ type: "keepalive" });
  });

  it("sendData encodes a frame on the specified channel + type", () => {
    const { dispatcher, sent } = makeDispatcher();
    dispatcher.sendData(13, FRAME_TYPE.DATA, new Uint8Array([1, 2, 3]));
    expect(sent).toHaveLength(1);
    const bytes = sent[0];
    expect(bytes[0]).toBe(0);
    expect(bytes[1]).toBe(0);
    expect(bytes[2]).toBe(0);
    expect(bytes[3]).toBe(13);
    expect(bytes[4]).toBe(FRAME_TYPE.DATA);
    expect(Array.from(bytes.slice(5))).toEqual([1, 2, 3]);
  });
});
