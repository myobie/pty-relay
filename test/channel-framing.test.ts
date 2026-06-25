import { describe, it, expect } from "vitest";
import {
  encodeFrame,
  decodeFrame,
  wrapSubstream,
  unwrapSubstream,
  MIN_FRAME_BYTES,
  MAX_FRAME_BYTES,
  FRAME_TYPE,
  SUBSTREAM,
  CONTROL_CHANNEL_ID,
} from "../src/relay/channel-framing.ts";

/** Build a Uint8Array from a value-producing function (cheap fixture). */
function bytes(n: number, fill: (i: number) => number = (i) => i & 0xff): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = fill(i);
  return out;
}

describe("encodeFrame / decodeFrame round-trip", () => {
  it("round-trips an empty-payload frame on channel 0", () => {
    const encoded = encodeFrame(CONTROL_CHANNEL_ID, FRAME_TYPE.DATA, new Uint8Array(0));
    expect(encoded.length).toBe(MIN_FRAME_BYTES);
    const decoded = decodeFrame(encoded);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.frame.channelId).toBe(0);
    expect(decoded.frame.type).toBe(FRAME_TYPE.DATA);
    expect(decoded.frame.payload.length).toBe(0);
  });

  it("round-trips a frame on a non-control channel with a substantial payload", () => {
    const payload = bytes(1024);
    const encoded = encodeFrame(42, FRAME_TYPE.DATA, payload);
    const decoded = decodeFrame(encoded);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.frame.channelId).toBe(42);
    expect(decoded.frame.type).toBe(FRAME_TYPE.DATA);
    expect(Array.from(decoded.frame.payload)).toEqual(Array.from(payload));
  });

  it("encodes channel-id as big-endian", () => {
    const encoded = encodeFrame(0x12345678, FRAME_TYPE.DATA, new Uint8Array(0));
    // bytes 0..3 must be 0x12, 0x34, 0x56, 0x78 in order
    expect(encoded[0]).toBe(0x12);
    expect(encoded[1]).toBe(0x34);
    expect(encoded[2]).toBe(0x56);
    expect(encoded[3]).toBe(0x78);
  });

  it("encodes the type byte at offset 4", () => {
    const encoded = encodeFrame(1, FRAME_TYPE.SIGNAL, new Uint8Array(0));
    expect(encoded[4]).toBe(FRAME_TYPE.SIGNAL);
  });

  it("handles channel id 0xffffffff (largest u32)", () => {
    const encoded = encodeFrame(0xffffffff, 0xff, new Uint8Array(0));
    const decoded = decodeFrame(encoded);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.frame.channelId).toBe(0xffffffff);
    expect(decoded.frame.type).toBe(0xff);
  });

  it("round-trips at the MAX_FRAME_BYTES boundary", () => {
    const payload = bytes(MAX_FRAME_BYTES - MIN_FRAME_BYTES);
    const encoded = encodeFrame(1, FRAME_TYPE.DATA, payload);
    expect(encoded.length).toBe(MAX_FRAME_BYTES);
    const decoded = decodeFrame(encoded);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.frame.payload.length).toBe(MAX_FRAME_BYTES - MIN_FRAME_BYTES);
  });

  it("decoded payload is a defensive copy (mutating the source doesn't affect the result)", () => {
    const raw = bytes(20);
    const encoded = encodeFrame(1, FRAME_TYPE.DATA, raw.slice(MIN_FRAME_BYTES));
    const decoded = decodeFrame(encoded);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    // Mutate the source buffer; payload must be unaffected.
    encoded.fill(0xaa);
    expect(decoded.frame.payload[0]).not.toBe(0xaa);
  });
});

describe("encodeFrame input validation", () => {
  it("rejects a negative channel id", () => {
    expect(() => encodeFrame(-1, 0, new Uint8Array(0))).toThrow(/channel id/);
  });

  it("rejects a channel id larger than u32", () => {
    expect(() => encodeFrame(0x1_0000_0000, 0, new Uint8Array(0))).toThrow(/channel id/);
  });

  it("rejects a non-integer channel id", () => {
    expect(() => encodeFrame(1.5, 0, new Uint8Array(0))).toThrow(/channel id/);
  });

  it("rejects a type byte outside [0, 255]", () => {
    expect(() => encodeFrame(0, 256, new Uint8Array(0))).toThrow(/type/);
    expect(() => encodeFrame(0, -1, new Uint8Array(0))).toThrow(/type/);
  });

  it("rejects a payload that would push the frame over MAX_FRAME_BYTES", () => {
    const tooBig = new Uint8Array(MAX_FRAME_BYTES);
    expect(() => encodeFrame(1, 0, tooBig)).toThrow(/max/);
  });
});

describe("decodeFrame error paths", () => {
  it("rejects a frame shorter than MIN_FRAME_BYTES", () => {
    const result = decodeFrame(new Uint8Array(4));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe("frame_too_short");
  });

  it("rejects an empty input", () => {
    const result = decodeFrame(new Uint8Array(0));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe("frame_too_short");
  });

  it("rejects a frame longer than MAX_FRAME_BYTES", () => {
    // Build an oversize byte array directly (encode would refuse to make
    // one — we want to drive the decoder past the cap deliberately).
    const oversize = new Uint8Array(MAX_FRAME_BYTES + 1);
    const result = decodeFrame(oversize);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe("frame_too_large");
  });
});

describe("substream wrap/unwrap (exec mode)", () => {
  it("prepends the substream byte", () => {
    const wrapped = wrapSubstream(SUBSTREAM.STDOUT, new Uint8Array([0xaa, 0xbb]));
    expect(wrapped[0]).toBe(SUBSTREAM.STDOUT);
    expect(wrapped[1]).toBe(0xaa);
    expect(wrapped[2]).toBe(0xbb);
  });

  it("handles an empty payload (used for stdin EOF)", () => {
    const wrapped = wrapSubstream(SUBSTREAM.STDIN, new Uint8Array(0));
    expect(wrapped.length).toBe(1);
    expect(wrapped[0]).toBe(SUBSTREAM.STDIN);
  });

  it("round-trips through unwrapSubstream", () => {
    for (const ss of [SUBSTREAM.STDIN, SUBSTREAM.STDOUT, SUBSTREAM.STDERR]) {
      const wrapped = wrapSubstream(ss, new Uint8Array([1, 2, 3]));
      const unwrapped = unwrapSubstream(wrapped);
      expect(unwrapped).not.toBeNull();
      expect(unwrapped!.substream).toBe(ss);
      expect(Array.from(unwrapped!.bytes)).toEqual([1, 2, 3]);
    }
  });

  it("unwrapSubstream returns null for empty payloads (no leading byte)", () => {
    expect(unwrapSubstream(new Uint8Array(0))).toBeNull();
  });

  it("unwrapSubstream tolerates unknown substream ids (caller checks)", () => {
    // The framing layer doesn't validate the substream value — that's
    // the bridge's job. Out-of-range bytes come through verbatim.
    const wrapped = new Uint8Array([0xff, 1, 2]);
    const unwrapped = unwrapSubstream(wrapped);
    expect(unwrapped).not.toBeNull();
    expect(unwrapped!.substream).toBe(0xff);
    expect(Array.from(unwrapped!.bytes)).toEqual([1, 2]);
  });
});
