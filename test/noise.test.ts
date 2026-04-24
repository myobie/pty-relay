import { describe, it, expect, beforeAll } from "vitest";
import {
  ready,
  generateKeypair,
  Handshake,
  NK,
  KK,
} from "../src/crypto/index.ts";

beforeAll(async () => {
  await ready();
});

/** Run one complete two-message handshake between matched initiator
 *  and responder instances and return their HandshakeResults. */
function runHandshake(
  initiator: Handshake,
  responder: Handshake
): { i: ReturnType<Handshake["split"]>; r: ReturnType<Handshake["split"]> } {
  const hello = initiator.writeMessage();
  responder.readMessage(hello);
  const welcome = responder.writeMessage();
  initiator.readMessage(welcome);
  return { i: initiator.split(), r: responder.split() };
}

describe("Noise NK handshake (self-hosted: anonymous client)", () => {
  it("both sides compute the same transport keys", () => {
    const daemon = generateKeypair();
    const i = new Handshake({
      pattern: NK,
      initiator: true,
      remoteStaticPublicKey: daemon.publicKey,
    });
    const r = new Handshake({
      pattern: NK,
      initiator: false,
      staticKeys: { publicKey: daemon.publicKey, privateKey: daemon.secretKey },
    });
    const { i: iResult, r: rResult } = runHandshake(i, r);

    const testMsg = new TextEncoder().encode("test");
    const enc = iResult.send.encryptWithAd(new Uint8Array(0), testMsg);
    expect(new TextDecoder().decode(
      rResult.recv.decryptWithAd(new Uint8Array(0), enc)
    )).toBe("test");

    const reply = new TextEncoder().encode("reply");
    const enc2 = rResult.send.encryptWithAd(new Uint8Array(0), reply);
    expect(new TextDecoder().decode(
      iResult.recv.decryptWithAd(new Uint8Array(0), enc2)
    )).toBe("reply");
  });

  it("different daemon keypairs produce independent streams", () => {
    const d1 = generateKeypair();
    const d2 = generateKeypair();

    const { r: r1 } = runHandshake(
      new Handshake({ pattern: NK, initiator: true, remoteStaticPublicKey: d1.publicKey }),
      new Handshake({ pattern: NK, initiator: false, staticKeys: { publicKey: d1.publicKey, privateKey: d1.secretKey } })
    );
    const { r: r2 } = runHandshake(
      new Handshake({ pattern: NK, initiator: true, remoteStaticPublicKey: d2.publicKey }),
      new Handshake({ pattern: NK, initiator: false, staticKeys: { publicKey: d2.publicKey, privateKey: d2.secretKey } })
    );

    const msg = new TextEncoder().encode("same message");
    const enc1 = r1.send.encryptWithAd(new Uint8Array(0), msg);
    const enc2 = r2.send.encryptWithAd(new Uint8Array(0), msg);
    expect(Buffer.from(enc1).equals(Buffer.from(enc2))).toBe(false);
  });

  it("rejects a HELLO with the wrong size", () => {
    const daemon = generateKeypair();
    const r = new Handshake({
      pattern: NK,
      initiator: false,
      staticKeys: { publicKey: daemon.publicKey, privateKey: daemon.secretKey },
    });
    expect(() => r.readMessage(new Uint8Array(16))).toThrow(/truncated/);
  });

  it("handshake fails at transcript time if the responder's key doesn't match what the initiator expected", () => {
    const real = generateKeypair();
    const fake = generateKeypair();

    const i = new Handshake({ pattern: NK, initiator: true, remoteStaticPublicKey: fake.publicKey });
    const r = new Handshake({
      pattern: NK,
      initiator: false,
      staticKeys: { publicKey: real.publicKey, privateKey: real.secretKey },
    });

    // Both sides mix their local view of `rs` into the handshake hash
    // before any messages. If those differ, the chain keys diverge at
    // message 1's `es` DH, and the empty authenticated payload that
    // Noise always appends to each message no longer decrypts. The
    // responder detects the mismatch when reading the initiator's
    // message, not later during transport.
    const hello = i.writeMessage();
    expect(() => r.readMessage(hello)).toThrow(/ciphertext/);
  });

  it("throws at construction when the required key is missing", () => {
    const d = generateKeypair();
    expect(
      () => new Handshake({ pattern: NK, initiator: true })
    ).toThrow(/remoteStaticPublicKey/);
    expect(
      () => new Handshake({ pattern: NK, initiator: false })
    ).toThrow(/staticKeys/);
    // NK initiator must NOT need a static keypair — this should work.
    expect(
      () => new Handshake({
        pattern: NK,
        initiator: true,
        remoteStaticPublicKey: d.publicKey,
      })
    ).not.toThrow();
  });
});

describe("Noise KK handshake (public-mode: both parties registered)", () => {
  it("both sides compute the same transport keys", () => {
    const client = generateKeypair();
    const daemon = generateKeypair();

    const i = new Handshake({
      pattern: KK,
      initiator: true,
      staticKeys: { publicKey: client.publicKey, privateKey: client.secretKey },
      remoteStaticPublicKey: daemon.publicKey,
    });
    const r = new Handshake({
      pattern: KK,
      initiator: false,
      staticKeys: { publicKey: daemon.publicKey, privateKey: daemon.secretKey },
      remoteStaticPublicKey: client.publicKey,
    });

    const { i: iResult, r: rResult } = runHandshake(i, r);

    const msg = new TextEncoder().encode("kk round-trip");
    const enc = iResult.send.encryptWithAd(new Uint8Array(0), msg);
    expect(new TextDecoder().decode(
      rResult.recv.decryptWithAd(new Uint8Array(0), enc)
    )).toBe("kk round-trip");
  });

  it("a responder expecting the wrong client static key fails the handshake", () => {
    const client = generateKeypair();
    const wrong = generateKeypair();
    const daemon = generateKeypair();

    const i = new Handshake({
      pattern: KK,
      initiator: true,
      staticKeys: { publicKey: client.publicKey, privateKey: client.secretKey },
      remoteStaticPublicKey: daemon.publicKey,
    });
    const r = new Handshake({
      pattern: KK,
      initiator: false,
      staticKeys: { publicKey: daemon.publicKey, privateKey: daemon.secretKey },
      remoteStaticPublicKey: wrong.publicKey, // LIED about who's connecting
    });

    // KK mixes both statics pre-message. If the responder's view of
    // the initiator's static differs from what the initiator actually
    // holds, the chaining key diverges at `ss` and the responder can't
    // decrypt the first message's authenticated payload. That's the
    // whole point of KK vs NK — impersonation dies at handshake time.
    const hello = i.writeMessage();
    expect(() => r.readMessage(hello)).toThrow(/ciphertext/);
  });

  it("KK requires both sides' static keys at construction", () => {
    const d = generateKeypair();
    const c = generateKeypair();

    expect(
      () => new Handshake({
        pattern: KK,
        initiator: true,
        remoteStaticPublicKey: d.publicKey,
        // missing staticKeys
      })
    ).toThrow(/staticKeys/);

    expect(
      () => new Handshake({
        pattern: KK,
        initiator: true,
        staticKeys: { publicKey: c.publicKey, privateKey: c.secretKey },
        // missing remoteStaticPublicKey
      })
    ).toThrow(/remoteStaticPublicKey/);
  });
});

describe("Handshake driver behavior", () => {
  it("isMyTurn / isComplete track message progress", () => {
    const d = generateKeypair();
    const i = new Handshake({ pattern: NK, initiator: true, remoteStaticPublicKey: d.publicKey });
    const r = new Handshake({
      pattern: NK,
      initiator: false,
      staticKeys: { publicKey: d.publicKey, privateKey: d.secretKey },
    });

    expect(i.isMyTurn()).toBe(true);
    expect(r.isMyTurn()).toBe(false);
    expect(i.isComplete()).toBe(false);

    const hello = i.writeMessage();
    expect(i.isMyTurn()).toBe(false);
    r.readMessage(hello);
    expect(r.isMyTurn()).toBe(true);

    const welcome = r.writeMessage();
    expect(r.isComplete()).toBe(true);
    i.readMessage(welcome);
    expect(i.isComplete()).toBe(true);
  });

  it("throws if writeMessage is called out of turn", () => {
    const d = generateKeypair();
    const r = new Handshake({
      pattern: NK,
      initiator: false,
      staticKeys: { publicKey: d.publicKey, privateKey: d.secretKey },
    });
    expect(() => r.writeMessage()).toThrow(/not our turn/);
  });

  it("throws if split() is called before completion", () => {
    const d = generateKeypair();
    const i = new Handshake({ pattern: NK, initiator: true, remoteStaticPublicKey: d.publicKey });
    expect(() => i.split()).toThrow(/not complete/);
  });
});
