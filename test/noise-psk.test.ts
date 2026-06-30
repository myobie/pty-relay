import { describe, it, expect, beforeAll } from "vitest";
import sodium from "libsodium-wrappers-sumo";
import {
  ready,
  generateKeypair,
  Handshake,
  NK,
  NKpsk2,
  PSK_LEN,
  Transport,
} from "../src/crypto/index.ts";

beforeAll(async () => {
  await ready();
});

/** Run one complete two-message handshake between matched parties and
 *  return their HandshakeResults. */
function runHandshake(initiator: Handshake, responder: Handshake) {
  const hello = initiator.writeMessage();
  responder.readMessage(hello);
  const welcome = responder.writeMessage();
  initiator.readMessage(welcome);
  return { i: initiator.split(), r: responder.split() };
}

function randomPsk(): Uint8Array {
  return sodium.randombytes_buf(PSK_LEN);
}

describe("Noise NKpsk2 handshake — happy path", () => {
  it("both sides compute the same transport keys when the PSK matches", () => {
    const daemon = generateKeypair();
    const psk = randomPsk();
    const i = new Handshake({
      pattern: NKpsk2,
      initiator: true,
      remoteStaticPublicKey: daemon.publicKey,
      preSharedKey: psk,
    });
    const r = new Handshake({
      pattern: NKpsk2,
      initiator: false,
      staticKeys: { publicKey: daemon.publicKey, privateKey: daemon.secretKey },
      preSharedKey: psk,
    });
    const { i: iKeys, r: rKeys } = runHandshake(i, r);

    // initiator-send must equal responder-recv (and vice versa) for
    // bidirectional transport.
    const it_ = new Transport(iKeys);
    const rt_ = new Transport(rKeys);
    const msg1 = it_.encrypt(new TextEncoder().encode("hello"));
    expect(new TextDecoder().decode(rt_.decrypt(msg1))).toBe("hello");
    const msg2 = rt_.encrypt(new TextEncoder().encode("world"));
    expect(new TextDecoder().decode(it_.decrypt(msg2))).toBe("world");
  });

  it("split() runs both directions with a different psk per handshake (no key reuse across sessions)", () => {
    const daemon = generateKeypair();
    const make = (psk: Uint8Array) => {
      const ini = new Handshake({
        pattern: NKpsk2,
        initiator: true,
        remoteStaticPublicKey: daemon.publicKey,
        preSharedKey: psk,
      });
      const res = new Handshake({
        pattern: NKpsk2,
        initiator: false,
        staticKeys: { publicKey: daemon.publicKey, privateKey: daemon.secretKey },
        preSharedKey: psk,
      });
      return runHandshake(ini, res);
    };

    const a = make(randomPsk());
    const b = make(randomPsk());

    // Same plaintext encrypted under independent transports must
    // produce distinct ciphertexts.
    const ta = new Transport(a.i);
    const tb = new Transport(b.i);
    const ca = ta.encrypt(new TextEncoder().encode("x"));
    const cb = tb.encrypt(new TextEncoder().encode("x"));
    expect(Array.from(ca)).not.toEqual(Array.from(cb));
  });
});

describe("Noise NKpsk2 handshake — auth failures", () => {
  it("responder rejects the initiator when the PSK doesn't match", () => {
    const daemon = generateKeypair();
    const i = new Handshake({
      pattern: NKpsk2,
      initiator: true,
      remoteStaticPublicKey: daemon.publicKey,
      preSharedKey: randomPsk(),
    });
    const r = new Handshake({
      pattern: NKpsk2,
      initiator: false,
      staticKeys: { publicKey: daemon.publicKey, privateKey: daemon.secretKey },
      preSharedKey: randomPsk(), // different PSK
    });

    // First message uses only `e, es` — has not consumed the PSK yet
    // on either side, so the first read succeeds.
    const hello = i.writeMessage();
    r.readMessage(hello);

    // Responder's second message mixes its (different) PSK after `ee`
    // — initiator can't decrypt it.
    const welcome = r.writeMessage();
    expect(() => i.readMessage(welcome)).toThrow();
  });

  it("responder rejects the initiator when the PSK is right size but wrong bytes (off by one)", () => {
    const daemon = generateKeypair();
    const correct = randomPsk();
    const tampered = new Uint8Array(correct);
    tampered[0] ^= 0x01;

    const i = new Handshake({
      pattern: NKpsk2,
      initiator: true,
      remoteStaticPublicKey: daemon.publicKey,
      preSharedKey: correct,
    });
    const r = new Handshake({
      pattern: NKpsk2,
      initiator: false,
      staticKeys: { publicKey: daemon.publicKey, privateKey: daemon.secretKey },
      preSharedKey: tampered,
    });

    const hello = i.writeMessage();
    r.readMessage(hello);
    const welcome = r.writeMessage();
    expect(() => i.readMessage(welcome)).toThrow();
  });

  it("a v1-NK client cannot interop with an NKpsk2 responder — the protocol-name differs so even message 1 fails", () => {
    const daemon = generateKeypair();
    const i = new Handshake({
      pattern: NK,
      initiator: true,
      remoteStaticPublicKey: daemon.publicKey,
    });
    const r = new Handshake({
      pattern: NKpsk2,
      initiator: false,
      staticKeys: { publicKey: daemon.publicKey, privateKey: daemon.secretKey },
      preSharedKey: randomPsk(),
    });

    const hello = i.writeMessage();
    // NK and NKpsk2 use different protocol names ("Noise_NK_…" vs
    // "Noise_NKpsk2_…"), which seed different initial SymmetricState
    // hashes. The chaining + cipher keys diverge from message 1's
    // encryptAndHash, so the responder can't decrypt the initiator's
    // first message at all. Defense by construction: no chance for a
    // v1 client to slip past a v2-only daemon.
    expect(() => r.readMessage(hello)).toThrow();
  });
});

describe("Noise NKpsk2 handshake — input validation", () => {
  it("throws at construction if a psk-pattern is used without a preSharedKey", () => {
    const daemon = generateKeypair();
    expect(
      () =>
        new Handshake({
          pattern: NKpsk2,
          initiator: true,
          remoteStaticPublicKey: daemon.publicKey,
        }),
    ).toThrow(/pass preSharedKey/);
  });

  it("throws at construction if the PSK is too short", () => {
    const daemon = generateKeypair();
    expect(
      () =>
        new Handshake({
          pattern: NKpsk2,
          initiator: true,
          remoteStaticPublicKey: daemon.publicKey,
          preSharedKey: new Uint8Array(31),
        }),
    ).toThrow(/exactly 32/);
  });

  it("throws at construction if the PSK is too long", () => {
    const daemon = generateKeypair();
    expect(
      () =>
        new Handshake({
          pattern: NKpsk2,
          initiator: true,
          remoteStaticPublicKey: daemon.publicKey,
          preSharedKey: new Uint8Array(33),
        }),
    ).toThrow(/exactly 32/);
  });

  it("throws at construction if a non-psk pattern is given a preSharedKey (defense against caller misconfiguration)", () => {
    const daemon = generateKeypair();
    expect(
      () =>
        new Handshake({
          pattern: NK,
          initiator: true,
          remoteStaticPublicKey: daemon.publicKey,
          preSharedKey: randomPsk(),
        }),
    ).toThrow(/no "psk" token/);
  });
});

describe("Noise NKpsk2 — protocol name", () => {
  it("matches the spec-canonical Noise_NKpsk2_25519_ChaChaPoly_BLAKE2b string", () => {
    expect(NKpsk2.name).toBe("Noise_NKpsk2_25519_ChaChaPoly_BLAKE2b");
  });

  it("has the psk token in the second message (not the first — that would be psk0)", () => {
    expect(NKpsk2.messages[0]).toEqual(["e", "es"]);
    expect(NKpsk2.messages[1]).toEqual(["e", "ee", "psk"]);
  });
});

describe("PSK_LEN constant", () => {
  it("is 32 bytes per Noise spec § 9", () => {
    expect(PSK_LEN).toBe(32);
  });
});
