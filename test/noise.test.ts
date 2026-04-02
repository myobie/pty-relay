import { describe, it, expect, beforeAll } from "vitest";
import {
  ready,
  generateKeypair,
  InitiatorHandshake,
  ResponderHandshake,
} from "../src/crypto/index.ts";

beforeAll(async () => {
  await ready();
});

describe("Noise NK handshake", () => {
  it("both sides compute the same transport keys", () => {
    const daemon = generateKeypair();

    // Client side (initiator)
    const initiator = new InitiatorHandshake(daemon.publicKey);
    const hello = initiator.writeHello();
    expect(hello.length).toBe(32);

    // Daemon side (responder)
    const responder = new ResponderHandshake(
      daemon.publicKey,
      daemon.secretKey
    );
    responder.readHello(hello);
    const { message: welcome, result: responderResult } =
      responder.writeWelcome();
    expect(welcome.length).toBe(32);

    // Client finalizes
    const initiatorResult = initiator.readWelcome(welcome);

    // Verify: initiator's send encrypts what responder's recv decrypts
    const testMsg = new TextEncoder().encode("test");
    const encrypted = initiatorResult.send.encryptWithAd(
      new Uint8Array(0),
      testMsg
    );
    const decrypted = responderResult.recv.decryptWithAd(
      new Uint8Array(0),
      encrypted
    );
    expect(new TextDecoder().decode(decrypted)).toBe("test");

    // And vice versa
    const testMsg2 = new TextEncoder().encode("reply");
    const encrypted2 = responderResult.send.encryptWithAd(
      new Uint8Array(0),
      testMsg2
    );
    const decrypted2 = initiatorResult.recv.decryptWithAd(
      new Uint8Array(0),
      encrypted2
    );
    expect(new TextDecoder().decode(decrypted2)).toBe("reply");
  });

  it("produces different keys for different daemon keypairs", () => {
    const daemon1 = generateKeypair();
    const daemon2 = generateKeypair();

    const initiator1 = new InitiatorHandshake(daemon1.publicKey);
    const hello1 = initiator1.writeHello();
    const responder1 = new ResponderHandshake(
      daemon1.publicKey,
      daemon1.secretKey
    );
    responder1.readHello(hello1);
    const { result: result1 } = responder1.writeWelcome();

    const initiator2 = new InitiatorHandshake(daemon2.publicKey);
    const hello2 = initiator2.writeHello();
    const responder2 = new ResponderHandshake(
      daemon2.publicKey,
      daemon2.secretKey
    );
    responder2.readHello(hello2);
    const { result: result2 } = responder2.writeWelcome();

    // Different daemon keys → different encrypted outputs for same plaintext
    const msg = new TextEncoder().encode("same message");
    const enc1 = result1.send.encryptWithAd(new Uint8Array(0), msg);
    const enc2 = result2.send.encryptWithAd(new Uint8Array(0), msg);

    expect(Buffer.from(enc1).equals(Buffer.from(enc2))).toBe(false);
  });

  it("full handshake simulation without network", () => {
    const daemon = generateKeypair();

    // Initiator (client) creates HELLO
    const initiator = new InitiatorHandshake(daemon.publicKey);
    const hello = initiator.writeHello();

    // Responder (daemon) receives HELLO, creates WELCOME
    const responder = new ResponderHandshake(
      daemon.publicKey,
      daemon.secretKey
    );
    responder.readHello(hello);
    const { message: welcome, result: rResult } = responder.writeWelcome();

    // Initiator receives WELCOME
    const iResult = initiator.readWelcome(welcome);

    // Client encrypts "ping" → Daemon decrypts
    const ping = new TextEncoder().encode("ping");
    const encPing = iResult.send.encryptWithAd(new Uint8Array(0), ping);
    const decPing = rResult.recv.decryptWithAd(new Uint8Array(0), encPing);
    expect(new TextDecoder().decode(decPing)).toBe("ping");

    // Daemon encrypts "pong" → Client decrypts
    const pong = new TextEncoder().encode("pong");
    const encPong = rResult.send.encryptWithAd(new Uint8Array(0), pong);
    const decPong = iResult.recv.decryptWithAd(new Uint8Array(0), encPong);
    expect(new TextDecoder().decode(decPong)).toBe("pong");
  });

  it("rejects HELLO with wrong size", () => {
    const daemon = generateKeypair();
    const responder = new ResponderHandshake(
      daemon.publicKey,
      daemon.secretKey
    );

    expect(() => responder.readHello(new Uint8Array(16))).toThrow(/32 bytes/);
  });

  it("rejects WELCOME with wrong size", () => {
    const daemon = generateKeypair();
    const initiator = new InitiatorHandshake(daemon.publicKey);
    initiator.writeHello();

    expect(() => initiator.readWelcome(new Uint8Array(16))).toThrow(/32 bytes/);
  });

  it("handshake fails if daemon public key doesn't match", () => {
    const realDaemon = generateKeypair();
    const fakeDaemon = generateKeypair();

    // Client thinks it's talking to fakeDaemon, but the responder is realDaemon
    const initiator = new InitiatorHandshake(fakeDaemon.publicKey);
    const hello = initiator.writeHello();

    const responder = new ResponderHandshake(
      realDaemon.publicKey,
      realDaemon.secretKey
    );
    responder.readHello(hello);
    const { message: welcome, result: rResult } = responder.writeWelcome();

    // Client gets different keys (wrong daemon public key in handshake hash)
    const iResult = initiator.readWelcome(welcome);

    // Decryption should fail because the symmetric states diverged
    const msg = new TextEncoder().encode("secret");
    const encrypted = iResult.send.encryptWithAd(new Uint8Array(0), msg);

    expect(() =>
      rResult.recv.decryptWithAd(new Uint8Array(0), encrypted)
    ).toThrow();
  });
});
