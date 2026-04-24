import { describe, it, expect, beforeAll } from "vitest";
import {
  ready,
  generateKeypair,
  Handshake,
  NK,
  Transport,
} from "../src/crypto/index.ts";

beforeAll(async () => {
  await ready();
});

function setupTransports(): { client: Transport; daemon: Transport } {
  const daemonKeys = generateKeypair();

  const initiator = new Handshake({
    pattern: NK,
    initiator: true,
    remoteStaticPublicKey: daemonKeys.publicKey,
  });
  const responder = new Handshake({
    pattern: NK,
    initiator: false,
    staticKeys: { publicKey: daemonKeys.publicKey, privateKey: daemonKeys.secretKey },
  });

  const hello = initiator.writeMessage();
  responder.readMessage(hello);
  const welcome = responder.writeMessage();
  initiator.readMessage(welcome);

  return {
    client: new Transport(initiator.split()),
    daemon: new Transport(responder.split()),
  };
}

describe("Transport", () => {
  it("encrypts and decrypts a message (client → daemon)", () => {
    const { client, daemon } = setupTransports();

    const plaintext = new TextEncoder().encode("hello from client");
    const ciphertext = client.encrypt(plaintext);
    const decrypted = daemon.decrypt(ciphertext);

    expect(new TextDecoder().decode(decrypted)).toBe("hello from client");
  });

  it("encrypts and decrypts a message (daemon → client)", () => {
    const { client, daemon } = setupTransports();

    const plaintext = new TextEncoder().encode("hello from daemon");
    const ciphertext = daemon.encrypt(plaintext);
    const decrypted = client.decrypt(ciphertext);

    expect(new TextDecoder().decode(decrypted)).toBe("hello from daemon");
  });

  it("ciphertext is larger than plaintext by 16 bytes (TAG_LEN)", () => {
    const { client } = setupTransports();

    const plaintext = new Uint8Array(100);
    const ciphertext = client.encrypt(plaintext);

    expect(ciphertext.length).toBe(100 + 16);
  });

  it("handles multiple sequential messages", () => {
    const { client, daemon } = setupTransports();

    const sizes = [0, 1, 10, 1024, 64 * 1024];

    for (const size of sizes) {
      const plaintext = new Uint8Array(size);
      // Fill with a recognizable pattern
      for (let i = 0; i < size; i++) plaintext[i] = i & 0xff;

      const ciphertext = client.encrypt(plaintext);
      const decrypted = daemon.decrypt(ciphertext);

      expect(decrypted.length).toBe(size);
      expect(Buffer.from(decrypted).equals(Buffer.from(plaintext))).toBe(true);
    }
  });

  it("fails to decrypt with wrong transport (different handshake)", () => {
    const { client: client1 } = setupTransports();
    const { daemon: daemon2 } = setupTransports();

    const plaintext = new TextEncoder().encode("secret");
    const ciphertext = client1.encrypt(plaintext);

    expect(() => daemon2.decrypt(ciphertext)).toThrow();
  });

  it("fails to decrypt tampered ciphertext", () => {
    const { client, daemon } = setupTransports();

    const plaintext = new TextEncoder().encode("important data");
    const ciphertext = client.encrypt(plaintext);

    // Flip one bit
    const tampered = new Uint8Array(ciphertext);
    tampered[0] ^= 0x01;

    expect(() => daemon.decrypt(tampered)).toThrow();
  });

  it("two independent streams work simultaneously (bidirectional)", () => {
    const { client, daemon } = setupTransports();

    // Interleave messages in both directions
    const c2d1 = client.encrypt(new TextEncoder().encode("c2d-1"));
    const d2c1 = daemon.encrypt(new TextEncoder().encode("d2c-1"));
    const c2d2 = client.encrypt(new TextEncoder().encode("c2d-2"));
    const d2c2 = daemon.encrypt(new TextEncoder().encode("d2c-2"));

    // Decrypt in order
    expect(new TextDecoder().decode(daemon.decrypt(c2d1))).toBe("c2d-1");
    expect(new TextDecoder().decode(client.decrypt(d2c1))).toBe("d2c-1");
    expect(new TextDecoder().decode(daemon.decrypt(c2d2))).toBe("c2d-2");
    expect(new TextDecoder().decode(client.decrypt(d2c2))).toBe("d2c-2");
  });

  it("ciphertext does not contain plaintext", () => {
    const { client } = setupTransports();

    const plaintext = new TextEncoder().encode("super secret message");
    const ciphertext = client.encrypt(plaintext);

    // The ciphertext should not contain the plaintext bytes
    const plaintextStr = Buffer.from(plaintext).toString("hex");
    const ciphertextStr = Buffer.from(ciphertext).toString("hex");

    expect(ciphertextStr).not.toContain(plaintextStr);
  });

  it("100 messages in each direction", () => {
    const { client, daemon } = setupTransports();

    // Send 100 messages client → daemon
    const c2dCiphertexts: Uint8Array[] = [];
    for (let i = 0; i < 100; i++) {
      const msg = new TextEncoder().encode(`c2d-${i}`);
      c2dCiphertexts.push(client.encrypt(msg));
    }

    // Send 100 messages daemon → client
    const d2cCiphertexts: Uint8Array[] = [];
    for (let i = 0; i < 100; i++) {
      const msg = new TextEncoder().encode(`d2c-${i}`);
      d2cCiphertexts.push(daemon.encrypt(msg));
    }

    // Decrypt all (ordering preserved)
    for (let i = 0; i < 100; i++) {
      const dec = new TextDecoder().decode(daemon.decrypt(c2dCiphertexts[i]));
      expect(dec).toBe(`c2d-${i}`);
    }

    for (let i = 0; i < 100; i++) {
      const dec = new TextDecoder().decode(client.decrypt(d2cCiphertexts[i]));
      expect(dec).toBe(`d2c-${i}`);
    }
  });
});
