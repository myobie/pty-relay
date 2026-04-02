/**
 * Transport encryption layer over Noise NK CipherStates.
 *
 * After the handshake completes, both sides have a send and recv CipherState.
 * This module provides simple encrypt/decrypt wrappers for transport messages.
 *
 * Each encrypted message is: plaintext_length + TAG_LEN (16) bytes.
 * Nonces auto-increment inside CipherState — no nonce is transmitted.
 */

import type { CipherState, HandshakeResult } from "./noise.ts";

const EMPTY_AD = new Uint8Array(0);

export class Transport {
  private sendCipher: CipherState;
  private recvCipher: CipherState;

  constructor(handshakeResult: HandshakeResult) {
    this.sendCipher = handshakeResult.send;
    this.recvCipher = handshakeResult.recv;
  }

  /** Encrypt a plaintext message for sending. */
  encrypt(plaintext: Uint8Array): Uint8Array {
    return this.sendCipher.encryptWithAd(EMPTY_AD, plaintext);
  }

  /** Decrypt a received ciphertext message. Throws on auth failure. */
  decrypt(ciphertext: Uint8Array): Uint8Array {
    return this.recvCipher.decryptWithAd(EMPTY_AD, ciphertext);
  }
}
