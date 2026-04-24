/**
 * Noise Protocol Framework handshake engine.
 *
 * A single token-driven `Handshake` class supports any two-message
 * interactive pattern whose messages use only the five pre-known-static
 * tokens: `e`, `ee`, `es`, `se`, `ss`. Concrete patterns are values in
 * this file.
 *
 *   - NK — initiator anonymous, responder's static pre-known.
 *          Used for self-hosted pty-relay where the client pastes a
 *          `#pk.secret` URL and has no registered identity.
 *   - KK — both parties' statics pre-known.
 *          Used for public-relay `role=client_pair` where both sides
 *          have registered Ed25519 keys (converted to Curve25519).
 *
 * Patterns that TRANSMIT a static pubkey in-band (IK, XX, etc.) would
 * need a sixth token `s` and a couple extra lines in writeMessage /
 * readMessage. Not shipped, not tested, not supported — add them
 * alongside a real test vector if the need arises.
 *
 * References:
 *   - https://noiseprotocol.org/noise.html (sections 5, 7, 8)
 */

import sodium from "libsodium-wrappers-sumo";

// --- Constants ---

const DH_LEN = 32; // Curve25519 output / public-key size
const KEY_LEN = 32; // ChaCha20-Poly1305 key size
const NONCE_LEN = 12; // ChaCha20-Poly1305-IETF nonce size
const HASH_LEN = 64; // BLAKE2b output size we use for ck and h
/** 2^64 − 1 — Noise spec § 5.1 caps the nonce counter here. */
const MAX_NONCE = 0xFFFF_FFFF_FFFF_FFFFn;

// Noise spec § 5.1: nonce is a 64-bit little-endian counter, padded with
// 4 leading zero bytes to fill the 12-byte ChaCha20-Poly1305-IETF nonce.
function nonceFromCounter(n: bigint): Uint8Array {
  const nonce = new Uint8Array(NONCE_LEN);
  const view = new DataView(nonce.buffer);
  view.setUint32(4, Number(n & 0xffffffffn), true);
  view.setUint32(8, Number((n >> 32n) & 0xffffffffn), true);
  return nonce;
}

// --- CipherState ---

/** ChaCha20-Poly1305-IETF with an auto-incrementing 64-bit nonce. */
export class CipherState {
  private k: Uint8Array | null;
  private n: bigint;

  constructor(k: Uint8Array | null = null) {
    this.k = k;
    this.n = 0n;
  }

  hasKey(): boolean {
    return this.k !== null;
  }

  encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (!this.k) throw new Error("CipherState has no key");
    if (this.n >= MAX_NONCE) throw new Error("Nonce exhausted");
    const nonce = nonceFromCounter(this.n);
    this.n++;
    return sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      plaintext, ad, null, nonce, this.k
    );
  }

  decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (!this.k) throw new Error("CipherState has no key");
    if (this.n >= MAX_NONCE) throw new Error("Nonce exhausted");
    const nonce = nonceFromCounter(this.n);
    this.n++;
    return sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
      null, ciphertext, ad, nonce, this.k
    );
  }
}

// --- HKDF (HMAC-BLAKE2b), Noise spec § 4.3 ---

function hmacBlake2b(key: Uint8Array, data: Uint8Array): Uint8Array {
  const blockSize = 128; // BLAKE2b
  const keyBlock = new Uint8Array(blockSize);
  if (key.length > blockSize) {
    keyBlock.set(sodium.crypto_generichash(HASH_LEN, key, null));
  } else {
    keyBlock.set(key);
  }
  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = keyBlock[i] ^ 0x36;
    opad[i] = keyBlock[i] ^ 0x5c;
  }
  const inner = new Uint8Array(blockSize + data.length);
  inner.set(ipad);
  inner.set(data, blockSize);
  const innerHash = sodium.crypto_generichash(HASH_LEN, inner, null);
  const outer = new Uint8Array(blockSize + HASH_LEN);
  outer.set(opad);
  outer.set(innerHash, blockSize);
  return sodium.crypto_generichash(HASH_LEN, outer, null);
}

function hkdf2(
  chainingKey: Uint8Array,
  inputKeyMaterial: Uint8Array
): [Uint8Array, Uint8Array] {
  const tempKey = hmacBlake2b(chainingKey, inputKeyMaterial);
  const output1 = hmacBlake2b(tempKey, new Uint8Array([0x01]));
  const input2 = new Uint8Array(output1.length + 1);
  input2.set(output1);
  input2[output1.length] = 0x02;
  const output2 = hmacBlake2b(tempKey, input2);
  sodium.memzero(tempKey);
  return [output1, output2];
}

// --- SymmetricState, Noise spec § 5.2 ---

class SymmetricState {
  ck: Uint8Array;
  h: Uint8Array;
  private cipher: CipherState;

  constructor(protocolName: string) {
    const protocolBytes = new TextEncoder().encode(protocolName);
    if (protocolBytes.length <= HASH_LEN) {
      this.h = new Uint8Array(HASH_LEN);
      this.h.set(protocolBytes);
    } else {
      this.h = sodium.crypto_generichash(HASH_LEN, protocolBytes, null);
    }
    this.ck = new Uint8Array(this.h);
    this.cipher = new CipherState();
  }

  mixHash(data: Uint8Array): void {
    const combined = new Uint8Array(this.h.length + data.length);
    combined.set(this.h);
    combined.set(data, this.h.length);
    this.h = sodium.crypto_generichash(HASH_LEN, combined, null);
  }

  mixKey(inputKeyMaterial: Uint8Array): void {
    const oldCk = this.ck;
    const [newCk, tempK] = hkdf2(this.ck, inputKeyMaterial);
    this.ck = newCk;
    this.cipher = new CipherState(tempK.slice(0, KEY_LEN));
    sodium.memzero(oldCk);
    sodium.memzero(tempK);
    sodium.memzero(inputKeyMaterial);
  }

  encryptAndHash(plaintext: Uint8Array): Uint8Array {
    if (!this.cipher.hasKey()) {
      this.mixHash(plaintext);
      return plaintext;
    }
    const ciphertext = this.cipher.encryptWithAd(this.h, plaintext);
    this.mixHash(ciphertext);
    return ciphertext;
  }

  decryptAndHash(ciphertext: Uint8Array): Uint8Array {
    if (!this.cipher.hasKey()) {
      this.mixHash(ciphertext);
      return ciphertext;
    }
    const plaintext = this.cipher.decryptWithAd(this.h, ciphertext);
    this.mixHash(ciphertext);
    return plaintext;
  }

  split(): [CipherState, CipherState] {
    const [k1, k2] = hkdf2(this.ck, new Uint8Array(0));
    const out: [CipherState, CipherState] = [
      new CipherState(k1.slice(0, KEY_LEN)),
      new CipherState(k2.slice(0, KEY_LEN)),
    ];
    sodium.memzero(this.ck);
    sodium.memzero(this.h);
    sodium.memzero(k1);
    sodium.memzero(k2);
    return out;
  }
}

// --- Patterns ---

/**
 * Tokens the handshake engine processes during a MESSAGE. `e` generates
 * and transmits an ephemeral; the four DH tokens mix scalar-mult output
 * into the chaining key. Each message's payload (empty for our usage)
 * is encryptAndHash'd at the end.
 *
 * Patterns like IK / XX also use an `s` token to TRANSMIT a static
 * pubkey in-band. NK and KK — the only patterns we currently ship —
 * pre-share statics via the constructor, so no `s` transmission
 * happens and the engine doesn't handle it. If we ever add such a
 * pattern we'll widen this type + add the token case alongside.
 */
export type Token = "e" | "ee" | "es" | "se" | "ss";

/** Tokens a PRE-MESSAGE references. Pre-message `s` means "this side's
 *  static is known to the peer in advance" — it's mixed into the
 *  initial handshake hash, not transmitted. Different semantics from
 *  a message-level `s`, which is why it has its own type. */
export type PreMessageToken = "s" | "e";

export interface Pattern {
  /** Full protocol name used as the SymmetricState initializer
   *  (matched byte-for-byte against the Noise spec). */
  name: string;
  /** Tokens mixed into the handshake hash before any messages — one
   *  list per side. NK: initiator=[], responder=["s"]. KK: both ["s"]. */
  preMessages: {
    initiator: PreMessageToken[];
    responder: PreMessageToken[];
  };
  /** Message sequence. Every entry is the tokens for that message;
   *  who sends it alternates starting from the initiator. */
  messages: Token[][];
}

export const NK: Pattern = {
  name: "Noise_NK_25519_ChaChaPoly_BLAKE2b",
  preMessages: { initiator: [], responder: ["s"] },
  messages: [
    ["e", "es"],  // -> e, es
    ["e", "ee"],  // <- e, ee
  ],
};

export const KK: Pattern = {
  name: "Noise_KK_25519_ChaChaPoly_BLAKE2b",
  preMessages: { initiator: ["s"], responder: ["s"] },
  messages: [
    ["e", "es", "ss"],  // -> e, es, ss
    ["e", "ee", "se"],  // <- e, ee, se
  ],
};

// --- Handshake engine ---

/** Keys a handshake party may hold. Which are required depends on the
 *  pattern's pre-messages: whatever pubkey appears there on a side
 *  must be supplied by that side (as local `staticKeys`) and by the
 *  peer (as `remoteStaticPublicKey`). */
export interface HandshakeKeys {
  staticKeys?: { publicKey: Uint8Array; privateKey: Uint8Array };
  remoteStaticPublicKey?: Uint8Array;
}

export interface HandshakeOptions extends HandshakeKeys {
  pattern: Pattern;
  initiator: boolean;
}

/** Result of a completed handshake: one CipherState per direction. */
export interface HandshakeResult {
  /** CipherState this party uses to encrypt outgoing traffic. */
  send: CipherState;
  /** CipherState this party uses to decrypt incoming traffic. */
  recv: CipherState;
}

/**
 * Generic Noise handshake driver. One instance per handshake; don't
 * reuse across sessions. Advance one message at a time via
 * `writeMessage()` and `readMessage()`; which to call first is
 * determined by whether this party is the initiator.
 *
 * After all pattern messages have been exchanged, `split()` returns
 * the transport CipherStates. Calling `writeMessage()` or
 * `readMessage()` after that throws.
 */
export class Handshake {
  private readonly pattern: Pattern;
  private readonly initiator: boolean;
  private readonly s?: { publicKey: Uint8Array; privateKey: Uint8Array };
  private readonly rs?: Uint8Array;
  private ss: SymmetricState;
  private e: { publicKey: Uint8Array; privateKey: Uint8Array } | null = null;
  private re: Uint8Array | null = null;
  private nextMessageIndex = 0;

  constructor(opts: HandshakeOptions) {
    this.pattern = opts.pattern;
    this.initiator = opts.initiator;
    this.s = opts.staticKeys;
    this.rs = opts.remoteStaticPublicKey
      ? new Uint8Array(opts.remoteStaticPublicKey)
      : undefined;

    // Validate that the keys the pattern's pre-messages demand are
    // actually supplied. We do this at construction time so a
    // misconfigured handshake fails before either side sends bytes.
    if (this.pattern.preMessages.initiator.includes("s")) {
      if (this.initiator && !this.s) {
        throw new Error(
          `${this.pattern.name}: initiator pre-message includes "s" — pass staticKeys`
        );
      }
      if (!this.initiator && !this.rs) {
        throw new Error(
          `${this.pattern.name}: initiator pre-message includes "s" — pass remoteStaticPublicKey on responder`
        );
      }
    }
    if (this.pattern.preMessages.responder.includes("s")) {
      if (!this.initiator && !this.s) {
        throw new Error(
          `${this.pattern.name}: responder pre-message includes "s" — pass staticKeys`
        );
      }
      if (this.initiator && !this.rs) {
        throw new Error(
          `${this.pattern.name}: responder pre-message includes "s" — pass remoteStaticPublicKey on initiator`
        );
      }
    }

    this.ss = new SymmetricState(this.pattern.name);

    // Pre-message mixHash — initiator first, then responder, matching
    // the order in the pattern tables of the Noise spec (§ 7).
    for (const token of this.pattern.preMessages.initiator) {
      if (token === "s") this.ss.mixHash(this.initiator ? this.s!.publicKey : this.rs!);
      else throw new Error(`pre-message token "${token}" not supported`);
    }
    for (const token of this.pattern.preMessages.responder) {
      if (token === "s") this.ss.mixHash(this.initiator ? this.rs! : this.s!.publicKey);
      else throw new Error(`pre-message token "${token}" not supported`);
    }
  }

  /** Is it this party's turn to write the next message? */
  isMyTurn(): boolean {
    if (this.nextMessageIndex >= this.pattern.messages.length) return false;
    const senderIsInitiator = this.nextMessageIndex % 2 === 0;
    return senderIsInitiator === this.initiator;
  }

  /** Have we exchanged every pattern message? If so, call split(). */
  isComplete(): boolean {
    return this.nextMessageIndex >= this.pattern.messages.length;
  }

  /** Build the next outbound message. Throws if it's not our turn. */
  writeMessage(payload: Uint8Array = new Uint8Array(0)): Uint8Array {
    if (this.isComplete()) throw new Error("handshake already complete");
    if (!this.isMyTurn()) {
      throw new Error("not our turn to write — call readMessage first");
    }

    const tokens = this.pattern.messages[this.nextMessageIndex];
    const parts: Uint8Array[] = [];

    for (const token of tokens) {
      if (token === "e") {
        const kp = sodium.crypto_box_keypair();
        this.e = { publicKey: kp.publicKey, privateKey: kp.privateKey };
        this.ss.mixHash(this.e.publicKey);
        parts.push(new Uint8Array(this.e.publicKey));
      } else {
        this.mixDh(token);
      }
    }

    const encryptedPayload = this.ss.encryptAndHash(payload);
    parts.push(encryptedPayload);

    this.nextMessageIndex++;
    return concatBytes(parts);
  }

  /** Consume the next inbound message. Throws if it's our turn instead. */
  readMessage(message: Uint8Array): Uint8Array {
    if (this.isComplete()) throw new Error("handshake already complete");
    if (this.isMyTurn()) {
      throw new Error("not our turn to read — call writeMessage first");
    }

    const tokens = this.pattern.messages[this.nextMessageIndex];
    let offset = 0;

    for (const token of tokens) {
      if (token === "e") {
        if (offset + DH_LEN > message.length) {
          throw new Error(`truncated message: expected ephemeral pubkey`);
        }
        this.re = new Uint8Array(message.subarray(offset, offset + DH_LEN));
        offset += DH_LEN;
        this.ss.mixHash(this.re);
      } else {
        this.mixDh(token);
      }
    }

    const payloadBytes = message.subarray(offset);
    const payload = this.ss.decryptAndHash(new Uint8Array(payloadBytes));

    this.nextMessageIndex++;
    return payload;
  }

  /** After `isComplete()` returns true, derive the transport ciphers.
   *  The two CipherStates are assigned to send/recv based on this
   *  party's role: initiator-send == responder-recv == split()[0]. */
  split(): HandshakeResult {
    if (!this.isComplete()) {
      throw new Error("handshake not complete — more messages remain");
    }

    // Best-effort zeroization of any keys we still hold. Ephemeral
    // privates should already be gone from mixDh; static privates are
    // caller-owned so we leave them alone.
    if (this.e) {
      sodium.memzero(this.e.privateKey);
      this.e = null;
    }
    this.re = null;

    const [c1, c2] = this.ss.split();
    return this.initiator
      ? { send: c1, recv: c2 }
      : { send: c2, recv: c1 };
  }

  /** Process one DH token. Throws if the required key isn't available. */
  private mixDh(token: "ee" | "es" | "se" | "ss"): void {
    // Per Noise § 5.3:
    //   ee → DH(e, re)
    //   es → DH(e, rs) if initiator, DH(s, re) if responder
    //   se → DH(s, re) if initiator, DH(e, rs) if responder
    //   ss → DH(s, rs)
    //
    // In every case the local party uses its local private half and
    // multiplies against the remote's public half.
    let localPriv: Uint8Array;
    let remotePub: Uint8Array;

    switch (token) {
      case "ee":
        if (!this.e) throw new Error('"ee" before generating ephemeral');
        if (!this.re) throw new Error('"ee" before receiving remote ephemeral');
        localPriv = this.e.privateKey;
        remotePub = this.re;
        break;
      case "es":
        if (this.initiator) {
          if (!this.e) throw new Error('"es" (initiator) before generating ephemeral');
          if (!this.rs) throw new Error('"es" (initiator) without remote static');
          localPriv = this.e.privateKey;
          remotePub = this.rs;
        } else {
          if (!this.s) throw new Error('"es" (responder) without static keypair');
          if (!this.re) throw new Error('"es" (responder) before receiving remote ephemeral');
          localPriv = this.s.privateKey;
          remotePub = this.re;
        }
        break;
      case "se":
        if (this.initiator) {
          if (!this.s) throw new Error('"se" (initiator) without static keypair');
          if (!this.re) throw new Error('"se" (initiator) before receiving remote ephemeral');
          localPriv = this.s.privateKey;
          remotePub = this.re;
        } else {
          if (!this.e) throw new Error('"se" (responder) before generating ephemeral');
          if (!this.rs) throw new Error('"se" (responder) without remote static');
          localPriv = this.e.privateKey;
          remotePub = this.rs;
        }
        break;
      case "ss":
        if (!this.s) throw new Error('"ss" without static keypair');
        if (!this.rs) throw new Error('"ss" without remote static');
        localPriv = this.s.privateKey;
        remotePub = this.rs;
        break;
    }

    const dh = sodium.crypto_scalarmult(localPriv, remotePub);
    this.ss.mixKey(dh);
  }
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}
