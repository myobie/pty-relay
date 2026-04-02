/**
 * Noise NK handshake implementation from scratch on libsodium.
 *
 * This implements the Noise Protocol Framework's NK pattern:
 *
 *   NK:
 *     <- s                 (pre-message: initiator knows responder's static key)
 *     ...
 *     -> e, es             (initiator sends ephemeral pubkey, DH with responder's static)
 *     <- e, ee             (responder sends ephemeral pubkey, DH both ephemerals)
 *
 * In our case:
 *   - Initiator = Client (anonymous, generates ephemeral key per session)
 *   - Responder = Daemon (has long-lived static keypair, public key in token)
 *
 * After the 2-message handshake, split() produces two CipherStates
 * (one per direction) for encrypted transport.
 *
 * References:
 *   - https://noiseprotocol.org/noise.html
 *   - Section 7.4 (NK pattern)
 *   - Section 5 (Processing rules)
 */

import sodium from "libsodium-wrappers-sumo";

// --- Constants ---

// Protocol name for NK with 25519, ChaChaPoly, BLAKE2b
// This is hashed into the initial handshake state per the Noise spec (Section 5.2)
const PROTOCOL_NAME = "Noise_NK_25519_ChaChaPoly_BLAKE2b";

const DH_LEN = 32; // Curve25519 key size
const KEY_LEN = 32; // ChaCha20-Poly1305 key size
const NONCE_LEN = 12; // ChaCha20-Poly1305-IETF nonce size
const TAG_LEN = 16; // Poly1305 tag size
const HASH_LEN = 64; // BLAKE2b output size (we use 64 for ck and h)
const MAX_NONCE = 0xFFFF_FFFF_FFFF_FFFFn; // 2^64 - 1, per Noise spec Section 5.1

// Noise spec Section 5.1: nonce is a 64-bit unsigned integer, encoded as
// 8 bytes little-endian, padded with 4 leading zero bytes to fill the
// 12-byte ChaCha20-Poly1305-IETF nonce.
//
// Layout: [0 0 0 0] [counter_lo_le] [counter_hi_le]
//          bytes 0-3   bytes 4-7       bytes 8-11
function nonceFromCounter(n: bigint): Uint8Array {
  const nonce = new Uint8Array(NONCE_LEN); // starts as all zeros
  const view = new DataView(nonce.buffer);
  view.setUint32(4, Number(n & 0xffffffffn), true);
  view.setUint32(8, Number((n >> 32n) & 0xffffffffn), true);
  return nonce;
}

// --- CipherState ---
// Wraps ChaCha20-Poly1305-IETF with auto-incrementing nonce (Noise Section 5.1)

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

  /** Encrypt plaintext with associated data. Returns ciphertext + tag. */
  encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (!this.k) throw new Error("CipherState has no key");
    if (this.n >= MAX_NONCE) throw new Error("Nonce exhausted");

    const nonce = nonceFromCounter(this.n);
    this.n++;

    return sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      plaintext,
      ad,
      null, // nsec (unused)
      nonce,
      this.k
    );
  }

  /** Decrypt ciphertext with associated data. Returns plaintext or throws. */
  decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (!this.k) throw new Error("CipherState has no key");
    if (this.n >= MAX_NONCE) throw new Error("Nonce exhausted");

    const nonce = nonceFromCounter(this.n);
    this.n++;

    const result = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
      null, // nsec (unused)
      ciphertext,
      ad,
      nonce,
      this.k
    );

    return result;
  }
}

// --- HKDF using BLAKE2b ---
// Noise uses HKDF(chaining_key, input_key_material) → (ck, k)
// Implemented with HMAC-BLAKE2b per Noise Section 4.3

function hmacBlake2b(key: Uint8Array, data: Uint8Array): Uint8Array {
  // HMAC: H(K ^ opad || H(K ^ ipad || message))
  const blockSize = 128; // BLAKE2b block size

  let keyBlock = new Uint8Array(blockSize);
  if (key.length > blockSize) {
    keyBlock.set(sodium.crypto_generichash(HASH_LEN, key));
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
  const innerHash = sodium.crypto_generichash(HASH_LEN, inner);

  const outer = new Uint8Array(blockSize + HASH_LEN);
  outer.set(opad);
  outer.set(innerHash, blockSize);
  return sodium.crypto_generichash(HASH_LEN, outer);
}

function hkdf(
  chainingKey: Uint8Array,
  inputKeyMaterial: Uint8Array
): [Uint8Array, Uint8Array] {
  // HKDF with 2 outputs (Noise Section 4.3)
  const tempKey = hmacBlake2b(chainingKey, inputKeyMaterial);
  const output1 = hmacBlake2b(tempKey, new Uint8Array([0x01]));

  const input2 = new Uint8Array(output1.length + 1);
  input2.set(output1);
  input2[output1.length] = 0x02;
  const output2 = hmacBlake2b(tempKey, input2);

  sodium.memzero(tempKey);

  return [output1, output2];
}

// --- SymmetricState ---
// Manages the chaining key (ck) and handshake hash (h) per Noise Section 5.2

class SymmetricState {
  ck: Uint8Array; // chaining key
  h: Uint8Array; // handshake hash
  private cipher: CipherState;

  constructor() {
    // Initialize with the protocol name hash (Section 5.2)
    const protocolBytes = new TextEncoder().encode(PROTOCOL_NAME);

    if (protocolBytes.length <= HASH_LEN) {
      // Pad to HASH_LEN
      this.h = new Uint8Array(HASH_LEN);
      this.h.set(protocolBytes);
    } else {
      this.h = sodium.crypto_generichash(HASH_LEN, protocolBytes);
    }

    this.ck = new Uint8Array(this.h);
    this.cipher = new CipherState();
  }

  /** Mix data into the handshake hash: h = BLAKE2b(h || data) */
  mixHash(data: Uint8Array): void {
    const combined = new Uint8Array(this.h.length + data.length);
    combined.set(this.h);
    combined.set(data, this.h.length);
    this.h = sodium.crypto_generichash(HASH_LEN, combined);
  }

  /** Mix DH output into the chaining key and derive a new cipher key */
  mixKey(inputKeyMaterial: Uint8Array): void {
    const oldCk = this.ck;
    const [newCk, tempK] = hkdf(this.ck, inputKeyMaterial);
    this.ck = newCk;
    this.cipher = new CipherState(tempK.slice(0, KEY_LEN));
    sodium.memzero(oldCk);
    sodium.memzero(tempK);
    sodium.memzero(inputKeyMaterial);
  }

  /** Encrypt plaintext using h as associated data, then mix ciphertext into h */
  encryptAndHash(plaintext: Uint8Array): Uint8Array {
    if (!this.cipher.hasKey()) {
      // Before any mixKey, just pass through
      this.mixHash(plaintext);
      return plaintext;
    }

    const ciphertext = this.cipher.encryptWithAd(this.h, plaintext);
    this.mixHash(ciphertext);
    return ciphertext;
  }

  /** Decrypt ciphertext using h as associated data, then mix ciphertext into h */
  decryptAndHash(ciphertext: Uint8Array): Uint8Array {
    if (!this.cipher.hasKey()) {
      this.mixHash(ciphertext);
      return ciphertext;
    }

    const plaintext = this.cipher.decryptWithAd(this.h, ciphertext);
    this.mixHash(ciphertext);
    return plaintext;
  }

  /** Split into two CipherStates for transport (Section 5.2) */
  split(): [CipherState, CipherState] {
    const [tempK1, tempK2] = hkdf(this.ck, new Uint8Array(0));
    const result: [CipherState, CipherState] = [
      new CipherState(tempK1.slice(0, KEY_LEN)),
      new CipherState(tempK2.slice(0, KEY_LEN)),
    ];
    // Zeroize handshake state — it's no longer needed after split
    sodium.memzero(this.ck);
    sodium.memzero(this.h);
    sodium.memzero(tempK1);
    sodium.memzero(tempK2);
    return result;
  }
}

// --- Handshake ---

/** Result of a completed handshake: two CipherStates for transport */
export interface HandshakeResult {
  /** CipherState for encrypting outgoing messages */
  send: CipherState;
  /** CipherState for decrypting incoming messages */
  recv: CipherState;
}

/**
 * Initiator (client) side of the NK handshake.
 *
 * The client knows the responder's (daemon's) static public key from the token.
 */
export class InitiatorHandshake {
  private ss: SymmetricState;
  private e: { publicKey: Uint8Array; privateKey: Uint8Array } | null = null;
  private rs: Uint8Array; // responder's static public key

  constructor(responderStaticPublicKey: Uint8Array) {
    this.rs = responderStaticPublicKey;
    this.ss = new SymmetricState();

    // Pre-message pattern: <- s
    // Mix the responder's static public key into the handshake hash
    this.ss.mixHash(this.rs);
  }

  /**
   * Step 1: Generate HELLO message.
   *
   * Pattern: -> e, es
   *   - Generate ephemeral keypair
   *   - Send ephemeral public key
   *   - DH(ephemeral_private, responder_static_public)
   *
   * Returns the 32-byte HELLO message to send to the responder.
   */
  writeHello(): Uint8Array {
    // -> e: generate ephemeral keypair
    const { publicKey, privateKey } = sodium.crypto_box_keypair();
    this.e = { publicKey, privateKey };

    // Mix ephemeral public key into hash
    this.ss.mixHash(this.e.publicKey);

    // -> es: DH(e, rs) — mixKey zeroizes the DH output
    const dh = sodium.crypto_scalarmult(this.e.privateKey, this.rs);
    this.ss.mixKey(dh);

    return new Uint8Array(this.e.publicKey);
  }

  /**
   * Step 3: Process WELCOME message and complete handshake.
   *
   * Pattern: <- e, ee
   *   - Receive responder's ephemeral public key
   *   - DH(initiator_ephemeral_private, responder_ephemeral_public)
   *
   * Returns the two CipherStates for transport.
   */
  readWelcome(welcomeMsg: Uint8Array): HandshakeResult {
    if (!this.e) throw new Error("Must call writeHello before readWelcome");
    if (welcomeMsg.length !== DH_LEN) {
      throw new Error(`WELCOME must be ${DH_LEN} bytes, got ${welcomeMsg.length}`);
    }

    // <- e: receive responder's ephemeral public key. Defensive copy so
    // mixHash's transcript can't be perturbed by a caller that reuses
    // the inbound buffer after we return.
    const re = new Uint8Array(welcomeMsg);
    this.ss.mixHash(re);

    // <- ee: DH(e, re) — mixKey zeroizes the DH output
    const dh = sodium.crypto_scalarmult(this.e.privateKey, re);
    this.ss.mixKey(dh);

    // Zeroize ephemeral private key — no longer needed
    sodium.memzero(this.e.privateKey);
    this.e = null;

    const [c1, c2] = this.ss.split();
    return { send: c1, recv: c2 };
  }
}

/**
 * Responder (daemon) side of the NK handshake.
 *
 * The daemon has a long-lived static keypair.
 */
export class ResponderHandshake {
  private ss: SymmetricState;
  private s: { publicKey: Uint8Array; privateKey: Uint8Array };
  private e: { publicKey: Uint8Array; privateKey: Uint8Array } | null = null;
  private re: Uint8Array | null = null; // initiator's ephemeral public key

  constructor(staticPublicKey: Uint8Array, staticPrivateKey: Uint8Array) {
    this.s = { publicKey: staticPublicKey, privateKey: staticPrivateKey };
    this.ss = new SymmetricState();

    // Pre-message pattern: <- s
    // Mix the responder's static public key into the handshake hash
    this.ss.mixHash(this.s.publicKey);
  }

  /**
   * Step 2a: Process HELLO message from initiator.
   *
   * Pattern: -> e, es (from initiator's perspective)
   *   - Receive initiator's ephemeral public key
   *   - DH(responder_static_private, initiator_ephemeral_public)
   */
  readHello(helloMsg: Uint8Array): void {
    if (helloMsg.length !== DH_LEN) {
      throw new Error(`HELLO must be ${DH_LEN} bytes, got ${helloMsg.length}`);
    }

    // -> e: receive initiator's ephemeral public key. Copy into a fresh buffer
    // so the handshake state never aliases a caller-owned buffer — otherwise
    // a caller that reuses the input would silently mutate `this.re` after
    // mixHash has already been computed, breaking the handshake transcript.
    this.re = new Uint8Array(helloMsg);
    this.ss.mixHash(this.re);

    // -> es: DH(s, re) — responder uses static private key. mixKey zeroizes DH output.
    const dh = sodium.crypto_scalarmult(this.s.privateKey, this.re);
    this.ss.mixKey(dh);
  }

  /**
   * Step 2b: Generate WELCOME message.
   *
   * Pattern: <- e, ee
   *   - Generate ephemeral keypair
   *   - Send ephemeral public key
   *   - DH(responder_ephemeral_private, initiator_ephemeral_public)
   *
   * Returns the 32-byte WELCOME message and the transport CipherStates.
   */
  writeWelcome(): { message: Uint8Array; result: HandshakeResult } {
    if (!this.re)
      throw new Error("Must call readHello before writeWelcome");

    // <- e: generate ephemeral keypair
    const { publicKey, privateKey } = sodium.crypto_box_keypair();
    this.e = { publicKey, privateKey };

    // Mix ephemeral public key into hash
    this.ss.mixHash(this.e.publicKey);

    // <- ee: DH(e, re) — mixKey zeroizes the DH output
    const dh = sodium.crypto_scalarmult(this.e.privateKey, this.re);
    this.ss.mixKey(dh);

    const message = new Uint8Array(this.e.publicKey);

    // Zeroize ephemeral private key — no longer needed
    sodium.memzero(this.e.privateKey);
    this.e = null;
    this.re = null;

    // Responder's send = second CipherState, recv = first
    // (opposite of initiator because split() produces [initiator_send, responder_send])
    const [c1, c2] = this.ss.split();

    return {
      message,
      result: { send: c2, recv: c1 },
    };
  }
}
