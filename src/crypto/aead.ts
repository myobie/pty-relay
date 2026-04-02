import sodium from "libsodium-wrappers-sumo";

export type KdfProfile = "moderate" | "interactive";

/**
 * Derive a 32-byte key from a passphrase using Argon2id.
 * Profile selects opslimit/memlimit.
 * Caller must ensure libsodium is ready (sodium.ready).
 */
export function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  profile: KdfProfile
): Uint8Array {
  if (salt.length !== sodium.crypto_pwhash_SALTBYTES) {
    throw new Error(
      `deriveKey: salt must be ${sodium.crypto_pwhash_SALTBYTES} bytes`
    );
  }

  const { opslimit, memlimit } = profileParams(profile);
  const keyLen = sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
  const passphraseBytes = sodium.from_string(passphrase);

  return sodium.crypto_pwhash(
    keyLen,
    passphraseBytes,
    salt,
    opslimit,
    memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
}

export function profileParams(profile: KdfProfile): {
  opslimit: number;
  memlimit: number;
} {
  if (profile === "moderate") {
    return {
      opslimit: sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      memlimit: sodium.crypto_pwhash_MEMLIMIT_MODERATE,
    };
  }
  return {
    opslimit: sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    memlimit: sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
  };
}

/**
 * Encrypt a plaintext blob with XChaCha20-Poly1305 using a random nonce.
 */
export function encryptBlob(
  key: Uint8Array,
  plaintext: Uint8Array
): { nonce: Uint8Array; ct: Uint8Array } {
  if (key.length !== sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
    throw new Error(
      `encryptBlob: key must be ${sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES} bytes`
    );
  }

  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    null, // no additional data
    null, // nsec is always null
    nonce,
    key
  );
  return { nonce, ct };
}

/**
 * Decrypt a blob. Throws on authentication failure.
 */
export function decryptBlob(
  key: Uint8Array,
  nonce: Uint8Array,
  ct: Uint8Array
): Uint8Array {
  if (key.length !== sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
    throw new Error("decryptBlob: wrong key length");
  }
  if (nonce.length !== sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
    throw new Error("decryptBlob: wrong nonce length");
  }

  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, // nsec
    ct,
    null, // no additional data
    nonce,
    key
  );
}

/** 16 random bytes, suitable for Argon2id salt. */
export function randomSalt(): Uint8Array {
  return sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
}

/** 32 random bytes, suitable for an XChaCha20-Poly1305 key. */
export function randomKey(): Uint8Array {
  return sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
  );
}

/**
 * Best-effort overwrite of a buffer with zeros.
 * JavaScript does not give us any real guarantees about memory, but this
 * at least clears the visible view.
 */
export function zeroize(buf: Uint8Array): void {
  try {
    buf.fill(0);
  } catch {
    // ignore (e.g. if buf is frozen)
  }
}
