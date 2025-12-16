import type { Nonce, Ciphertext, SecretstreamHeader, X25519PublicKey, X25519PrivateKey, Ed25519PublicKey, Ed25519PrivateKey } from './branded.ts';

/**
 * Result of single-shot encryption.
 */
export type EncryptedData = {
  readonly nonce: Nonce;
  readonly ciphertext: Ciphertext;
};

/**
 * Header for crypto_secretstream.
 */
export type StreamHeader = {
  readonly header: SecretstreamHeader;
};

/**
 * Generic keypair structure.
 */
export type KeyPair<TPub extends Uint8Array, TPriv extends Uint8Array> = {
  readonly publicKey: TPub;
  readonly privateKey: TPriv;
};

/**
 * X25519 keypair for encryption/key-wrapping operations.
 */
export type X25519KeyPair = {
  readonly publicKey: X25519PublicKey;
  readonly privateKey: X25519PrivateKey;
};

/**
 * Ed25519 keypair for signing/identity operations.
 */
export type Ed25519KeyPair = {
  readonly publicKey: Ed25519PublicKey;
  readonly privateKey: Ed25519PrivateKey;
};

/**
 * Sealed box result (anonymous encryption).
 */
export type SealedBox = {
  readonly sealed: Uint8Array;
};

/**
 * Authenticated wrapped key result.
 */
export type AuthenticatedWrappedKey = {
  readonly nonce: Nonce;
  readonly ciphertext: Ciphertext;
  readonly senderPublicKey: X25519PublicKey;
};

/**
 * Multi-recipient wrapped key.
 */
export type MultiRecipientWrappedKey<T extends SealedBox | AuthenticatedWrappedKey> = {
  readonly wrappedKeys: readonly T[];
};

/**
 * Streaming encryption state.
 *
 * @security Call dispose() when done to release resources and zero internal buffers.
 * The header getter returns a defensive copy, safe to use after dispose().
 *
 * Note: The secretstream state lives in WASM memory and cannot be directly
 * zeroed from JS. Callers should zeroize the SymmetricKey after disposal.
 */
export type EncryptStream = {
  /** Returns a copy of the header (safe to use after dispose) */
  readonly header: SecretstreamHeader;
  push(chunk: Uint8Array, isFinal: boolean): Uint8Array;
  /** Zeros internal header buffer */
  dispose(): void;
};

/**
 * Streaming decryption state.
 *
 * @security Truncation detection is enforced automatically. dispose() throws
 * STREAM_TRUNCATED if TAG_FINAL was not received, ensuring consumers cannot
 * accidentally accept truncated streams.
 *
 * dispose() will NOT throw if:
 * - finalize() was already called (explicit truncation check performed)
 * - pull() threw an error (stream already known to be invalid)
 *
 * Note: The secretstream state lives in WASM memory and cannot be directly
 * zeroed from JS. Callers should zeroize the SymmetricKey after disposal.
 */
export type DecryptStream = {
  pull(chunk: Uint8Array): { plaintext: Uint8Array; isFinal: boolean };
  /** @throws {EncryptionError} STREAM_TRUNCATED if TAG_FINAL not received */
  finalize(): void;
  /** @throws {EncryptionError} STREAM_TRUNCATED if TAG_FINAL not received and finalize() not called */
  dispose(): void;
};

/**
 * Streaming hasher interface.
 */
export type StreamingHasher = {
  update(data: Uint8Array): void;
  digest(): Promise<Uint8Array>;
};

/**
 * Key derivation context (8 bytes).
 */
export type KdfContext = 'crust___' | 'icp_____' | 'encrypt_';

/**
 * Cryptographic size constants.
 */
export const SIZES = {
  SYMMETRIC_KEY: 32,
  NONCE: 24,
  AUTH_TAG: 16,
  STREAM_HEADER: 24,
  STREAM_CHUNK_OVERHEAD: 17,
  X25519_PUBLIC_KEY: 32,
  X25519_PRIVATE_KEY: 32,
  ED25519_PUBLIC_KEY: 32,
  ED25519_PRIVATE_KEY: 64,
  SEED: 64,
  SHA256: 32,
  SEALED_BOX: 80,
  KDF_CONTEXT: 8,
  DEFAULT_CHUNK: 64 * 1024,
} as const;
