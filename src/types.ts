/**
 * Result of single-shot encryption.
 */
export type EncryptedData = {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
};

/**
 * Header for crypto_secretstream.
 */
export type StreamHeader = {
  readonly header: Uint8Array;
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
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
};

/**
 * Ed25519 keypair for signing/identity operations.
 */
export type Ed25519KeyPair = {
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
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
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly senderPublicKey: Uint8Array;
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
 * @security Call dispose() when done to release resources.
 * Internal libsodium state cannot be securely zeroized from JS;
 * callers should zeroize the SymmetricKey after stream disposal.
 */
export type EncryptStream = {
  readonly header: Uint8Array;
  push(chunk: Uint8Array, isFinal: boolean): Uint8Array;
  dispose(): void;
};

/**
 * Streaming decryption state.
 *
 * @security Call finalize() after processing all chunks to verify
 * TAG_FINAL was received (prevents truncation attacks). Call dispose()
 * when done to release resources. Internal libsodium state cannot be
 * securely zeroized from JS; callers should zeroize the SymmetricKey
 * after stream disposal.
 */
export type DecryptStream = {
  pull(chunk: Uint8Array): { plaintext: Uint8Array; isFinal: boolean };
  finalize(): void;
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
