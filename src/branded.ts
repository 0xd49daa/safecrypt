import { invalidKeySize, invalidNonceSize, invalidStreamHeader } from './errors.ts';
import { SIZES } from './types.ts';

declare const brand: unique symbol;
type Brand<T, B> = T & { readonly [brand]: B };

/** 32-byte symmetric encryption key */
export type SymmetricKey = Brand<Uint8Array, 'SymmetricKey'>;

/** 24-byte nonce */
export type Nonce = Brand<Uint8Array, 'Nonce'>;

/** Encrypted ciphertext (variable length) */
export type Ciphertext = Brand<Uint8Array, 'Ciphertext'>;

/** Unique file identifier (content hash) */
export type FileId = Brand<Uint8Array, 'FileId'>;

/** 24-byte crypto_secretstream header */
export type SecretstreamHeader = Brand<Uint8Array, 'SecretstreamHeader'>;

/** 32-byte X25519 public key */
export type X25519PublicKey = Brand<Uint8Array, 'X25519PublicKey'>;

/** 32-byte X25519 private key */
export type X25519PrivateKey = Brand<Uint8Array, 'X25519PrivateKey'>;

/** 32-byte Ed25519 public key */
export type Ed25519PublicKey = Brand<Uint8Array, 'Ed25519PublicKey'>;

/** 64-byte Ed25519 private key */
export type Ed25519PrivateKey = Brand<Uint8Array, 'Ed25519PrivateKey'>;

/** 32-byte SHA-256 content hash */
export type ContentHash = Brand<Uint8Array, 'ContentHash'>;

/** 64-byte BIP-39 derived seed */
export type Seed = Brand<Uint8Array, 'Seed'>;

/**
 * Validate and brand as SymmetricKey.
 * @throws EncryptionError if not exactly 32 bytes
 */
export function asSymmetricKey(bytes: Uint8Array): SymmetricKey {
  if (bytes.length !== SIZES.SYMMETRIC_KEY) {
    throw invalidKeySize(bytes.length, SIZES.SYMMETRIC_KEY);
  }
  return bytes as SymmetricKey;
}

/**
 * Validate and brand as Nonce.
 * @throws EncryptionError if not exactly 24 bytes
 */
export function asNonce(bytes: Uint8Array): Nonce {
  if (bytes.length !== SIZES.NONCE) {
    throw invalidNonceSize(bytes.length, SIZES.NONCE);
  }
  return bytes as Nonce;
}

/**
 * Brand as Ciphertext (no size validation).
 */
export function asCiphertext(bytes: Uint8Array): Ciphertext {
  return bytes as Ciphertext;
}

/**
 * Validate and brand as FileId.
 * @throws EncryptionError if not exactly 32 bytes
 */
export function asFileId(bytes: Uint8Array): FileId {
  if (bytes.length !== SIZES.SHA256) {
    throw invalidKeySize(bytes.length, SIZES.SHA256);
  }
  return bytes as FileId;
}

/**
 * Validate and brand as SecretstreamHeader.
 * @throws EncryptionError if not exactly 24 bytes
 */
export function asSecretstreamHeader(bytes: Uint8Array): SecretstreamHeader {
  if (bytes.length !== SIZES.STREAM_HEADER) {
    throw invalidStreamHeader(`expected ${SIZES.STREAM_HEADER} bytes, got ${bytes.length}`);
  }
  return bytes as SecretstreamHeader;
}

/**
 * Validate and brand as X25519PublicKey.
 * @throws EncryptionError if not exactly 32 bytes
 */
export function asX25519PublicKey(bytes: Uint8Array): X25519PublicKey {
  if (bytes.length !== SIZES.X25519_PUBLIC_KEY) {
    throw invalidKeySize(bytes.length, SIZES.X25519_PUBLIC_KEY);
  }
  return bytes as X25519PublicKey;
}

/**
 * Validate and brand as X25519PrivateKey.
 * @throws EncryptionError if not exactly 32 bytes
 */
export function asX25519PrivateKey(bytes: Uint8Array): X25519PrivateKey {
  if (bytes.length !== SIZES.X25519_PRIVATE_KEY) {
    throw invalidKeySize(bytes.length, SIZES.X25519_PRIVATE_KEY);
  }
  return bytes as X25519PrivateKey;
}

/**
 * Validate and brand as Ed25519PublicKey.
 * @throws EncryptionError if not exactly 32 bytes
 */
export function asEd25519PublicKey(bytes: Uint8Array): Ed25519PublicKey {
  if (bytes.length !== SIZES.ED25519_PUBLIC_KEY) {
    throw invalidKeySize(bytes.length, SIZES.ED25519_PUBLIC_KEY);
  }
  return bytes as Ed25519PublicKey;
}

/**
 * Validate and brand as Ed25519PrivateKey.
 * @throws EncryptionError if not exactly 64 bytes
 */
export function asEd25519PrivateKey(bytes: Uint8Array): Ed25519PrivateKey {
  if (bytes.length !== SIZES.ED25519_PRIVATE_KEY) {
    throw invalidKeySize(bytes.length, SIZES.ED25519_PRIVATE_KEY);
  }
  return bytes as Ed25519PrivateKey;
}

/**
 * Validate and brand as ContentHash.
 * @throws EncryptionError if not exactly 32 bytes
 */
export function asContentHash(bytes: Uint8Array): ContentHash {
  if (bytes.length !== SIZES.SHA256) {
    throw invalidKeySize(bytes.length, SIZES.SHA256);
  }
  return bytes as ContentHash;
}

/**
 * Validate and brand as Seed.
 * @throws EncryptionError if not exactly 64 bytes
 */
export function asSeed(bytes: Uint8Array): Seed {
  if (bytes.length !== SIZES.SEED) {
    throw invalidKeySize(bytes.length, SIZES.SEED);
  }
  return bytes as Seed;
}

/**
 * Unsafe branding without validation.
 * Use only when source is trusted (e.g., output from libsodium functions).
 */
export const unsafe = {
  asSymmetricKey: (bytes: Uint8Array): SymmetricKey => bytes as SymmetricKey,
  asNonce: (bytes: Uint8Array): Nonce => bytes as Nonce,
  asCiphertext: (bytes: Uint8Array): Ciphertext => bytes as Ciphertext,
  asFileId: (bytes: Uint8Array): FileId => bytes as FileId,
  asSecretstreamHeader: (bytes: Uint8Array): SecretstreamHeader => bytes as SecretstreamHeader,
  asX25519PublicKey: (bytes: Uint8Array): X25519PublicKey => bytes as X25519PublicKey,
  asX25519PrivateKey: (bytes: Uint8Array): X25519PrivateKey => bytes as X25519PrivateKey,
  asEd25519PublicKey: (bytes: Uint8Array): Ed25519PublicKey => bytes as Ed25519PublicKey,
  asEd25519PrivateKey: (bytes: Uint8Array): Ed25519PrivateKey => bytes as Ed25519PrivateKey,
  asContentHash: (bytes: Uint8Array): ContentHash => bytes as ContentHash,
  asSeed: (bytes: Uint8Array): Seed => bytes as Seed,
};
