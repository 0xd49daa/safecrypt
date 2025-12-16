export { ErrorCode, EncryptionError } from './errors.ts';

export type {
  EncryptedData,
  EncryptStream,
  DecryptStream,
  KdfContext,
  StreamingHasher,
} from './types.ts';

export { SIZES } from './types.ts';

export type {
  SymmetricKey,
  Nonce,
  Ciphertext,
  FileId,
  SecretstreamHeader,
  X25519PublicKey,
  X25519PrivateKey,
  Ed25519PublicKey,
  Ed25519PrivateKey,
  ContentHash,
  Seed,
} from './branded.ts';

export { asContentHash } from './branded.ts';

export { toBase64, fromBase64 } from './bytes.ts';

export { secureZero, secureZeroAsync, constantTimeEqual, randomBytes } from './memory.ts';

export { preloadSodium } from './sodium.ts';

export { hash, hashBlake2b, createBlake2bHasher } from './hash.ts';

export {
  deriveSeed,
  deriveEncryptionKeyPair,
  deriveIdentityKeyPair,
  CONTEXT_CRUST,
  CONTEXT_ICP,
} from './key-derivation.ts';

export type { X25519KeyPair, Ed25519KeyPair } from './key-derivation.ts';

export {
  generateKey,
  encrypt,
  decrypt,
  createEncryptStream,
  createDecryptStream,
} from './encryption.ts';

export {
  wrapKeySeal,
  unwrapKeySeal,
  wrapKeySealMulti,
  wrapKeyAuthenticated,
  wrapKeyAuthenticatedMulti,
  unwrapKeyAuthenticated,
} from './key-wrapping.ts';

export type { AuthenticatedWrappedKey } from './key-wrapping.ts';
