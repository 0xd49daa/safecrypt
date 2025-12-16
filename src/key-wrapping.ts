import { getSodium } from './sodium.ts';
import { unsafe, asSymmetricKey, asX25519PublicKey, asX25519PrivateKey } from './branded.ts';
import { decryptionFailed, senderMismatch } from './errors.ts';
import { constantTimeEqual } from './memory.ts';
import type { SymmetricKey, X25519PublicKey } from './branded.ts';
import type { X25519KeyPair } from './key-derivation.ts';

/**
 * Result of authenticated key wrapping, includes sender identity for verification.
 */
export type AuthenticatedWrappedKey = {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly senderPublicKey: X25519PublicKey;
};

function validateKeyPair(keyPair: X25519KeyPair): void {
  asX25519PublicKey(keyPair.publicKey);
  asX25519PrivateKey(keyPair.privateKey);
}

/**
 * Wraps a symmetric key anonymously using sealed box (X25519 + XSalsa20-Poly1305).
 * Use for self-encryption or when sender identity is not needed.
 * @param key - Symmetric key to wrap
 * @param recipientPublicKey - Recipient's X25519 public key
 * @returns 48-byte sealed box (32-byte ephemeral pk + 16-byte tag + 32-byte encrypted key)
 */
export async function wrapKeySeal(
  key: SymmetricKey,
  recipientPublicKey: X25519PublicKey
): Promise<Uint8Array> {
  asSymmetricKey(key); // Runtime validation
  asX25519PublicKey(recipientPublicKey); // Runtime validation
  const sodium = await getSodium();
  return sodium.crypto_box_seal(key, recipientPublicKey);
}

/**
 * Unwraps a symmetric key from a sealed box.
 * @param sealedKey - Sealed box from wrapKeySeal()
 * @param recipientKeyPair - Recipient's X25519 keypair
 * @returns Unwrapped symmetric key
 * @throws {EncryptionError} DECRYPTION_FAILED if decryption fails
 */
export async function unwrapKeySeal(
  sealedKey: Uint8Array,
  recipientKeyPair: X25519KeyPair
): Promise<SymmetricKey> {
  validateKeyPair(recipientKeyPair); // Runtime validation
  const sodium = await getSodium();

  try {
    const key = sodium.crypto_box_seal_open(
      sealedKey,
      recipientKeyPair.publicKey,
      recipientKeyPair.privateKey
    );
    return unsafe.asSymmetricKey(key);
  } catch (error) {
    throw decryptionFailed(error instanceof Error ? error : undefined);
  }
}

/**
 * Wraps a symmetric key for multiple recipients using sealed boxes.
 * @param key - Symmetric key to wrap
 * @param recipientPublicKeys - Array of recipient X25519 public keys
 * @returns Array of sealed boxes, one per recipient
 */
export async function wrapKeySealMulti(
  key: SymmetricKey,
  recipientPublicKeys: readonly X25519PublicKey[]
): Promise<readonly Uint8Array[]> {
  asSymmetricKey(key); // Runtime validation
  recipientPublicKeys.forEach((pk) => asX25519PublicKey(pk)); // Runtime validation
  const sodium = await getSodium();
  return recipientPublicKeys.map((pubKey) => sodium.crypto_box_seal(key, pubKey));
}

/**
 * Wraps a symmetric key with sender authentication (crypto_box).
 * Use for user-to-user key sharing where sender identity matters.
 * @param key - Symmetric key to wrap
 * @param recipientPublicKey - Recipient's X25519 public key
 * @param senderKeyPair - Sender's X25519 keypair for authentication
 * @returns Wrapped key with nonce, ciphertext, and sender public key
 */
export async function wrapKeyAuthenticated(
  key: SymmetricKey,
  recipientPublicKey: X25519PublicKey,
  senderKeyPair: X25519KeyPair
): Promise<AuthenticatedWrappedKey> {
  asSymmetricKey(key); // Runtime validation
  asX25519PublicKey(recipientPublicKey); // Runtime validation
  validateKeyPair(senderKeyPair); // Runtime validation
  const sodium = await getSodium();
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);

  const ciphertext = sodium.crypto_box_easy(
    key,
    nonce,
    recipientPublicKey,
    senderKeyPair.privateKey
  );

  return {
    nonce,
    ciphertext,
    senderPublicKey: senderKeyPair.publicKey,
  };
}

/**
 * Unwraps a symmetric key and verifies sender identity.
 * @param wrapped - Wrapped key from wrapKeyAuthenticated()
 * @param expectedSenderPublicKey - Expected sender's public key for verification
 * @param recipientKeyPair - Recipient's X25519 keypair
 * @returns Unwrapped symmetric key
 * @throws {EncryptionError} SENDER_MISMATCH if sender key doesn't match expected
 * @throws {EncryptionError} DECRYPTION_FAILED if decryption fails
 */
export async function unwrapKeyAuthenticated(
  wrapped: AuthenticatedWrappedKey,
  expectedSenderPublicKey: X25519PublicKey,
  recipientKeyPair: X25519KeyPair
): Promise<SymmetricKey> {
  asX25519PublicKey(expectedSenderPublicKey); // Runtime validation
  validateKeyPair(recipientKeyPair); // Runtime validation
  const isMatch = await constantTimeEqual(wrapped.senderPublicKey, expectedSenderPublicKey);
  if (!isMatch) {
    throw senderMismatch();
  }

  const sodium = await getSodium();

  try {
    const key = sodium.crypto_box_open_easy(
      wrapped.ciphertext,
      wrapped.nonce,
      wrapped.senderPublicKey,
      recipientKeyPair.privateKey
    );
    return unsafe.asSymmetricKey(key);
  } catch (error) {
    throw decryptionFailed(error instanceof Error ? error : undefined);
  }
}

/**
 * Wraps a symmetric key for multiple recipients with sender authentication.
 * @param key - Symmetric key to wrap
 * @param recipientPublicKeys - Array of recipient X25519 public keys
 * @param senderKeyPair - Sender's X25519 keypair for authentication
 * @returns Array of authenticated wrapped keys, one per recipient
 */
export async function wrapKeyAuthenticatedMulti(
  key: SymmetricKey,
  recipientPublicKeys: readonly X25519PublicKey[],
  senderKeyPair: X25519KeyPair
): Promise<readonly AuthenticatedWrappedKey[]> {
  asSymmetricKey(key); // Runtime validation
  recipientPublicKeys.forEach((pk) => asX25519PublicKey(pk)); // Runtime validation
  validateKeyPair(senderKeyPair); // Runtime validation
  const sodium = await getSodium();

  return recipientPublicKeys.map((recipientPubKey) => {
    const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);

    const ciphertext = sodium.crypto_box_easy(
      key,
      nonce,
      recipientPubKey,
      senderKeyPair.privateKey
    );

    return {
      nonce,
      ciphertext,
      senderPublicKey: senderKeyPair.publicKey,
    };
  });
}
