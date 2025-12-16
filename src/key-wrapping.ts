import { getSodium } from './sodium.ts';
import { unsafe, asSymmetricKey, asX25519PublicKey, asX25519PrivateKey } from './branded.ts';
import { decryptionFailed, senderMismatch } from './errors.ts';
import { constantTimeEqual } from './memory.ts';
import type { SymmetricKey, X25519PublicKey } from './branded.ts';
import type { X25519KeyPair } from './key-derivation.ts';

export type AuthenticatedWrappedKey = {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly senderPublicKey: X25519PublicKey;
};

function validateKeyPair(keyPair: X25519KeyPair): void {
  asX25519PublicKey(keyPair.publicKey);
  asX25519PrivateKey(keyPair.privateKey);
}

export async function wrapKeySeal(
  key: SymmetricKey,
  recipientPublicKey: X25519PublicKey
): Promise<Uint8Array> {
  asSymmetricKey(key); // Runtime validation
  asX25519PublicKey(recipientPublicKey); // Runtime validation
  const sodium = await getSodium();
  return sodium.crypto_box_seal(key, recipientPublicKey);
}

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

export async function wrapKeySealMulti(
  key: SymmetricKey,
  recipientPublicKeys: readonly X25519PublicKey[]
): Promise<readonly Uint8Array[]> {
  asSymmetricKey(key); // Runtime validation
  recipientPublicKeys.forEach((pk) => asX25519PublicKey(pk)); // Runtime validation
  const sodium = await getSodium();
  return recipientPublicKeys.map((pubKey) => sodium.crypto_box_seal(key, pubKey));
}

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
