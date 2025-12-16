import { describe, expect, test } from 'bun:test';
import {
  wrapKeySeal,
  wrapKeySealMulti,
  unwrapKeySeal,
  wrapKeyAuthenticated,
  wrapKeyAuthenticatedMulti,
  unwrapKeyAuthenticated,
} from '../src/key-wrapping.ts';
import { generateKey } from '../src/encryption.ts';
import { deriveEncryptionKeyPair, deriveSeed } from '../src/key-derivation.ts';
import { toHex, bytesEqual } from '../src/bytes.ts';
import { ErrorCode, EncryptionError } from '../src/errors.ts';
import { asX25519PublicKey, asX25519PrivateKey } from '../src/branded.ts';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

async function createTestKeyPair(index: number) {
  const seed = await deriveSeed(TEST_MNEMONIC);
  return deriveEncryptionKeyPair(seed, index);
}

describe('wrapKeySeal/unwrapKeySeal', () => {
  test('round-trips symmetric key', async () => {
    const keyPair = await createTestKeyPair(0);
    const symmetricKey = await generateKey();

    const sealed = await wrapKeySeal(symmetricKey, keyPair.publicKey);
    const unwrapped = await unwrapKeySeal(sealed, keyPair);

    expect(bytesEqual(unwrapped, symmetricKey)).toBe(true);
  });

  test('different recipient keypair fails with DECRYPTION_FAILED', async () => {
    const keyPair1 = await createTestKeyPair(0);
    const keyPair2 = await createTestKeyPair(1);
    const symmetricKey = await generateKey();

    const sealed = await wrapKeySeal(symmetricKey, keyPair1.publicKey);

    try {
      await unwrapKeySeal(sealed, keyPair2);
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
    }
  });

  test('tampered sealed box fails with DECRYPTION_FAILED', async () => {
    const keyPair = await createTestKeyPair(0);
    const symmetricKey = await generateKey();

    const sealed = await wrapKeySeal(symmetricKey, keyPair.publicKey);
    sealed[0] = sealed[0]! ^ 0xff;

    try {
      await unwrapKeySeal(sealed, keyPair);
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
    }
  });

  test('produces 80-byte output', async () => {
    const keyPair = await createTestKeyPair(0);
    const symmetricKey = await generateKey();

    const sealed = await wrapKeySeal(symmetricKey, keyPair.publicKey);
    expect(sealed.length).toBe(80);
  });

  test('output is different each time (ephemeral keypair)', async () => {
    const keyPair = await createTestKeyPair(0);
    const symmetricKey = await generateKey();

    const sealed1 = await wrapKeySeal(symmetricKey, keyPair.publicKey);
    const sealed2 = await wrapKeySeal(symmetricKey, keyPair.publicKey);

    expect(toHex(sealed1)).not.toBe(toHex(sealed2));
  });
});

describe('wrapKeySealMulti', () => {
  test('wraps for multiple recipients', async () => {
    const keyPair1 = await createTestKeyPair(0);
    const keyPair2 = await createTestKeyPair(1);
    const keyPair3 = await createTestKeyPair(2);
    const symmetricKey = await generateKey();

    const sealedKeys = await wrapKeySealMulti(symmetricKey, [
      keyPair1.publicKey,
      keyPair2.publicKey,
      keyPair3.publicKey,
    ]);

    expect(sealedKeys.length).toBe(3);
    expect(sealedKeys[0]!.length).toBe(80);
    expect(sealedKeys[1]!.length).toBe(80);
    expect(sealedKeys[2]!.length).toBe(80);
  });

  test('each recipient can unwrap independently', async () => {
    const keyPair1 = await createTestKeyPair(0);
    const keyPair2 = await createTestKeyPair(1);
    const keyPair3 = await createTestKeyPair(2);
    const symmetricKey = await generateKey();

    const sealedKeys = await wrapKeySealMulti(symmetricKey, [
      keyPair1.publicKey,
      keyPair2.publicKey,
      keyPair3.publicKey,
    ]);

    const unwrapped1 = await unwrapKeySeal(sealedKeys[0]!, keyPair1);
    const unwrapped2 = await unwrapKeySeal(sealedKeys[1]!, keyPair2);
    const unwrapped3 = await unwrapKeySeal(sealedKeys[2]!, keyPair3);

    expect(bytesEqual(unwrapped1, symmetricKey)).toBe(true);
    expect(bytesEqual(unwrapped2, symmetricKey)).toBe(true);
    expect(bytesEqual(unwrapped3, symmetricKey)).toBe(true);
  });

  test('recipient A cannot unwrap recipient B sealed box', async () => {
    const keyPair1 = await createTestKeyPair(0);
    const keyPair2 = await createTestKeyPair(1);
    const symmetricKey = await generateKey();

    const sealedKeys = await wrapKeySealMulti(symmetricKey, [
      keyPair1.publicKey,
      keyPair2.publicKey,
    ]);

    try {
      await unwrapKeySeal(sealedKeys[1]!, keyPair1);
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
    }
  });

  test('handles empty recipient list', async () => {
    const symmetricKey = await generateKey();
    const sealedKeys = await wrapKeySealMulti(symmetricKey, []);
    expect(sealedKeys.length).toBe(0);
  });

  test('handles single recipient', async () => {
    const keyPair = await createTestKeyPair(0);
    const symmetricKey = await generateKey();

    const sealedKeys = await wrapKeySealMulti(symmetricKey, [keyPair.publicKey]);

    expect(sealedKeys.length).toBe(1);
    const unwrapped = await unwrapKeySeal(sealedKeys[0]!, keyPair);
    expect(bytesEqual(unwrapped, symmetricKey)).toBe(true);
  });
});

describe('wrapKeyAuthenticated/unwrapKeyAuthenticated', () => {
  test('round-trips symmetric key', async () => {
    const senderKeyPair = await createTestKeyPair(0);
    const recipientKeyPair = await createTestKeyPair(1);
    const symmetricKey = await generateKey();

    const wrapped = await wrapKeyAuthenticated(
      symmetricKey,
      recipientKeyPair.publicKey,
      senderKeyPair
    );

    const unwrapped = await unwrapKeyAuthenticated(
      wrapped,
      senderKeyPair.publicKey,
      recipientKeyPair
    );

    expect(bytesEqual(unwrapped, symmetricKey)).toBe(true);
  });

  test('includes correct sender public key', async () => {
    const senderKeyPair = await createTestKeyPair(0);
    const recipientKeyPair = await createTestKeyPair(1);
    const symmetricKey = await generateKey();

    const wrapped = await wrapKeyAuthenticated(
      symmetricKey,
      recipientKeyPair.publicKey,
      senderKeyPair
    );

    expect(bytesEqual(wrapped.senderPublicKey, senderKeyPair.publicKey)).toBe(true);
  });

  test('wrong expected sender fails with SENDER_MISMATCH', async () => {
    const senderKeyPair = await createTestKeyPair(0);
    const recipientKeyPair = await createTestKeyPair(1);
    const wrongSenderKeyPair = await createTestKeyPair(2);
    const symmetricKey = await generateKey();

    const wrapped = await wrapKeyAuthenticated(
      symmetricKey,
      recipientKeyPair.publicKey,
      senderKeyPair
    );

    try {
      await unwrapKeyAuthenticated(wrapped, wrongSenderKeyPair.publicKey, recipientKeyPair);
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.SENDER_MISMATCH);
    }
  });

  test('wrong recipient keypair fails with DECRYPTION_FAILED', async () => {
    const senderKeyPair = await createTestKeyPair(0);
    const recipientKeyPair = await createTestKeyPair(1);
    const wrongRecipientKeyPair = await createTestKeyPair(2);
    const symmetricKey = await generateKey();

    const wrapped = await wrapKeyAuthenticated(
      symmetricKey,
      recipientKeyPair.publicKey,
      senderKeyPair
    );

    try {
      await unwrapKeyAuthenticated(wrapped, senderKeyPair.publicKey, wrongRecipientKeyPair);
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
    }
  });

  test('tampered ciphertext fails with DECRYPTION_FAILED', async () => {
    const senderKeyPair = await createTestKeyPair(0);
    const recipientKeyPair = await createTestKeyPair(1);
    const symmetricKey = await generateKey();

    const wrapped = await wrapKeyAuthenticated(
      symmetricKey,
      recipientKeyPair.publicKey,
      senderKeyPair
    );

    const tamperedCiphertext = new Uint8Array(wrapped.ciphertext);
    tamperedCiphertext[0] = tamperedCiphertext[0]! ^ 0xff;

    try {
      await unwrapKeyAuthenticated(
        { ...wrapped, ciphertext: tamperedCiphertext },
        senderKeyPair.publicKey,
        recipientKeyPair
      );
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
    }
  });

  test('tampered nonce fails with DECRYPTION_FAILED', async () => {
    const senderKeyPair = await createTestKeyPair(0);
    const recipientKeyPair = await createTestKeyPair(1);
    const symmetricKey = await generateKey();

    const wrapped = await wrapKeyAuthenticated(
      symmetricKey,
      recipientKeyPair.publicKey,
      senderKeyPair
    );

    const tamperedNonce = new Uint8Array(wrapped.nonce);
    tamperedNonce[0] = tamperedNonce[0]! ^ 0xff;

    try {
      await unwrapKeyAuthenticated(
        { ...wrapped, nonce: tamperedNonce },
        senderKeyPair.publicKey,
        recipientKeyPair
      );
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
    }
  });

  test('produces correct size output', async () => {
    const senderKeyPair = await createTestKeyPair(0);
    const recipientKeyPair = await createTestKeyPair(1);
    const symmetricKey = await generateKey();

    const wrapped = await wrapKeyAuthenticated(
      symmetricKey,
      recipientKeyPair.publicKey,
      senderKeyPair
    );

    expect(wrapped.nonce.length).toBe(24);
    expect(wrapped.ciphertext.length).toBe(32 + 16);
    expect(wrapped.senderPublicKey.length).toBe(32);
  });

  test('nonce is unique per wrapping', async () => {
    const senderKeyPair = await createTestKeyPair(0);
    const recipientKeyPair = await createTestKeyPair(1);
    const symmetricKey = await generateKey();

    const wrapped1 = await wrapKeyAuthenticated(
      symmetricKey,
      recipientKeyPair.publicKey,
      senderKeyPair
    );
    const wrapped2 = await wrapKeyAuthenticated(
      symmetricKey,
      recipientKeyPair.publicKey,
      senderKeyPair
    );

    expect(toHex(wrapped1.nonce)).not.toBe(toHex(wrapped2.nonce));
  });
});

describe('wrapKeyAuthenticatedMulti', () => {
  test('wraps for multiple recipients with same sender', async () => {
    const senderKeyPair = await createTestKeyPair(0);
    const recipientKeyPair1 = await createTestKeyPair(1);
    const recipientKeyPair2 = await createTestKeyPair(2);
    const recipientKeyPair3 = await createTestKeyPair(3);
    const symmetricKey = await generateKey();

    const wrappedKeys = await wrapKeyAuthenticatedMulti(
      symmetricKey,
      [recipientKeyPair1.publicKey, recipientKeyPair2.publicKey, recipientKeyPair3.publicKey],
      senderKeyPair
    );

    expect(wrappedKeys.length).toBe(3);
    expect(bytesEqual(wrappedKeys[0]!.senderPublicKey, senderKeyPair.publicKey)).toBe(true);
    expect(bytesEqual(wrappedKeys[1]!.senderPublicKey, senderKeyPair.publicKey)).toBe(true);
    expect(bytesEqual(wrappedKeys[2]!.senderPublicKey, senderKeyPair.publicKey)).toBe(true);
  });

  test('each recipient can unwrap and verify sender', async () => {
    const senderKeyPair = await createTestKeyPair(0);
    const recipientKeyPair1 = await createTestKeyPair(1);
    const recipientKeyPair2 = await createTestKeyPair(2);
    const symmetricKey = await generateKey();

    const wrappedKeys = await wrapKeyAuthenticatedMulti(
      symmetricKey,
      [recipientKeyPair1.publicKey, recipientKeyPair2.publicKey],
      senderKeyPair
    );

    const unwrapped1 = await unwrapKeyAuthenticated(
      wrappedKeys[0]!,
      senderKeyPair.publicKey,
      recipientKeyPair1
    );
    const unwrapped2 = await unwrapKeyAuthenticated(
      wrappedKeys[1]!,
      senderKeyPair.publicKey,
      recipientKeyPair2
    );

    expect(bytesEqual(unwrapped1, symmetricKey)).toBe(true);
    expect(bytesEqual(unwrapped2, symmetricKey)).toBe(true);
  });

  test('uses unique nonce per recipient', async () => {
    const senderKeyPair = await createTestKeyPair(0);
    const recipientKeyPair1 = await createTestKeyPair(1);
    const recipientKeyPair2 = await createTestKeyPair(2);
    const symmetricKey = await generateKey();

    const wrappedKeys = await wrapKeyAuthenticatedMulti(
      symmetricKey,
      [recipientKeyPair1.publicKey, recipientKeyPair2.publicKey],
      senderKeyPair
    );

    expect(toHex(wrappedKeys[0]!.nonce)).not.toBe(toHex(wrappedKeys[1]!.nonce));
  });

  test('recipient A cannot unwrap recipient B wrapped key', async () => {
    const senderKeyPair = await createTestKeyPair(0);
    const recipientKeyPair1 = await createTestKeyPair(1);
    const recipientKeyPair2 = await createTestKeyPair(2);
    const symmetricKey = await generateKey();

    const wrappedKeys = await wrapKeyAuthenticatedMulti(
      symmetricKey,
      [recipientKeyPair1.publicKey, recipientKeyPair2.publicKey],
      senderKeyPair
    );

    try {
      await unwrapKeyAuthenticated(wrappedKeys[1]!, senderKeyPair.publicKey, recipientKeyPair1);
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
    }
  });

  test('handles empty recipient list', async () => {
    const senderKeyPair = await createTestKeyPair(0);
    const symmetricKey = await generateKey();

    const wrappedKeys = await wrapKeyAuthenticatedMulti(symmetricKey, [], senderKeyPair);

    expect(wrappedKeys.length).toBe(0);
  });

  test('handles single recipient', async () => {
    const senderKeyPair = await createTestKeyPair(0);
    const recipientKeyPair = await createTestKeyPair(1);
    const symmetricKey = await generateKey();

    const wrappedKeys = await wrapKeyAuthenticatedMulti(
      symmetricKey,
      [recipientKeyPair.publicKey],
      senderKeyPair
    );

    expect(wrappedKeys.length).toBe(1);
    const unwrapped = await unwrapKeyAuthenticated(
      wrappedKeys[0]!,
      senderKeyPair.publicKey,
      recipientKeyPair
    );
    expect(bytesEqual(unwrapped, symmetricKey)).toBe(true);
  });
});

describe('security properties', () => {
  test('sealed box provides no sender authentication', async () => {
    const recipientKeyPair = await createTestKeyPair(0);
    const attacker1KeyPair = await createTestKeyPair(1);
    const attacker2KeyPair = await createTestKeyPair(2);
    const symmetricKey = await generateKey();

    const sealed1 = await wrapKeySeal(symmetricKey, recipientKeyPair.publicKey);
    const sealed2 = await wrapKeySeal(symmetricKey, recipientKeyPair.publicKey);

    const unwrapped1 = await unwrapKeySeal(sealed1, recipientKeyPair);
    const unwrapped2 = await unwrapKeySeal(sealed2, recipientKeyPair);

    expect(bytesEqual(unwrapped1, symmetricKey)).toBe(true);
    expect(bytesEqual(unwrapped2, symmetricKey)).toBe(true);
  });

  test('authenticated box sender cannot be forged', async () => {
    const realSenderKeyPair = await createTestKeyPair(0);
    const fakeSenderKeyPair = await createTestKeyPair(1);
    const recipientKeyPair = await createTestKeyPair(2);
    const symmetricKey = await generateKey();

    const wrapped = await wrapKeyAuthenticated(
      symmetricKey,
      recipientKeyPair.publicKey,
      fakeSenderKeyPair
    );

    try {
      await unwrapKeyAuthenticated(wrapped, realSenderKeyPair.publicKey, recipientKeyPair);
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.SENDER_MISMATCH);
    }
  });

  test('nonces are unique across multiple wrappings', async () => {
    const senderKeyPair = await createTestKeyPair(0);
    const recipientKeyPair = await createTestKeyPair(1);
    const symmetricKey = await generateKey();
    const nonces = new Set<string>();

    for (let i = 0; i < 100; i++) {
      const wrapped = await wrapKeyAuthenticated(
        symmetricKey,
        recipientKeyPair.publicKey,
        senderKeyPair
      );
      nonces.add(toHex(wrapped.nonce));
    }

    expect(nonces.size).toBe(100);
  });

  test('ephemeral keypair in seal provides different ciphertext each time', async () => {
    const recipientKeyPair = await createTestKeyPair(0);
    const symmetricKey = await generateKey();
    const ciphertexts = new Set<string>();

    for (let i = 0; i < 100; i++) {
      const sealed = await wrapKeySeal(symmetricKey, recipientKeyPair.publicKey);
      ciphertexts.add(toHex(sealed));
    }

    expect(ciphertexts.size).toBe(100);
  });
});

describe('interop with key-derivation', () => {
  test('works with deriveEncryptionKeyPair output', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    const senderKeyPair = await deriveEncryptionKeyPair(seed, 0);
    const recipientKeyPair = await deriveEncryptionKeyPair(seed, 1);
    const symmetricKey = await generateKey();

    const wrapped = await wrapKeyAuthenticated(
      symmetricKey,
      recipientKeyPair.publicKey,
      senderKeyPair
    );

    const unwrapped = await unwrapKeyAuthenticated(
      wrapped,
      senderKeyPair.publicKey,
      recipientKeyPair
    );

    expect(bytesEqual(unwrapped, symmetricKey)).toBe(true);
  });

  test('deterministic keypairs produce consistent results', async () => {
    const seed1 = await deriveSeed(TEST_MNEMONIC);
    const seed2 = await deriveSeed(TEST_MNEMONIC);

    const keyPair1 = await deriveEncryptionKeyPair(seed1, 0);
    const keyPair2 = await deriveEncryptionKeyPair(seed2, 0);

    expect(bytesEqual(keyPair1.publicKey, keyPair2.publicKey)).toBe(true);
    expect(bytesEqual(keyPair1.privateKey, keyPair2.privateKey)).toBe(true);

    const symmetricKey = await generateKey();
    const sealed = await wrapKeySeal(symmetricKey, keyPair1.publicKey);

    const unwrapped = await unwrapKeySeal(sealed, keyPair2);
    expect(bytesEqual(unwrapped, symmetricKey)).toBe(true);
  });
});
