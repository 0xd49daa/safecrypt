import { describe, expect, test } from 'bun:test';
import {
  generateKey,
  encrypt,
  decrypt,
} from '../../src/encryption.ts';
import {
  deriveSeed,
  deriveEncryptionKeyPair,
  deriveIdentityKeyPair,
  CONTEXT_CRUST,
  CONTEXT_ICP,
} from '../../src/key-derivation.ts';
import {
  wrapKeySeal,
  unwrapKeySeal,
  wrapKeyAuthenticated,
  unwrapKeyAuthenticated,
} from '../../src/key-wrapping.ts';
import { ErrorCode, EncryptionError } from '../../src/errors.ts';
import {
  TEST_MNEMONIC_12,
  TEST_MNEMONIC_24,
  TEST_PASSPHRASE,
  createTestData,
  SIZES,
} from '../helpers/fixtures.ts';
import { expectBytesEqual, expectBytesNotEqual } from '../helpers/assertions.ts';

describe('integration: recovery', () => {
  describe('mnemonic recovery', () => {
    test('recovers all keys from 24-word mnemonic', async () => {
      const seed = await deriveSeed(TEST_MNEMONIC_24);

      const encryptionKeyPair = await deriveEncryptionKeyPair(seed, 0);
      const crustIdentity = await deriveIdentityKeyPair(seed, CONTEXT_CRUST, 0);
      const icpIdentity = await deriveIdentityKeyPair(seed, CONTEXT_ICP, 0);

      expect(seed.length).toBe(64);
      expect(encryptionKeyPair.publicKey.length).toBe(32);
      expect(encryptionKeyPair.privateKey.length).toBe(32);
      expect(crustIdentity.publicKey.length).toBe(32);
      expect(crustIdentity.privateKey.length).toBe(64);
      expect(icpIdentity.publicKey.length).toBe(32);
      expect(icpIdentity.privateKey.length).toBe(64);
    });

    test('recovers keys with optional passphrase', async () => {
      const seedWithoutPassphrase = await deriveSeed(TEST_MNEMONIC_12);
      const seedWithPassphrase = await deriveSeed(TEST_MNEMONIC_12, TEST_PASSPHRASE);

      expectBytesNotEqual(seedWithoutPassphrase, seedWithPassphrase);

      const keyPairWithout = await deriveEncryptionKeyPair(seedWithoutPassphrase, 0);
      const keyPairWith = await deriveEncryptionKeyPair(seedWithPassphrase, 0);

      expectBytesNotEqual(keyPairWithout.publicKey, keyPairWith.publicKey);
    });

    test('same mnemonic always produces same seed', async () => {
      const seeds = await Promise.all([
        deriveSeed(TEST_MNEMONIC_12),
        deriveSeed(TEST_MNEMONIC_12),
        deriveSeed(TEST_MNEMONIC_12),
      ]);

      expectBytesEqual(seeds[0], seeds[1]);
      expectBytesEqual(seeds[1], seeds[2]);
    });

    test('12-word and 24-word mnemonics both work', async () => {
      const seed12 = await deriveSeed(TEST_MNEMONIC_12);
      const seed24 = await deriveSeed(TEST_MNEMONIC_24);

      expect(seed12.length).toBe(64);
      expect(seed24.length).toBe(64);
      expectBytesNotEqual(seed12, seed24);
    });
  });

  describe('data recovery flow', () => {
    test('encrypted file + mnemonic → recovered plaintext', async () => {
      const originalSeed = await deriveSeed(TEST_MNEMONIC_12);
      const originalKeyPair = await deriveEncryptionKeyPair(originalSeed, 0);

      const fileKey = await generateKey();
      const plaintext = new TextEncoder().encode('Important document content');
      const { nonce, ciphertext } = await encrypt(plaintext, fileKey);
      const sealedKey = await wrapKeySeal(fileKey, originalKeyPair.publicKey);

      const storedData = { nonce, ciphertext, sealedKey };

      const recoverySeed = await deriveSeed(TEST_MNEMONIC_12);
      const recoveryKeyPair = await deriveEncryptionKeyPair(recoverySeed, 0);

      const recoveredFileKey = await unwrapKeySeal(storedData.sealedKey, recoveryKeyPair);
      const recoveredPlaintext = await decrypt(
        storedData.ciphertext,
        storedData.nonce,
        recoveredFileKey
      );

      expect(new TextDecoder().decode(recoveredPlaintext)).toBe('Important document content');
    });

    test('recovers files shared by others', async () => {
      const aliceSeed = await deriveSeed(TEST_MNEMONIC_12);
      const aliceKeyPair = await deriveEncryptionKeyPair(aliceSeed, 0);

      const bobSeed = await deriveSeed(TEST_MNEMONIC_24);
      const bobKeyPair = await deriveEncryptionKeyPair(bobSeed, 0);

      const fileKey = await generateKey();
      const plaintext = new TextEncoder().encode('Shared secret from Alice');
      const { nonce, ciphertext } = await encrypt(plaintext, fileKey);
      const wrappedKey = await wrapKeyAuthenticated(fileKey, bobKeyPair.publicKey, aliceKeyPair);

      const storedData = { nonce, ciphertext, wrappedKey, senderPublicKey: aliceKeyPair.publicKey };

      const bobRecoverySeed = await deriveSeed(TEST_MNEMONIC_24);
      const bobRecoveryKeyPair = await deriveEncryptionKeyPair(bobRecoverySeed, 0);

      const recoveredFileKey = await unwrapKeyAuthenticated(
        storedData.wrappedKey,
        storedData.senderPublicKey,
        bobRecoveryKeyPair
      );
      const recoveredPlaintext = await decrypt(
        storedData.ciphertext,
        storedData.nonce,
        recoveredFileKey
      );

      expect(new TextDecoder().decode(recoveredPlaintext)).toBe('Shared secret from Alice');
    });

    test('multiple files can be recovered from single mnemonic', async () => {
      const seed = await deriveSeed(TEST_MNEMONIC_12);
      const keyPair = await deriveEncryptionKeyPair(seed, 0);

      const files = [
        { name: 'file1.txt', content: 'Content of file 1' },
        { name: 'file2.txt', content: 'Content of file 2' },
        { name: 'file3.txt', content: 'Content of file 3' },
      ];

      const encryptedFiles = await Promise.all(
        files.map(async (file) => {
          const fileKey = await generateKey();
          const plaintext = new TextEncoder().encode(file.content);
          const { nonce, ciphertext } = await encrypt(plaintext, fileKey);
          const sealedKey = await wrapKeySeal(fileKey, keyPair.publicKey);
          return { name: file.name, nonce, ciphertext, sealedKey };
        })
      );

      const recoverySeed = await deriveSeed(TEST_MNEMONIC_12);
      const recoveryKeyPair = await deriveEncryptionKeyPair(recoverySeed, 0);

      for (let i = 0; i < encryptedFiles.length; i++) {
        const encFile = encryptedFiles[i]!;
        const recoveredKey = await unwrapKeySeal(encFile.sealedKey, recoveryKeyPair);
        const recoveredPlaintext = await decrypt(encFile.ciphertext, encFile.nonce, recoveredKey);
        expect(new TextDecoder().decode(recoveredPlaintext)).toBe(files[i]!.content);
      }
    });
  });

  describe('cross-platform recovery', () => {
    test('deterministic key derivation is consistent', async () => {
      const seed = await deriveSeed(TEST_MNEMONIC_12);

      const keyPairs = await Promise.all([
        deriveEncryptionKeyPair(seed, 0),
        deriveEncryptionKeyPair(seed, 1),
        deriveEncryptionKeyPair(seed, 2),
      ]);

      const seed2 = await deriveSeed(TEST_MNEMONIC_12);
      const keyPairs2 = await Promise.all([
        deriveEncryptionKeyPair(seed2, 0),
        deriveEncryptionKeyPair(seed2, 1),
        deriveEncryptionKeyPair(seed2, 2),
      ]);

      for (let i = 0; i < keyPairs.length; i++) {
        expectBytesEqual(keyPairs[i]!.publicKey, keyPairs2[i]!.publicKey);
        expectBytesEqual(keyPairs[i]!.privateKey, keyPairs2[i]!.privateKey);
      }
    });

    test('encrypted data portable across sessions', async () => {
      const seed1 = await deriveSeed(TEST_MNEMONIC_12);
      const keyPair1 = await deriveEncryptionKeyPair(seed1, 0);

      const fileKey = await generateKey();
      const plaintext = createTestData(SIZES.MEDIUM);
      const { nonce, ciphertext } = await encrypt(plaintext, fileKey);
      const sealedKey = await wrapKeySeal(fileKey, keyPair1.publicKey);

      const seed2 = await deriveSeed(TEST_MNEMONIC_12);
      const keyPair2 = await deriveEncryptionKeyPair(seed2, 0);

      const unwrappedKey = await unwrapKeySeal(sealedKey, keyPair2);
      const decrypted = await decrypt(ciphertext, nonce, unwrappedKey);

      expectBytesEqual(decrypted, plaintext);
    });
  });

  describe('edge cases', () => {
    test('rejects non-canonical mnemonics for better typo detection', async () => {
      const normalMnemonic = TEST_MNEMONIC_12;
      const uppercaseMnemonic = TEST_MNEMONIC_12.toUpperCase();
      const extraSpacesMnemonic = TEST_MNEMONIC_12.split(' ').join('   ');

      // Normal mnemonic should work
      const seed = await deriveSeed(normalMnemonic);
      expect(seed.length).toBe(64);

      // Uppercase should be rejected
      await expect(deriveSeed(uppercaseMnemonic)).rejects.toThrow('mnemonic must be lowercase');

      // Extra spaces should be rejected
      await expect(deriveSeed(extraSpacesMnemonic)).rejects.toThrow('mnemonic must have single spaces between words');
    });

    test('rejects invalid mnemonics', async () => {
      const invalidMnemonics = [
        'abandon abandon abandon',
        'invalid words here that are not bip39',
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon',
        '',
      ];

      for (const mnemonic of invalidMnemonics) {
        try {
          await deriveSeed(mnemonic);
          expect(true).toBe(false);
        } catch (error) {
          expect(error).toBeInstanceOf(EncryptionError);
          expect((error as EncryptionError).code).toBe(ErrorCode.INVALID_MNEMONIC);
        }
      }
    });

    test('different passphrase produces different keys', async () => {
      const seed1 = await deriveSeed(TEST_MNEMONIC_12, 'password1');
      const seed2 = await deriveSeed(TEST_MNEMONIC_12, 'password2');
      const seed3 = await deriveSeed(TEST_MNEMONIC_12, '');

      expectBytesNotEqual(seed1, seed2);
      expectBytesNotEqual(seed2, seed3);
      expectBytesNotEqual(seed1, seed3);
    });

    test('recovery with wrong passphrase fails gracefully', async () => {
      const correctSeed = await deriveSeed(TEST_MNEMONIC_12, 'correct-passphrase');
      const correctKeyPair = await deriveEncryptionKeyPair(correctSeed, 0);

      const fileKey = await generateKey();
      const plaintext = new TextEncoder().encode('Secret');
      const { nonce, ciphertext } = await encrypt(plaintext, fileKey);
      const sealedKey = await wrapKeySeal(fileKey, correctKeyPair.publicKey);

      const wrongSeed = await deriveSeed(TEST_MNEMONIC_12, 'wrong-passphrase');
      const wrongKeyPair = await deriveEncryptionKeyPair(wrongSeed, 0);

      try {
        await unwrapKeySeal(sealedKey, wrongKeyPair);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
      }
    });
  });
});
