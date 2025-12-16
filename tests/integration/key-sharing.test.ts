import { describe, expect, test } from 'bun:test';
import {
  generateKey,
  encrypt,
  decrypt,
  createEncryptStream,
  createDecryptStream,
} from '../../src/encryption.ts';
import {
  deriveSeed,
  deriveEncryptionKeyPair,
  deriveIdentityKeyPair,
  CONTEXT_CRUST,
  CONTEXT_ICP,
  CONTEXT_ENCRYPT,
} from '../../src/key-derivation.ts';
import {
  wrapKeySeal,
  unwrapKeySeal,
  wrapKeyAuthenticated,
  unwrapKeyAuthenticated,
  wrapKeyAuthenticatedMulti,
} from '../../src/key-wrapping.ts';
import { ErrorCode, EncryptionError } from '../../src/errors.ts';
import {
  TEST_MNEMONIC_12,
  TEST_MNEMONIC_24,
  createTestData,
  SIZES,
  CHUNK_SIZE,
} from '../helpers/fixtures.ts';
import { expectBytesEqual, expectBytesNotEqual } from '../helpers/assertions.ts';

describe('integration: key-sharing', () => {
  describe('self-encryption (single user, multiple devices)', () => {
    test('user encrypts file on device A, decrypts on device B', async () => {
      const mnemonic = TEST_MNEMONIC_12;

      const seedDeviceA = await deriveSeed(mnemonic);
      const keyPairDeviceA = await deriveEncryptionKeyPair(seedDeviceA, 0);

      const fileKey = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);
      const { nonce, ciphertext } = await encrypt(plaintext, fileKey);

      const sealedKey = await wrapKeySeal(fileKey, keyPairDeviceA.publicKey);

      const seedDeviceB = await deriveSeed(mnemonic);
      const keyPairDeviceB = await deriveEncryptionKeyPair(seedDeviceB, 0);

      const unwrappedKey = await unwrapKeySeal(sealedKey, keyPairDeviceB);
      const decrypted = await decrypt(ciphertext, nonce, unwrappedKey);

      expectBytesEqual(decrypted, plaintext);
    });

    test('same mnemonic produces same keypairs on different devices', async () => {
      const mnemonic = TEST_MNEMONIC_24;

      const seed1 = await deriveSeed(mnemonic);
      const seed2 = await deriveSeed(mnemonic);

      const keyPair1 = await deriveEncryptionKeyPair(seed1, 0);
      const keyPair2 = await deriveEncryptionKeyPair(seed2, 0);

      expectBytesEqual(keyPair1.publicKey, keyPair2.publicKey);
      expectBytesEqual(keyPair1.privateKey, keyPair2.privateKey);
    });

    test('sealed keys can be unwrapped by any device with mnemonic', async () => {
      const mnemonic = TEST_MNEMONIC_12;
      const seed = await deriveSeed(mnemonic);
      const keyPair = await deriveEncryptionKeyPair(seed, 0);

      const fileKeys = await Promise.all([generateKey(), generateKey(), generateKey()]);

      const sealedKeys = await Promise.all(
        fileKeys.map((key) => wrapKeySeal(key, keyPair.publicKey))
      );

      const differentDeviceSeed = await deriveSeed(mnemonic);
      const differentDeviceKeyPair = await deriveEncryptionKeyPair(differentDeviceSeed, 0);

      for (let i = 0; i < fileKeys.length; i++) {
        const unwrapped = await unwrapKeySeal(sealedKeys[i]!, differentDeviceKeyPair);
        expectBytesEqual(unwrapped, fileKeys[i]!);
      }
    });
  });

  describe('user-to-user sharing', () => {
    test('Alice shares file with Bob using authenticated wrapping', async () => {
      const aliceSeed = await deriveSeed(TEST_MNEMONIC_12);
      const aliceKeyPair = await deriveEncryptionKeyPair(aliceSeed, 0);

      const bobSeed = await deriveSeed(TEST_MNEMONIC_24);
      const bobKeyPair = await deriveEncryptionKeyPair(bobSeed, 0);

      const fileKey = await generateKey();
      const plaintext = new TextEncoder().encode('Secret message from Alice to Bob');
      const { nonce, ciphertext } = await encrypt(plaintext, fileKey);

      const wrappedKey = await wrapKeyAuthenticated(fileKey, bobKeyPair.publicKey, aliceKeyPair);

      const unwrappedKey = await unwrapKeyAuthenticated(
        wrappedKey,
        aliceKeyPair.publicKey,
        bobKeyPair
      );

      const decrypted = await decrypt(ciphertext, nonce, unwrappedKey);

      expect(new TextDecoder().decode(decrypted)).toBe('Secret message from Alice to Bob');
    });

    test('Bob verifies file came from Alice', async () => {
      const aliceSeed = await deriveSeed(TEST_MNEMONIC_12);
      const aliceKeyPair = await deriveEncryptionKeyPair(aliceSeed, 0);

      const bobSeed = await deriveSeed(TEST_MNEMONIC_24);
      const bobKeyPair = await deriveEncryptionKeyPair(bobSeed, 0);

      const fileKey = await generateKey();
      const wrappedKey = await wrapKeyAuthenticated(fileKey, bobKeyPair.publicKey, aliceKeyPair);

      expectBytesEqual(wrappedKey.senderPublicKey, aliceKeyPair.publicKey);

      const unwrappedKey = await unwrapKeyAuthenticated(
        wrappedKey,
        aliceKeyPair.publicKey,
        bobKeyPair
      );

      expectBytesEqual(unwrappedKey, fileKey);
    });

    test('Carol cannot unwrap key intended for Bob', async () => {
      const aliceSeed = await deriveSeed(TEST_MNEMONIC_12);
      const aliceKeyPair = await deriveEncryptionKeyPair(aliceSeed, 0);

      const bobSeed = await deriveSeed(TEST_MNEMONIC_24);
      const bobKeyPair = await deriveEncryptionKeyPair(bobSeed, 0);

      const carolKeyPair = await deriveEncryptionKeyPair(aliceSeed, 1);

      const fileKey = await generateKey();
      const wrappedKey = await wrapKeyAuthenticated(fileKey, bobKeyPair.publicKey, aliceKeyPair);

      try {
        await unwrapKeyAuthenticated(wrappedKey, aliceKeyPair.publicKey, carolKeyPair);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
      }
    });

    test('attacker cannot forge sender identity', async () => {
      const aliceSeed = await deriveSeed(TEST_MNEMONIC_12);
      const aliceKeyPair = await deriveEncryptionKeyPair(aliceSeed, 0);

      const bobSeed = await deriveSeed(TEST_MNEMONIC_24);
      const bobKeyPair = await deriveEncryptionKeyPair(bobSeed, 0);

      const eveKeyPair = await deriveEncryptionKeyPair(aliceSeed, 2);

      const fileKey = await generateKey();
      const wrappedKey = await wrapKeyAuthenticated(fileKey, bobKeyPair.publicKey, eveKeyPair);

      try {
        await unwrapKeyAuthenticated(wrappedKey, aliceKeyPair.publicKey, bobKeyPair);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SENDER_MISMATCH);
      }
    });
  });

  describe('multi-recipient sharing', () => {
    test('Alice shares file with Bob, Carol, and Dave', async () => {
      const aliceSeed = await deriveSeed(TEST_MNEMONIC_12);
      const aliceKeyPair = await deriveEncryptionKeyPair(aliceSeed, 0);

      const bobKeyPair = await deriveEncryptionKeyPair(aliceSeed, 1);
      const carolKeyPair = await deriveEncryptionKeyPair(aliceSeed, 2);
      const daveKeyPair = await deriveEncryptionKeyPair(aliceSeed, 3);

      const fileKey = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);
      const { nonce, ciphertext } = await encrypt(plaintext, fileKey);

      const wrappedKeys = await wrapKeyAuthenticatedMulti(
        fileKey,
        [bobKeyPair.publicKey, carolKeyPair.publicKey, daveKeyPair.publicKey],
        aliceKeyPair
      );

      expect(wrappedKeys.length).toBe(3);

      const bobKey = await unwrapKeyAuthenticated(
        wrappedKeys[0]!,
        aliceKeyPair.publicKey,
        bobKeyPair
      );
      const carolKey = await unwrapKeyAuthenticated(
        wrappedKeys[1]!,
        aliceKeyPair.publicKey,
        carolKeyPair
      );
      const daveKey = await unwrapKeyAuthenticated(
        wrappedKeys[2]!,
        aliceKeyPair.publicKey,
        daveKeyPair
      );

      expectBytesEqual(bobKey, fileKey);
      expectBytesEqual(carolKey, fileKey);
      expectBytesEqual(daveKey, fileKey);

      const bobDecrypted = await decrypt(ciphertext, nonce, bobKey);
      expectBytesEqual(bobDecrypted, plaintext);
    });

    test('each recipient can independently decrypt', async () => {
      const aliceSeed = await deriveSeed(TEST_MNEMONIC_12);
      const aliceKeyPair = await deriveEncryptionKeyPair(aliceSeed, 0);

      const recipients = await Promise.all([
        deriveEncryptionKeyPair(aliceSeed, 1),
        deriveEncryptionKeyPair(aliceSeed, 2),
        deriveEncryptionKeyPair(aliceSeed, 3),
      ]);

      const fileKey = await generateKey();
      const plaintext = createTestData(SIZES.MEDIUM);

      const encryptStream = await createEncryptStream(fileKey);
      const header = encryptStream.header;
      const encryptedChunks: Uint8Array[] = [];

      let offset = 0;
      while (offset < plaintext.length) {
        const end = Math.min(offset + CHUNK_SIZE, plaintext.length);
        const chunk = plaintext.subarray(offset, end);
        const isFinal = end === plaintext.length;
        encryptedChunks.push(encryptStream.push(chunk, isFinal));
        offset = end;
      }
      encryptStream.dispose();

      const wrappedKeys = await wrapKeyAuthenticatedMulti(
        fileKey,
        recipients.map((r) => r.publicKey),
        aliceKeyPair
      );

      for (let i = 0; i < recipients.length; i++) {
        const recipientKey = await unwrapKeyAuthenticated(
          wrappedKeys[i]!,
          aliceKeyPair.publicKey,
          recipients[i]!
        );

        const decryptStream = await createDecryptStream(recipientKey, header);
        const decryptedChunks: Uint8Array[] = [];
        for (const encChunk of encryptedChunks) {
          const { plaintext: chunk } = decryptStream.pull(encChunk);
          decryptedChunks.push(chunk);
        }
        decryptStream.dispose();

        const decrypted = concatenate(decryptedChunks);
        expectBytesEqual(decrypted, plaintext);
      }
    });

    test('adding new recipient requires re-wrapping', async () => {
      const aliceSeed = await deriveSeed(TEST_MNEMONIC_12);
      const aliceKeyPair = await deriveEncryptionKeyPair(aliceSeed, 0);

      const bobKeyPair = await deriveEncryptionKeyPair(aliceSeed, 1);
      const newRecipientKeyPair = await deriveEncryptionKeyPair(aliceSeed, 2);

      const fileKey = await generateKey();

      const wrappedKeysV1 = await wrapKeyAuthenticatedMulti(
        fileKey,
        [bobKeyPair.publicKey],
        aliceKeyPair
      );

      const wrappedKeysV2 = await wrapKeyAuthenticatedMulti(
        fileKey,
        [bobKeyPair.publicKey, newRecipientKeyPair.publicKey],
        aliceKeyPair
      );

      expect(wrappedKeysV1.length).toBe(1);
      expect(wrappedKeysV2.length).toBe(2);

      const newRecipientKey = await unwrapKeyAuthenticated(
        wrappedKeysV2[1]!,
        aliceKeyPair.publicKey,
        newRecipientKeyPair
      );
      expectBytesEqual(newRecipientKey, fileKey);
    });
  });

  describe('key hierarchy', () => {
    test('derives consistent encryption keys from mnemonic', async () => {
      const seed1 = await deriveSeed(TEST_MNEMONIC_12);
      const seed2 = await deriveSeed(TEST_MNEMONIC_12);

      const keyPair1 = await deriveEncryptionKeyPair(seed1, 0);
      const keyPair2 = await deriveEncryptionKeyPair(seed2, 0);

      expectBytesEqual(keyPair1.publicKey, keyPair2.publicKey);
      expectBytesEqual(keyPair1.privateKey, keyPair2.privateKey);
    });

    test('derives consistent identity keys from mnemonic', async () => {
      const seed1 = await deriveSeed(TEST_MNEMONIC_12);
      const seed2 = await deriveSeed(TEST_MNEMONIC_12);

      const crustKeyPair1 = await deriveIdentityKeyPair(seed1, CONTEXT_CRUST, 0);
      const crustKeyPair2 = await deriveIdentityKeyPair(seed2, CONTEXT_CRUST, 0);

      expectBytesEqual(crustKeyPair1.publicKey, crustKeyPair2.publicKey);
      expectBytesEqual(crustKeyPair1.privateKey, crustKeyPair2.privateKey);
    });

    test('different indexes produce different keys', async () => {
      const seed = await deriveSeed(TEST_MNEMONIC_12);

      const keyPair0 = await deriveEncryptionKeyPair(seed, 0);
      const keyPair1 = await deriveEncryptionKeyPair(seed, 1);
      const keyPair2 = await deriveEncryptionKeyPair(seed, 2);

      expectBytesNotEqual(keyPair0.publicKey, keyPair1.publicKey);
      expectBytesNotEqual(keyPair1.publicKey, keyPair2.publicKey);
      expectBytesNotEqual(keyPair0.publicKey, keyPair2.publicKey);
    });

    test('different contexts produce different keys', async () => {
      const seed = await deriveSeed(TEST_MNEMONIC_12);

      const crustKeyPair = await deriveIdentityKeyPair(seed, CONTEXT_CRUST, 0);
      const icpKeyPair = await deriveIdentityKeyPair(seed, CONTEXT_ICP, 0);

      expectBytesNotEqual(crustKeyPair.publicKey, icpKeyPair.publicKey);
    });
  });
});

function concatenate(chunks: Uint8Array[]): Uint8Array {
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}
