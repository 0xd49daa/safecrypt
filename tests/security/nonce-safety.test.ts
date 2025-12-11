import { describe, expect, test } from 'bun:test';
import {
  generateKey,
  encrypt,
  createEncryptStream,
} from '../../src/encryption.ts';
import {
  wrapKeyAuthenticated,
  wrapKeyAuthenticatedMulti,
  wrapKeySeal,
} from '../../src/key-wrapping.ts';
import { toHex } from '../../src/bytes.ts';
import { createTestKeyPair, createTestData, SIZES } from '../helpers/fixtures.ts';
import { expectUniqueArrays, expectUniqueNonces } from '../helpers/assertions.ts';

describe('security: nonce-safety', () => {
  describe('single-shot encryption', () => {
    test('generates unique nonce for each encryption', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);

      const { nonce: nonce1 } = await encrypt(plaintext, key);
      const { nonce: nonce2 } = await encrypt(plaintext, key);

      expect(toHex(nonce1)).not.toBe(toHex(nonce2));
    });

    test('10000 encryptions produce 10000 unique nonces', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.TINY);
      const nonces = new Set<string>();

      for (let i = 0; i < 10000; i++) {
        const { nonce } = await encrypt(plaintext, key);
        nonces.add(toHex(nonce));
      }

      expect(nonces.size).toBe(10000);
    });

    test('nonces are cryptographically random', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.TINY);
      const nonces: Uint8Array[] = [];

      for (let i = 0; i < 100; i++) {
        const { nonce } = await encrypt(plaintext, key);
        nonces.push(nonce);
      }

      for (const nonce of nonces) {
        expect(nonce.length).toBe(24);
        expect(nonce.some((b) => b !== 0)).toBe(true);
        expect(nonce.some((b) => b !== 0xff)).toBe(true);
      }

      expectUniqueNonces(nonces);
    });

    test('nonce length is exactly 24 bytes', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);

      for (let i = 0; i < 100; i++) {
        const { nonce } = await encrypt(plaintext, key);
        expect(nonce.length).toBe(24);
      }
    });
  });

  describe('streaming encryption', () => {
    test('each stream has unique header', async () => {
      const key = await generateKey();
      const headers: Uint8Array[] = [];

      for (let i = 0; i < 100; i++) {
        const stream = await createEncryptStream(key);
        headers.push(stream.header);
        stream.dispose();
      }

      expectUniqueArrays(headers);
    });

    test('new stream with same key has different header', async () => {
      const key = await generateKey();

      const stream1 = await createEncryptStream(key);
      const header1 = new Uint8Array(stream1.header);
      stream1.dispose();

      const stream2 = await createEncryptStream(key);
      const header2 = new Uint8Array(stream2.header);
      stream2.dispose();

      expect(toHex(header1)).not.toBe(toHex(header2));
    });

    test('header is 24 bytes (contains nonce state)', async () => {
      const key = await generateKey();
      const stream = await createEncryptStream(key);

      expect(stream.header.length).toBe(24);
      stream.dispose();
    });
  });

  describe('key wrapping', () => {
    test('authenticated wrapping uses unique nonce per call', async () => {
      const senderKeyPair = await createTestKeyPair(0);
      const recipientKeyPair = await createTestKeyPair(1);
      const key = await generateKey();
      const nonces: Uint8Array[] = [];

      for (let i = 0; i < 100; i++) {
        const wrapped = await wrapKeyAuthenticated(
          key,
          recipientKeyPair.publicKey,
          senderKeyPair
        );
        nonces.push(wrapped.nonce);
      }

      expectUniqueNonces(nonces);
    });

    test('multi-recipient uses unique nonce per recipient', async () => {
      const senderKeyPair = await createTestKeyPair(0);
      const recipients = await Promise.all([
        createTestKeyPair(1),
        createTestKeyPair(2),
        createTestKeyPair(3),
        createTestKeyPair(4),
        createTestKeyPair(5),
      ]);
      const key = await generateKey();

      const wrappedKeys = await wrapKeyAuthenticatedMulti(
        key,
        recipients.map((r) => r.publicKey),
        senderKeyPair
      );

      const nonces = wrappedKeys.map((w) => w.nonce);
      expectUniqueNonces(nonces);
    });

    test('sealed box uses ephemeral keypair (implicit nonce safety)', async () => {
      const recipientKeyPair = await createTestKeyPair(0);
      const key = await generateKey();
      const sealedBoxes: Uint8Array[] = [];

      for (let i = 0; i < 100; i++) {
        const sealed = await wrapKeySeal(key, recipientKeyPair.publicKey);
        sealedBoxes.push(sealed);
      }

      expectUniqueArrays(sealedBoxes);
    });
  });

  describe('statistical tests', () => {
    test('nonce byte distribution is approximately uniform', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.TINY);
      const byteCounts = new Array(256).fill(0);

      for (let i = 0; i < 1000; i++) {
        const { nonce } = await encrypt(plaintext, key);
        for (const byte of nonce) {
          byteCounts[byte]++;
        }
      }

      const totalBytes = 1000 * 24;
      const expectedCount = totalBytes / 256;
      const tolerance = expectedCount * 0.5;

      let outliers = 0;
      for (let i = 0; i < 256; i++) {
        if (Math.abs(byteCounts[i] - expectedCount) > tolerance) {
          outliers++;
        }
      }

      expect(outliers).toBeLessThan(10);
    });

    test('no detectable patterns in nonce sequence', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.TINY);
      const nonces: Uint8Array[] = [];

      for (let i = 0; i < 100; i++) {
        const { nonce } = await encrypt(plaintext, key);
        nonces.push(nonce);
      }

      for (let i = 1; i < nonces.length; i++) {
        const prev = nonces[i - 1];
        const curr = nonces[i];

        let matchingBytes = 0;
        for (let j = 0; j < 24; j++) {
          if (prev[j] === curr[j]) matchingBytes++;
        }

        expect(matchingBytes).toBeLessThan(12);
      }
    });

    test('first bytes of nonces are well distributed', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.TINY);
      const firstBytes = new Set<number>();

      for (let i = 0; i < 256; i++) {
        const { nonce } = await encrypt(plaintext, key);
        firstBytes.add(nonce[0]);
      }

      expect(firstBytes.size).toBeGreaterThan(100);
    });
  });
});
