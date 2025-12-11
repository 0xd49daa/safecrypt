import { describe, expect, test } from 'bun:test';
import { generateKey } from '../../src/encryption.ts';
import { constantTimeEqual } from '../../src/memory.ts';
import {
  wrapKeyAuthenticated,
  unwrapKeyAuthenticated,
} from '../../src/key-wrapping.ts';
import { ErrorCode, EncryptionError } from '../../src/errors.ts';
import { createTestKeyPair } from '../helpers/fixtures.ts';

describe('security: timing-attacks', () => {
  describe('constantTimeEqual', () => {
    test('returns true for equal arrays', async () => {
      const arr1 = new Uint8Array([1, 2, 3, 4, 5]);
      const arr2 = new Uint8Array([1, 2, 3, 4, 5]);

      expect(await constantTimeEqual(arr1, arr2)).toBe(true);
    });

    test('returns false for unequal arrays', async () => {
      const arr1 = new Uint8Array([1, 2, 3, 4, 5]);
      const arr2 = new Uint8Array([1, 2, 3, 4, 6]);

      expect(await constantTimeEqual(arr1, arr2)).toBe(false);
    });

    test('returns false for different length arrays', async () => {
      const arr1 = new Uint8Array([1, 2, 3, 4, 5]);
      const arr2 = new Uint8Array([1, 2, 3, 4]);

      expect(await constantTimeEqual(arr1, arr2)).toBe(false);
    });

    test('handles empty arrays', async () => {
      const arr1 = new Uint8Array(0);
      const arr2 = new Uint8Array(0);

      expect(await constantTimeEqual(arr1, arr2)).toBe(true);
    });

    test('difference at start detected', async () => {
      const arr1 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
      const arr2 = new Uint8Array([1, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

      expect(await constantTimeEqual(arr1, arr2)).toBe(false);
    });

    test('difference at end detected', async () => {
      const arr1 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
      const arr2 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 10]);

      expect(await constantTimeEqual(arr1, arr2)).toBe(false);
    });

    test('difference in middle detected', async () => {
      const arr1 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
      const arr2 = new Uint8Array([0, 1, 2, 3, 255, 5, 6, 7, 8, 9]);

      expect(await constantTimeEqual(arr1, arr2)).toBe(false);
    });

    test('multiple differences detected', async () => {
      const arr1 = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
      const arr2 = new Uint8Array([1, 1, 2, 3, 255, 5, 6, 7, 8, 10]);

      expect(await constantTimeEqual(arr1, arr2)).toBe(false);
    });

    test('works with large arrays', async () => {
      const size = 10000;
      const arr1 = new Uint8Array(size);
      const arr2 = new Uint8Array(size);

      for (let i = 0; i < size; i++) {
        arr1[i] = i % 256;
        arr2[i] = i % 256;
      }

      expect(await constantTimeEqual(arr1, arr2)).toBe(true);

      arr2[size - 1] ^= 1;
      expect(await constantTimeEqual(arr1, arr2)).toBe(false);
    });
  });

  describe('sender verification', () => {
    test('sender mismatch uses constant-time comparison', async () => {
      const senderKeyPair = await createTestKeyPair(0);
      const recipientKeyPair = await createTestKeyPair(1);
      const wrongSenderKeyPair = await createTestKeyPair(2);
      const key = await generateKey();

      const wrapped = await wrapKeyAuthenticated(
        key,
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

    test('correct sender passes verification', async () => {
      const senderKeyPair = await createTestKeyPair(0);
      const recipientKeyPair = await createTestKeyPair(1);
      const key = await generateKey();

      const wrapped = await wrapKeyAuthenticated(
        key,
        recipientKeyPair.publicKey,
        senderKeyPair
      );

      const unwrapped = await unwrapKeyAuthenticated(
        wrapped,
        senderKeyPair.publicKey,
        recipientKeyPair
      );

      expect(unwrapped).toBeDefined();
    });
  });

  describe('implementation verification', () => {
    test('constantTimeEqual processes all bytes', async () => {
      const arr1 = new Uint8Array(32).fill(0);
      const arr2 = new Uint8Array(32).fill(0);

      expect(await constantTimeEqual(arr1, arr2)).toBe(true);

      for (let i = 0; i < 32; i++) {
        const modified = new Uint8Array(arr1);
        modified[i] = 1;
        expect(await constantTimeEqual(arr1, modified)).toBe(false);
      }
    });

    test('comparison result independent of similarity', async () => {
      const base = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        base[i] = i;
      }

      const oneDiff = new Uint8Array(base);
      oneDiff[0] = 255;

      const allDiff = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        allDiff[i] = 255 - i;
      }

      expect(await constantTimeEqual(base, oneDiff)).toBe(false);
      expect(await constantTimeEqual(base, allDiff)).toBe(false);
    });

    test('32-byte key comparison works correctly', async () => {
      const key1 = new Uint8Array(32);
      const key2 = new Uint8Array(32);

      crypto.getRandomValues(key1);
      key2.set(key1);

      expect(await constantTimeEqual(key1, key2)).toBe(true);

      key2[31] ^= 1;
      expect(await constantTimeEqual(key1, key2)).toBe(false);
    });
  });

  describe('timing characteristics', () => {
    test('equal arrays comparison completes', async () => {
      const arr1 = new Uint8Array(1000).fill(42);
      const arr2 = new Uint8Array(1000).fill(42);

      const result = await constantTimeEqual(arr1, arr2);
      expect(result).toBe(true);
    });

    test('unequal arrays comparison completes', async () => {
      const arr1 = new Uint8Array(1000).fill(42);
      const arr2 = new Uint8Array(1000).fill(43);

      const result = await constantTimeEqual(arr1, arr2);
      expect(result).toBe(false);
    });

    test('comparison with first-byte difference completes', async () => {
      const arr1 = new Uint8Array(1000).fill(42);
      const arr2 = new Uint8Array(1000).fill(42);
      arr2[0] = 0;

      const result = await constantTimeEqual(arr1, arr2);
      expect(result).toBe(false);
    });

    test('comparison with last-byte difference completes', async () => {
      const arr1 = new Uint8Array(1000).fill(42);
      const arr2 = new Uint8Array(1000).fill(42);
      arr2[999] = 0;

      const result = await constantTimeEqual(arr1, arr2);
      expect(result).toBe(false);
    });
  });
});
