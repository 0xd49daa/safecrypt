import { describe, expect, test } from 'bun:test';
import {
  generateKey,
  encrypt,
  decrypt,
  createEncryptStream,
  createDecryptStream,
} from '../../src/encryption.ts';
import { hash } from '../../src/hash.ts';
import { asFileId } from '../../src/branded.ts';
import { ErrorCode, EncryptionError } from '../../src/errors.ts';
import {
  createTestData,
  createRandomData,
  SIZES,
  CHUNK_SIZE,
  CHUNK_OVERHEAD,
} from '../helpers/fixtures.ts';
import { expectBytesEqual } from '../helpers/assertions.ts';

describe('integration: file-encryption', () => {
  describe('single-shot encryption', () => {
    test('encrypts and decrypts small file (<64KB)', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);

      const { nonce, ciphertext } = await encrypt(plaintext, key);
      const decrypted = await decrypt(ciphertext, nonce, key);

      expectBytesEqual(decrypted, plaintext);
    });

    test('works with empty file', async () => {
      const key = await generateKey();
      const plaintext = new Uint8Array(0);

      const { nonce, ciphertext } = await encrypt(plaintext, key);
      const decrypted = await decrypt(ciphertext, nonce, key);

      expect(decrypted.length).toBe(0);
    });

    test('works with maximum single-shot size (64KB)', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.MEDIUM);

      const { nonce, ciphertext } = await encrypt(plaintext, key);
      const decrypted = await decrypt(ciphertext, nonce, key);

      expectBytesEqual(decrypted, plaintext);
    });

    test('preserves exact file content after round-trip', async () => {
      const key = await generateKey();
      const plaintext = createRandomData(SIZES.SMALL);
      const originalHash = await hash(plaintext);

      const { nonce, ciphertext } = await encrypt(plaintext, key);
      const decrypted = await decrypt(ciphertext, nonce, key);
      const decryptedHash = await hash(decrypted);

      expectBytesEqual(decryptedHash, originalHash);
    });
  });

  describe('streaming encryption', () => {
    test('encrypts and decrypts large file (1MB)', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.LARGE);
      const originalHash = await hash(plaintext);

      const encryptStream = await createEncryptStream(key);
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

      const decryptStream = await createDecryptStream(key, header);
      const decryptedChunks: Uint8Array[] = [];
      for (const encChunk of encryptedChunks) {
        const { plaintext: chunk } = decryptStream.pull(encChunk);
        decryptedChunks.push(chunk);
      }
      decryptStream.dispose();

      const decrypted = concatenate(decryptedChunks);
      const decryptedHash = await hash(decrypted);

      expectBytesEqual(decryptedHash, originalHash);
      expect(decrypted.length).toBe(SIZES.LARGE);
    });

    test('handles chunk boundaries correctly', async () => {
      const key = await generateKey();
      const plaintext = createTestData(CHUNK_SIZE * 3 + 123);

      const encryptStream = await createEncryptStream(key);
      const header = encryptStream.header;
      const encryptedChunks: Uint8Array[] = [];

      let offset = 0;
      let chunkCount = 0;
      while (offset < plaintext.length) {
        const end = Math.min(offset + CHUNK_SIZE, plaintext.length);
        const chunk = plaintext.subarray(offset, end);
        const isFinal = end === plaintext.length;
        encryptedChunks.push(encryptStream.push(chunk, isFinal));
        offset = end;
        chunkCount++;
      }
      encryptStream.dispose();

      expect(chunkCount).toBe(4);

      const decryptStream = await createDecryptStream(key, header);
      const decryptedChunks: Uint8Array[] = [];
      for (const encChunk of encryptedChunks) {
        const { plaintext: chunk } = decryptStream.pull(encChunk);
        decryptedChunks.push(chunk);
      }
      decryptStream.dispose();

      const decrypted = concatenate(decryptedChunks);
      expectBytesEqual(decrypted, plaintext);
    });

    test('streaming output has correct overhead', async () => {
      const key = await generateKey();
      const chunkSize = 1000;
      const chunk = createTestData(chunkSize);

      const encryptStream = await createEncryptStream(key);
      const encryptedChunk = encryptStream.push(chunk, true);
      encryptStream.dispose();

      expect(encryptedChunk.length).toBe(chunkSize + CHUNK_OVERHEAD);
    });
  });

  describe('file-to-file pipeline', () => {
    test('stages file → encrypt → hash → store CID', async () => {
      const key = await generateKey();
      const plaintext = createRandomData(SIZES.MEDIUM);

      const fileId = asFileId(await hash(plaintext));

      const encryptStream = await createEncryptStream(key, fileId);
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

      const encrypted = concatenate(encryptedChunks);
      const cid = await hash(encrypted);

      expect(cid.length).toBe(32);
      expect(header.length).toBe(24);

      const decryptStream = await createDecryptStream(key, header, fileId);
      const decryptedChunks: Uint8Array[] = [];
      let decOffset = 0;
      while (decOffset < encrypted.length) {
        const chunkEnd = Math.min(decOffset + CHUNK_SIZE + CHUNK_OVERHEAD, encrypted.length);
        const encChunk = encrypted.subarray(decOffset, chunkEnd);
        const { plaintext: chunk } = decryptStream.pull(encChunk);
        decryptedChunks.push(chunk);
        decOffset = chunkEnd;
      }
      decryptStream.dispose();

      const decrypted = concatenate(decryptedChunks);
      expectBytesEqual(decrypted, plaintext);
    });

    test('handles binary files (images, PDFs)', async () => {
      const key = await generateKey();
      const binaryData = new Uint8Array([
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
        ...Array.from({ length: 1000 }, () => Math.floor(Math.random() * 256)),
      ]);

      const { nonce, ciphertext } = await encrypt(binaryData, key);
      const decrypted = await decrypt(ciphertext, nonce, key);

      expectBytesEqual(decrypted, binaryData);
    });

    test('handles text files with various encodings', async () => {
      const key = await generateKey();
      const textContent = 'Hello, 世界! 🌍 Привет مرحبا';
      const plaintext = new TextEncoder().encode(textContent);

      const { nonce, ciphertext } = await encrypt(plaintext, key);
      const decrypted = await decrypt(ciphertext, nonce, key);

      expect(new TextDecoder().decode(decrypted)).toBe(textContent);
    });
  });

  describe('error scenarios', () => {
    test('rejects corrupted encrypted data', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);

      const { nonce, ciphertext } = await encrypt(plaintext, key);
      const idx = Math.floor(ciphertext.length / 2);
      ciphertext[idx] = ciphertext[idx]! ^ 0xff;

      try {
        await decrypt(ciphertext, nonce, key);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
      }
    });

    test('rejects truncated stream', async () => {
      const key = await generateKey();
      const plaintext = createTestData(CHUNK_SIZE * 3);

      const encryptStream = await createEncryptStream(key);
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

      const decryptStream = await createDecryptStream(key, header);
      decryptStream.pull(encryptedChunks[0]!);

      const truncatedChunk = encryptedChunks[1]!.subarray(0, 10);

      try {
        decryptStream.pull(truncatedChunk);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
      }
      decryptStream.dispose();
    });

    test('rejects wrong key', async () => {
      const key1 = await generateKey();
      const key2 = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);

      const { nonce, ciphertext } = await encrypt(plaintext, key1);

      try {
        await decrypt(ciphertext, nonce, key2);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
      }
    });

    test('provides meaningful error messages', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);

      const { nonce, ciphertext } = await encrypt(plaintext, key);
      ciphertext[0] = ciphertext[0]! ^ 0xff;

      try {
        await decrypt(ciphertext, nonce, key);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        const encError = error as EncryptionError;
        expect(encError.message).toContain('Decryption failed');
        expect(encError.code).toBe(ErrorCode.DECRYPTION_FAILED);
      }
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
