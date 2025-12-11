import { describe, expect, test } from 'bun:test';
import {
  generateKey,
  createEncryptStream,
  createDecryptStream,
} from '../../src/encryption.ts';
import { hash } from '../../src/hash.ts';
import { asFileId, asSecretstreamHeader } from '../../src/branded.ts';
import { ErrorCode, EncryptionError } from '../../src/errors.ts';
import { createTestData, CHUNK_SIZE, CHUNK_OVERHEAD } from '../helpers/fixtures.ts';
import { expectBytesEqual } from '../helpers/assertions.ts';

describe('security: stream-integrity', () => {
  describe('chunk reordering', () => {
    test('detects swapped chunks', async () => {
      const key = await generateKey();
      const chunks = [
        createTestData(CHUNK_SIZE),
        createTestData(CHUNK_SIZE),
        createTestData(CHUNK_SIZE),
      ];

      const encryptStream = await createEncryptStream(key);
      const header = encryptStream.header;
      const encryptedChunks = chunks.map((chunk, i) =>
        encryptStream.push(chunk, i === chunks.length - 1)
      );
      encryptStream.dispose();

      const swapped = [encryptedChunks[1], encryptedChunks[0], encryptedChunks[2]];

      const decryptStream = await createDecryptStream(key, header);

      try {
        decryptStream.pull(swapped[0]);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
      }
      decryptStream.dispose();
    });

    test('detects reversed chunk order', async () => {
      const key = await generateKey();
      const chunks = [
        createTestData(1000),
        createTestData(1000),
        createTestData(1000),
      ];

      const encryptStream = await createEncryptStream(key);
      const header = encryptStream.header;
      const encryptedChunks = chunks.map((chunk, i) =>
        encryptStream.push(chunk, i === chunks.length - 1)
      );
      encryptStream.dispose();

      const reversed = [...encryptedChunks].reverse();

      const decryptStream = await createDecryptStream(key, header);

      try {
        decryptStream.pull(reversed[0]);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
      }
      decryptStream.dispose();
    });

    test('detects duplicated chunks', async () => {
      const key = await generateKey();
      const plaintext = createTestData(CHUNK_SIZE);

      const encryptStream = await createEncryptStream(key);
      const header = encryptStream.header;
      const chunk1 = encryptStream.push(plaintext, false);
      const chunk2 = encryptStream.push(plaintext, true);
      encryptStream.dispose();

      const decryptStream = await createDecryptStream(key, header);
      decryptStream.pull(chunk1);
      decryptStream.pull(chunk2);

      try {
        decryptStream.pull(chunk1);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
      }
      decryptStream.dispose();
    });

    test('detects chunk from different stream', async () => {
      const key = await generateKey();
      const plaintext = createTestData(CHUNK_SIZE);

      const stream1 = await createEncryptStream(key);
      const header1 = stream1.header;
      const chunk1 = stream1.push(plaintext, true);
      stream1.dispose();

      const stream2 = await createEncryptStream(key);
      const chunk2 = stream2.push(plaintext, true);
      stream2.dispose();

      const decryptStream = await createDecryptStream(key, header1);

      try {
        decryptStream.pull(chunk2);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
      }
      decryptStream.dispose();
    });
  });

  describe('truncation', () => {
    test('detects missing final chunk', async () => {
      const key = await generateKey();
      const chunks = [createTestData(1000), createTestData(1000), createTestData(1000)];

      const encryptStream = await createEncryptStream(key);
      const header = encryptStream.header;
      const encryptedChunks = chunks.map((chunk, i) =>
        encryptStream.push(chunk, i === chunks.length - 1)
      );
      encryptStream.dispose();

      const decryptStream = await createDecryptStream(key, header);

      const { isFinal: isFinal0 } = decryptStream.pull(encryptedChunks[0]);
      expect(isFinal0).toBe(false);

      const { isFinal: isFinal1 } = decryptStream.pull(encryptedChunks[1]);
      expect(isFinal1).toBe(false);

      decryptStream.dispose();
    });

    test('detects stream cut short mid-chunk', async () => {
      const key = await generateKey();
      const plaintext = createTestData(CHUNK_SIZE);

      const encryptStream = await createEncryptStream(key);
      const header = encryptStream.header;
      const encryptedChunk = encryptStream.push(plaintext, true);
      encryptStream.dispose();

      const truncated = encryptedChunk.subarray(0, encryptedChunk.length / 2);

      const decryptStream = await createDecryptStream(key, header);

      try {
        decryptStream.pull(truncated);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
      }
      decryptStream.dispose();
    });

    test('detects missing header data', async () => {
      const key = await generateKey();
      const truncatedHeader = asSecretstreamHeader(new Uint8Array(24));

      const plaintext = createTestData(100);
      const encryptStream = await createEncryptStream(key);
      const encryptedChunk = encryptStream.push(plaintext, true);
      encryptStream.dispose();

      const decryptStream = await createDecryptStream(key, truncatedHeader);

      try {
        decryptStream.pull(encryptedChunk);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
      }
      decryptStream.dispose();
    });

    test('TAG_FINAL required for successful stream completion', async () => {
      const key = await generateKey();
      const plaintext = createTestData(1000);

      const encryptStream = await createEncryptStream(key);
      const header = encryptStream.header;
      const nonFinalChunk = encryptStream.push(plaintext, false);
      const finalChunk = encryptStream.push(plaintext, true);
      encryptStream.dispose();

      const decryptStream = await createDecryptStream(key, header);

      const { isFinal: isFinal1 } = decryptStream.pull(nonFinalChunk);
      expect(isFinal1).toBe(false);

      const { isFinal: isFinal2 } = decryptStream.pull(finalChunk);
      expect(isFinal2).toBe(true);

      decryptStream.dispose();
    });

    test('finalize() succeeds when TAG_FINAL received', async () => {
      const key = await generateKey();
      const plaintext = createTestData(1000);

      const encryptStream = await createEncryptStream(key);
      const header = encryptStream.header;
      const chunk = encryptStream.push(plaintext, true);
      encryptStream.dispose();

      const decryptStream = await createDecryptStream(key, header);
      decryptStream.pull(chunk);
      decryptStream.finalize();
      decryptStream.dispose();
    });

    test('finalize() throws STREAM_TRUNCATED when no TAG_FINAL received', async () => {
      const key = await generateKey();
      const plaintext = createTestData(1000);

      const encryptStream = await createEncryptStream(key);
      const header = encryptStream.header;
      const nonFinalChunk = encryptStream.push(plaintext, false);
      encryptStream.push(plaintext, true);
      encryptStream.dispose();

      const decryptStream = await createDecryptStream(key, header);
      decryptStream.pull(nonFinalChunk);

      try {
        decryptStream.finalize();
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.STREAM_TRUNCATED);
      }
      decryptStream.dispose();
    });

    test('finalize() throws STREAM_TRUNCATED when called before any chunks', async () => {
      const key = await generateKey();

      const encryptStream = await createEncryptStream(key);
      const header = encryptStream.header;
      encryptStream.push(createTestData(100), true);
      encryptStream.dispose();

      const decryptStream = await createDecryptStream(key, header);

      try {
        decryptStream.finalize();
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.STREAM_TRUNCATED);
      }
      decryptStream.dispose();
    });
  });

  describe('modification', () => {
    test('detects single bit flip in ciphertext', async () => {
      const key = await generateKey();
      const plaintext = createTestData(CHUNK_SIZE);

      const encryptStream = await createEncryptStream(key);
      const header = encryptStream.header;
      const encryptedChunk = encryptStream.push(plaintext, true);
      encryptStream.dispose();

      const modified = new Uint8Array(encryptedChunk);
      modified[Math.floor(modified.length / 2)] ^= 0x01;

      const decryptStream = await createDecryptStream(key, header);

      try {
        decryptStream.pull(modified);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
      }
      decryptStream.dispose();
    });

    test('detects single bit flip in auth tag', async () => {
      const key = await generateKey();
      const plaintext = createTestData(100);

      const encryptStream = await createEncryptStream(key);
      const header = encryptStream.header;
      const encryptedChunk = encryptStream.push(plaintext, true);
      encryptStream.dispose();

      const modified = new Uint8Array(encryptedChunk);
      modified[modified.length - 1] ^= 0x01;

      const decryptStream = await createDecryptStream(key, header);

      try {
        decryptStream.pull(modified);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
      }
      decryptStream.dispose();
    });

    test('detects single bit flip in header', async () => {
      const key = await generateKey();
      const plaintext = createTestData(100);

      const encryptStream = await createEncryptStream(key);
      const originalHeader = new Uint8Array(encryptStream.header);
      const encryptedChunk = encryptStream.push(plaintext, true);
      encryptStream.dispose();

      const modifiedHeader = new Uint8Array(originalHeader);
      modifiedHeader[12] ^= 0x01;

      const decryptStream = await createDecryptStream(
        key,
        asSecretstreamHeader(modifiedHeader)
      );

      try {
        decryptStream.pull(encryptedChunk);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
      }
      decryptStream.dispose();
    });

    test('detects chunk length modification', async () => {
      const key = await generateKey();
      const plaintext = createTestData(100);

      const encryptStream = await createEncryptStream(key);
      const header = encryptStream.header;
      const encryptedChunk = encryptStream.push(plaintext, true);
      encryptStream.dispose();

      const extended = new Uint8Array(encryptedChunk.length + 10);
      extended.set(encryptedChunk);

      const decryptStream = await createDecryptStream(key, header);

      try {
        decryptStream.pull(extended);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
      }
      decryptStream.dispose();
    });
  });

  describe('insertion', () => {
    test('detects extra chunks inserted', async () => {
      const key = await generateKey();
      const plaintext = createTestData(1000);

      const encryptStream = await createEncryptStream(key);
      const header = encryptStream.header;
      const chunk1 = encryptStream.push(plaintext, false);
      const chunk2 = encryptStream.push(plaintext, true);
      encryptStream.dispose();

      const decryptStream = await createDecryptStream(key, header);
      decryptStream.pull(chunk1);
      decryptStream.pull(chunk2);

      const fakeChunk = new Uint8Array(1000 + CHUNK_OVERHEAD);

      try {
        decryptStream.pull(fakeChunk);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
      }
      decryptStream.dispose();
    });

    test('detects padding added to chunks', async () => {
      const key = await generateKey();
      const plaintext = createTestData(100);

      const encryptStream = await createEncryptStream(key);
      const header = encryptStream.header;
      const encryptedChunk = encryptStream.push(plaintext, true);
      encryptStream.dispose();

      const paddedChunk = new Uint8Array(encryptedChunk.length + 50);
      paddedChunk.set(encryptedChunk);

      const decryptStream = await createDecryptStream(key, header);

      try {
        decryptStream.pull(paddedChunk);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
      }
      decryptStream.dispose();
    });
  });

  describe('replay', () => {
    test('old stream cannot be replayed with new fileId', async () => {
      const key = await generateKey();
      const plaintext = createTestData(1000);
      const fileId1 = asFileId(await hash(new TextEncoder().encode('file1')));
      const fileId2 = asFileId(await hash(new TextEncoder().encode('file2')));

      const encryptStream = await createEncryptStream(key, fileId1);
      const header = encryptStream.header;
      const encryptedChunk = encryptStream.push(plaintext, true);
      encryptStream.dispose();

      const decryptStream = await createDecryptStream(key, header, fileId2);

      try {
        decryptStream.pull(encryptedChunk);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
      }
      decryptStream.dispose();
    });

    test('stream with correct fileId succeeds', async () => {
      const key = await generateKey();
      const plaintext = createTestData(1000);
      const fileId = asFileId(await hash(new TextEncoder().encode('file')));

      const encryptStream = await createEncryptStream(key, fileId);
      const header = encryptStream.header;
      const encryptedChunk = encryptStream.push(plaintext, true);
      encryptStream.dispose();

      const decryptStream = await createDecryptStream(key, header, fileId);
      const { plaintext: decrypted, isFinal } = decryptStream.pull(encryptedChunk);

      expectBytesEqual(decrypted, plaintext);
      expect(isFinal).toBe(true);
      decryptStream.dispose();
    });
  });
});
