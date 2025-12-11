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
import { createTestData, SIZES, CHUNK_SIZE } from '../helpers/fixtures.ts';
import { expectBytesEqual } from '../helpers/assertions.ts';

describe('security: context-commitment', () => {
  describe('single-shot context binding', () => {
    test('decryption fails with wrong context', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);
      const contextA = new TextEncoder().encode('context-a');
      const contextB = new TextEncoder().encode('context-b');

      const { nonce, ciphertext } = await encrypt(plaintext, key, contextA);

      try {
        await decrypt(ciphertext, nonce, key, contextB);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
      }
    });

    test('decryption fails with missing context', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);
      const context = new TextEncoder().encode('required-context');

      const { nonce, ciphertext } = await encrypt(plaintext, key, context);

      try {
        await decrypt(ciphertext, nonce, key);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
      }
    });

    test('decryption fails with extra context', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);

      const { nonce, ciphertext } = await encrypt(plaintext, key);
      const unexpectedContext = new TextEncoder().encode('unexpected');

      try {
        await decrypt(ciphertext, nonce, key, unexpectedContext);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
      }
    });

    test('empty context differs from no context', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);
      const emptyContext = new Uint8Array(0);

      const { nonce: nonce1, ciphertext: ciphertext1 } = await encrypt(plaintext, key);
      const { nonce: nonce2, ciphertext: ciphertext2 } = await encrypt(plaintext, key, emptyContext);

      const decrypted1 = await decrypt(ciphertext1, nonce1, key);
      const decrypted2 = await decrypt(ciphertext2, nonce2, key, emptyContext);

      expectBytesEqual(decrypted1, plaintext);
      expectBytesEqual(decrypted2, plaintext);
    });

    test('context binding is cryptographically enforced', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);
      const context1 = new TextEncoder().encode('manifest');
      const context2 = new TextEncoder().encode('manifest-v2');

      const { nonce, ciphertext } = await encrypt(plaintext, key, context1);

      try {
        await decrypt(ciphertext, nonce, key, context2);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
      }
    });
  });

  describe('streaming fileId binding', () => {
    test('decryption fails with wrong fileId', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.MEDIUM);
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

    test('decryption fails with missing fileId', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);
      const fileId = asFileId(await hash(new TextEncoder().encode('file')));

      const encryptStream = await createEncryptStream(key, fileId);
      const header = encryptStream.header;
      const encryptedChunk = encryptStream.push(plaintext, true);
      encryptStream.dispose();

      const decryptStream = await createDecryptStream(key, header);

      try {
        decryptStream.pull(encryptedChunk);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
      }
      decryptStream.dispose();
    });

    test('chunks from different files cannot be mixed', async () => {
      const key = await generateKey();
      const plaintext1 = createTestData(CHUNK_SIZE);
      const plaintext2 = createTestData(CHUNK_SIZE);
      const fileId1 = asFileId(await hash(new TextEncoder().encode('file1')));
      const fileId2 = asFileId(await hash(new TextEncoder().encode('file2')));

      const stream1 = await createEncryptStream(key, fileId1);
      const header1 = stream1.header;
      const chunk1 = stream1.push(plaintext1, true);
      stream1.dispose();

      const stream2 = await createEncryptStream(key, fileId2);
      stream2.push(plaintext2, true);
      stream2.dispose();

      const decryptStream = await createDecryptStream(key, header1, fileId1);

      const { plaintext: decrypted } = decryptStream.pull(chunk1);
      expectBytesEqual(decrypted, plaintext1);
      decryptStream.dispose();
    });
  });

  describe('cross-context attacks', () => {
    test('ciphertext from context A fails in context B', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);
      const contextA = new TextEncoder().encode('type-A');
      const contextB = new TextEncoder().encode('type-B');

      const { nonce, ciphertext } = await encrypt(plaintext, key, contextA);

      const decryptedA = await decrypt(ciphertext, nonce, key, contextA);
      expectBytesEqual(decryptedA, plaintext);

      try {
        await decrypt(ciphertext, nonce, key, contextB);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
      }
    });

    test('manifest ciphertext cannot decrypt as file', async () => {
      const key = await generateKey();
      const manifestData = new TextEncoder().encode('{"files":[]}');
      const manifestContext = new TextEncoder().encode('manifest');
      const fileContext = new TextEncoder().encode('file');

      const { nonce, ciphertext } = await encrypt(manifestData, key, manifestContext);

      try {
        await decrypt(ciphertext, nonce, key, fileContext);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
      }
    });

    test('file ciphertext cannot decrypt as manifest', async () => {
      const key = await generateKey();
      const fileData = createTestData(SIZES.SMALL);
      const fileContext = new TextEncoder().encode('file');
      const manifestContext = new TextEncoder().encode('manifest');

      const { nonce, ciphertext } = await encrypt(fileData, key, fileContext);

      try {
        await decrypt(ciphertext, nonce, key, manifestContext);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
        expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
      }
    });

    test('similar contexts are still distinguished', async () => {
      const key = await generateKey();
      const plaintext = createTestData(SIZES.SMALL);
      const context1 = new TextEncoder().encode('context');
      const context2 = new TextEncoder().encode('context1');
      const context3 = new TextEncoder().encode('Context');

      const { nonce, ciphertext } = await encrypt(plaintext, key, context1);

      try {
        await decrypt(ciphertext, nonce, key, context2);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
      }

      try {
        await decrypt(ciphertext, nonce, key, context3);
        expect(true).toBe(false);
      } catch (error) {
        expect(error).toBeInstanceOf(EncryptionError);
      }
    });
  });
});
