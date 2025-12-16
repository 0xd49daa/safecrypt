import { describe, expect, test } from 'bun:test';
import {
  generateKey,
  encrypt,
  decrypt,
  createEncryptStream,
  createDecryptStream,
} from '../src/encryption.ts';
import { asSymmetricKey, asNonce, asSecretstreamHeader, asFileId } from '../src/branded.ts';
import { toHex } from '../src/bytes.ts';
import { hash } from '../src/hash.ts';
import { ErrorCode, EncryptionError } from '../src/errors.ts';

describe('generateKey', () => {
  test('returns 32-byte SymmetricKey', async () => {
    const key = await generateKey();
    expect(key.length).toBe(32);
  });

  test('generates unique keys on each call', async () => {
    const key1 = await generateKey();
    const key2 = await generateKey();
    expect(toHex(key1)).not.toBe(toHex(key2));
  });

  test('keys are cryptographically random', async () => {
    const keys = await Promise.all(Array.from({ length: 100 }, () => generateKey()));
    const hexKeys = keys.map((k) => toHex(k));
    const uniqueKeys = new Set(hexKeys);
    expect(uniqueKeys.size).toBe(100);
  });
});

describe('encrypt/decrypt', () => {
  test('round-trips plaintext correctly', async () => {
    const key = await generateKey();
    const plaintext = new TextEncoder().encode('Hello, World!');

    const { nonce, ciphertext } = await encrypt(plaintext, key);
    const decrypted = await decrypt(ciphertext, nonce, key);

    expect(new TextDecoder().decode(decrypted)).toBe('Hello, World!');
  });

  test('handles empty plaintext', async () => {
    const key = await generateKey();
    const plaintext = new Uint8Array(0);

    const { nonce, ciphertext } = await encrypt(plaintext, key);
    const decrypted = await decrypt(ciphertext, nonce, key);

    expect(decrypted.length).toBe(0);
  });

  test('handles large plaintext', async () => {
    const key = await generateKey();
    const plaintext = new Uint8Array(1_000_000).fill(0x42);

    const { nonce, ciphertext } = await encrypt(plaintext, key);
    const decrypted = await decrypt(ciphertext, nonce, key);

    expect(decrypted.length).toBe(1_000_000);
    expect(decrypted.every((b) => b === 0x42)).toBe(true);
  });

  test('ciphertext is longer than plaintext by 16 bytes (auth tag)', async () => {
    const key = await generateKey();
    const plaintext = new TextEncoder().encode('test');

    const { ciphertext } = await encrypt(plaintext, key);
    expect(ciphertext.length).toBe(plaintext.length + 16);
  });

  test('nonce is 24 bytes', async () => {
    const key = await generateKey();
    const plaintext = new TextEncoder().encode('test');

    const { nonce } = await encrypt(plaintext, key);
    expect(nonce.length).toBe(24);
  });

  test('includes context in authentication', async () => {
    const key = await generateKey();
    const plaintext = new TextEncoder().encode('secret');
    const context = new TextEncoder().encode('manifest');

    const { nonce, ciphertext } = await encrypt(plaintext, key, context);
    const decrypted = await decrypt(ciphertext, nonce, key, context);

    expect(new TextDecoder().decode(decrypted)).toBe('secret');
  });

  test('different context fails decryption', async () => {
    const key = await generateKey();
    const plaintext = new TextEncoder().encode('secret');
    const context1 = new TextEncoder().encode('manifest');
    const context2 = new TextEncoder().encode('chunk');

    const { nonce, ciphertext } = await encrypt(plaintext, key, context1);

    try {
      await decrypt(ciphertext, nonce, key, context2);
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
    }
  });

  test('wrong key fails with DECRYPTION_FAILED', async () => {
    const key1 = await generateKey();
    const key2 = await generateKey();
    const plaintext = new TextEncoder().encode('secret');

    const { nonce, ciphertext } = await encrypt(plaintext, key1);

    try {
      await decrypt(ciphertext, nonce, key2);
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
    }
  });

  test('wrong nonce fails with DECRYPTION_FAILED', async () => {
    const key = await generateKey();
    const plaintext = new TextEncoder().encode('secret');

    const { ciphertext } = await encrypt(plaintext, key);
    const wrongNonce = asNonce(new Uint8Array(24).fill(0));

    try {
      await decrypt(ciphertext, wrongNonce, key);
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
    }
  });

  test('tampered ciphertext fails with DECRYPTION_FAILED', async () => {
    const key = await generateKey();
    const plaintext = new TextEncoder().encode('secret');

    const { nonce, ciphertext } = await encrypt(plaintext, key);
    ciphertext[0] = ciphertext[0]! ^ 0xff;

    try {
      await decrypt(ciphertext, nonce, key);
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
    }
  });

  test('generates unique nonce per encryption', async () => {
    const key = await generateKey();
    const plaintext = new TextEncoder().encode('test');

    const results = await Promise.all(Array.from({ length: 100 }, () => encrypt(plaintext, key)));

    const nonces = results.map((r) => toHex(r.nonce));
    const uniqueNonces = new Set(nonces);
    expect(uniqueNonces.size).toBe(100);
  });
});

describe('createEncryptStream/createDecryptStream', () => {
  test('round-trips single chunk', async () => {
    const key = await generateKey();
    const chunk = new TextEncoder().encode('Hello, streaming world!');

    const encryptStream = await createEncryptStream(key);
    const header = encryptStream.header;
    const encryptedChunk = encryptStream.push(chunk, true);
    encryptStream.dispose();

    const decryptStream = await createDecryptStream(key, header);
    const { plaintext, isFinal } = decryptStream.pull(encryptedChunk);
    decryptStream.dispose();

    expect(new TextDecoder().decode(plaintext)).toBe('Hello, streaming world!');
    expect(isFinal).toBe(true);
  });

  test('round-trips multiple chunks', async () => {
    const key = await generateKey();
    const chunks = [
      new TextEncoder().encode('Chunk 1'),
      new TextEncoder().encode('Chunk 2'),
      new TextEncoder().encode('Chunk 3'),
    ];

    const encryptStream = await createEncryptStream(key);
    const header = encryptStream.header;
    const encryptedChunks = chunks.map((chunk, i) =>
      encryptStream.push(chunk, i === chunks.length - 1)
    );
    encryptStream.dispose();

    const decryptStream = await createDecryptStream(key, header);
    const decryptedChunks: Uint8Array[] = [];
    let sawFinal = false;

    for (const encChunk of encryptedChunks) {
      const { plaintext, isFinal } = decryptStream.pull(encChunk);
      decryptedChunks.push(plaintext);
      if (isFinal) sawFinal = true;
    }
    decryptStream.dispose();

    expect(new TextDecoder().decode(decryptedChunks[0])).toBe('Chunk 1');
    expect(new TextDecoder().decode(decryptedChunks[1])).toBe('Chunk 2');
    expect(new TextDecoder().decode(decryptedChunks[2])).toBe('Chunk 3');
    expect(sawFinal).toBe(true);
  });

  test('handles empty chunks', async () => {
    const key = await generateKey();
    const chunk = new Uint8Array(0);

    const encryptStream = await createEncryptStream(key);
    const header = encryptStream.header;
    const encryptedChunk = encryptStream.push(chunk, true);
    encryptStream.dispose();

    const decryptStream = await createDecryptStream(key, header);
    const { plaintext, isFinal } = decryptStream.pull(encryptedChunk);
    decryptStream.dispose();

    expect(plaintext.length).toBe(0);
    expect(isFinal).toBe(true);
  });

  test('header is 24 bytes', async () => {
    const key = await generateKey();
    const encryptStream = await createEncryptStream(key);
    expect(encryptStream.header.length).toBe(24);
    encryptStream.dispose();
  });

  test('chunk overhead is 17 bytes', async () => {
    const key = await generateKey();
    const chunk = new Uint8Array(100);

    const encryptStream = await createEncryptStream(key);
    const encryptedChunk = encryptStream.push(chunk, true);
    encryptStream.dispose();

    expect(encryptedChunk.length).toBe(100 + 17);
  });

  test('detects chunk tampering with SEGMENT_AUTH_FAILED', async () => {
    const key = await generateKey();
    const chunk = new TextEncoder().encode('test data');

    const encryptStream = await createEncryptStream(key);
    const header = encryptStream.header;
    const encryptedChunk = encryptStream.push(chunk, true);
    encryptStream.dispose();

    const tamperedChunk = new Uint8Array(encryptedChunk);
    tamperedChunk[0] = tamperedChunk[0]! ^ 0xff;

    const decryptStream = await createDecryptStream(key, header);
    try {
      decryptStream.pull(tamperedChunk);
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
    }
    decryptStream.dispose();
  });

  test('wrong key fails authentication', async () => {
    const key1 = await generateKey();
    const key2 = await generateKey();
    const chunk = new TextEncoder().encode('test data');

    const encryptStream = await createEncryptStream(key1);
    const header = encryptStream.header;
    const encryptedChunk = encryptStream.push(chunk, true);
    encryptStream.dispose();

    let errorThrown = false;
    try {
      const decryptStream = await createDecryptStream(key2, header);
      decryptStream.pull(encryptedChunk);
      decryptStream.dispose();
    } catch (error) {
      errorThrown = true;
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
    }
    expect(errorThrown).toBe(true);
  });

  test('wrong header fails authentication', async () => {
    const key = await generateKey();
    const chunk = new TextEncoder().encode('test data');

    const encryptStream = await createEncryptStream(key);
    const encryptedChunk = encryptStream.push(chunk, true);
    encryptStream.dispose();

    const wrongHeader = asSecretstreamHeader(new Uint8Array(24).fill(0));

    let errorThrown = false;
    try {
      const decryptStream = await createDecryptStream(key, wrongHeader);
      decryptStream.pull(encryptedChunk);
      decryptStream.dispose();
    } catch (error) {
      errorThrown = true;
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
    }
    expect(errorThrown).toBe(true);
  });

  test('fileId mismatch fails authentication', async () => {
    const key = await generateKey();
    const chunk = new TextEncoder().encode('test data');
    const fileId1 = asFileId(await hash(new TextEncoder().encode('file1')));
    const fileId2 = asFileId(await hash(new TextEncoder().encode('file2')));

    const encryptStream = await createEncryptStream(key, fileId1);
    const header = encryptStream.header;
    const encryptedChunk = encryptStream.push(chunk, true);
    encryptStream.dispose();

    let errorThrown = false;
    try {
      const decryptStream = await createDecryptStream(key, header, fileId2);
      decryptStream.pull(encryptedChunk);
      decryptStream.dispose();
    } catch (error) {
      errorThrown = true;
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
    }
    expect(errorThrown).toBe(true);
  });

  test('handles large number of chunks (100+)', async () => {
    const key = await generateKey();
    const chunkCount = 100;
    const chunkSize = 1024;

    const encryptStream = await createEncryptStream(key);
    const header = encryptStream.header;
    const encryptedChunks: Uint8Array[] = [];

    for (let i = 0; i < chunkCount; i++) {
      const chunk = new Uint8Array(chunkSize).fill(i % 256);
      const isFinal = i === chunkCount - 1;
      encryptedChunks.push(encryptStream.push(chunk, isFinal));
    }
    encryptStream.dispose();

    const decryptStream = await createDecryptStream(key, header);
    let decryptedCount = 0;
    let sawFinal = false;

    for (let i = 0; i < encryptedChunks.length; i++) {
      const { plaintext, isFinal } = decryptStream.pull(encryptedChunks[i]!);
      expect(plaintext.length).toBe(chunkSize);
      expect(plaintext.every((b) => b === i % 256)).toBe(true);
      decryptedCount++;
      if (isFinal) sawFinal = true;
    }
    decryptStream.dispose();

    expect(decryptedCount).toBe(chunkCount);
    expect(sawFinal).toBe(true);
  });

  test('detects chunk reordering', async () => {
    const key = await generateKey();
    const chunks = [
      new TextEncoder().encode('Chunk 0'),
      new TextEncoder().encode('Chunk 1'),
      new TextEncoder().encode('Chunk 2'),
    ];

    const encryptStream = await createEncryptStream(key);
    const header = encryptStream.header;
    const encryptedChunks = chunks.map((chunk, i) =>
      encryptStream.push(chunk, i === chunks.length - 1)
    );
    encryptStream.dispose();

    const reordered = [encryptedChunks[1]!, encryptedChunks[0]!, encryptedChunks[2]!];

    let errorThrown = false;
    try {
      const decryptStream = await createDecryptStream(key, header);
      decryptStream.pull(reordered[0]!);
      decryptStream.dispose();
    } catch (error) {
      errorThrown = true;
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.SEGMENT_AUTH_FAILED);
    }
    expect(errorThrown).toBe(true);
  });
});

describe('security properties', () => {
  test('nonces are unique across many encryptions', async () => {
    const key = await generateKey();
    const plaintext = new TextEncoder().encode('test');
    const nonces = new Set<string>();

    for (let i = 0; i < 1000; i++) {
      const { nonce } = await encrypt(plaintext, key);
      nonces.add(toHex(nonce));
    }

    expect(nonces.size).toBe(1000);
  });

  test('keys are unique across many generations', async () => {
    const keys = new Set<string>();

    for (let i = 0; i < 1000; i++) {
      const key = await generateKey();
      keys.add(toHex(key));
    }

    expect(keys.size).toBe(1000);
  });

  test('context commitment: encrypt with A, decrypt with B fails', async () => {
    const key = await generateKey();
    const plaintext = new TextEncoder().encode('secret');
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

  test('no context vs with context fails decryption', async () => {
    const key = await generateKey();
    const plaintext = new TextEncoder().encode('secret');
    const context = new TextEncoder().encode('context');

    const { nonce, ciphertext } = await encrypt(plaintext, key, context);

    try {
      await decrypt(ciphertext, nonce, key);
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionError);
      expect((error as EncryptionError).code).toBe(ErrorCode.DECRYPTION_FAILED);
    }
  });
});
