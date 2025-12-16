import { describe, expect, test } from 'bun:test';
import {
  asSymmetricKey,
  asNonce,
  asCiphertext,
  asFileId,
  asSecretstreamHeader,
  asX25519PublicKey,
  asX25519PrivateKey,
  asEd25519PublicKey,
  asEd25519PrivateKey,
  asContentHash,
  asSeed,
  unsafe,
  type SymmetricKey,
  type Nonce,
  type Ciphertext,
  type FileId,
  type SecretstreamHeader,
  type X25519PublicKey,
  type X25519PrivateKey,
  type Ed25519PublicKey,
  type Ed25519PrivateKey,
  type ContentHash,
  type Seed,
} from '../src/branded.ts';
import { EncryptionError } from '../src/errors.ts';
import { SIZES } from '../src/types.ts';

describe('asSymmetricKey', () => {
  test('accepts 32-byte array', () => {
    const bytes = new Uint8Array(32);
    const key = asSymmetricKey(bytes);
    expect(key).toBe(bytes as SymmetricKey);
    expect(key.length).toBe(32);
  });

  test('throws for wrong size', () => {
    expect(() => asSymmetricKey(new Uint8Array(16))).toThrow(EncryptionError);
    expect(() => asSymmetricKey(new Uint8Array(64))).toThrow(EncryptionError);
  });
});

describe('asNonce', () => {
  test('accepts 24-byte array', () => {
    const bytes = new Uint8Array(24);
    const nonce = asNonce(bytes);
    expect(nonce).toBe(bytes as Nonce);
  });

  test('throws for wrong size', () => {
    expect(() => asNonce(new Uint8Array(12))).toThrow(EncryptionError);
  });
});

describe('asCiphertext', () => {
  test('accepts any size array', () => {
    const bytes = new Uint8Array(100);
    const ct = asCiphertext(bytes);
    expect(ct).toBe(bytes as Ciphertext);
  });

  test('accepts empty array', () => {
    const bytes = new Uint8Array(0);
    const ct = asCiphertext(bytes);
    expect(ct).toBe(bytes as Ciphertext);
  });
});

describe('asFileId', () => {
  test('accepts 32-byte array', () => {
    const bytes = new Uint8Array(32);
    const fileId = asFileId(bytes);
    expect(fileId).toBe(bytes as FileId);
  });

  test('throws for wrong size', () => {
    expect(() => asFileId(new Uint8Array(16))).toThrow(EncryptionError);
  });
});

describe('asSecretstreamHeader', () => {
  test('accepts 24-byte array', () => {
    const bytes = new Uint8Array(24);
    const header = asSecretstreamHeader(bytes);
    expect(header).toBe(bytes as SecretstreamHeader);
  });

  test('throws for wrong size', () => {
    expect(() => asSecretstreamHeader(new Uint8Array(32))).toThrow(EncryptionError);
  });
});

describe('asX25519PublicKey', () => {
  test('accepts 32-byte array', () => {
    const bytes = new Uint8Array(32);
    const key = asX25519PublicKey(bytes);
    expect(key).toBe(bytes as X25519PublicKey);
  });

  test('throws for wrong size', () => {
    expect(() => asX25519PublicKey(new Uint8Array(64))).toThrow(EncryptionError);
  });
});

describe('asX25519PrivateKey', () => {
  test('accepts 32-byte array', () => {
    const bytes = new Uint8Array(32);
    const key = asX25519PrivateKey(bytes);
    expect(key).toBe(bytes as X25519PrivateKey);
  });

  test('throws for wrong size', () => {
    expect(() => asX25519PrivateKey(new Uint8Array(64))).toThrow(EncryptionError);
  });
});

describe('asEd25519PublicKey', () => {
  test('accepts 32-byte array', () => {
    const bytes = new Uint8Array(32);
    const key = asEd25519PublicKey(bytes);
    expect(key).toBe(bytes as Ed25519PublicKey);
  });

  test('throws for wrong size', () => {
    expect(() => asEd25519PublicKey(new Uint8Array(64))).toThrow(EncryptionError);
  });
});

describe('asEd25519PrivateKey', () => {
  test('accepts 64-byte array', () => {
    const bytes = new Uint8Array(64);
    const key = asEd25519PrivateKey(bytes);
    expect(key).toBe(bytes as Ed25519PrivateKey);
  });

  test('throws for wrong size', () => {
    expect(() => asEd25519PrivateKey(new Uint8Array(32))).toThrow(EncryptionError);
  });
});

describe('asContentHash', () => {
  test('accepts 32-byte array', () => {
    const bytes = new Uint8Array(32);
    const hash = asContentHash(bytes);
    expect(hash).toBe(bytes as ContentHash);
  });

  test('throws for wrong size', () => {
    expect(() => asContentHash(new Uint8Array(64))).toThrow(EncryptionError);
  });
});

describe('asSeed', () => {
  test('accepts 64-byte array', () => {
    const bytes = new Uint8Array(64);
    const seed = asSeed(bytes);
    expect(seed).toBe(bytes as Seed);
  });

  test('throws for wrong size', () => {
    expect(() => asSeed(new Uint8Array(32))).toThrow(EncryptionError);
  });
});

describe('unsafe namespace', () => {
  test('brands without validation', () => {
    const wrongSize = new Uint8Array(5);
    expect(unsafe.asSymmetricKey(wrongSize).length).toBe(5);
    expect(unsafe.asNonce(wrongSize).length).toBe(5);
    expect(unsafe.asCiphertext(wrongSize).length).toBe(5);
    expect(unsafe.asFileId(wrongSize).length).toBe(5);
    expect(unsafe.asSecretstreamHeader(wrongSize).length).toBe(5);
    expect(unsafe.asX25519PublicKey(wrongSize).length).toBe(5);
    expect(unsafe.asX25519PrivateKey(wrongSize).length).toBe(5);
    expect(unsafe.asEd25519PublicKey(wrongSize).length).toBe(5);
    expect(unsafe.asEd25519PrivateKey(wrongSize).length).toBe(5);
    expect(unsafe.asContentHash(wrongSize).length).toBe(5);
    expect(unsafe.asSeed(wrongSize).length).toBe(5);
  });
});

describe('branded values work as Uint8Array', () => {
  test('can access array properties', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]);
    const key = asSymmetricKey(bytes);

    expect(key.length).toBe(32);
    expect(key[0]).toBe(1);
    expect(key[31]).toBe(32);
    expect(key.slice(0, 4)).toEqual(new Uint8Array([1, 2, 3, 4]));
  });

  test('can pass to functions expecting Uint8Array', () => {
    const bytes = new Uint8Array(32);
    const key = asSymmetricKey(bytes);

    function acceptsUint8Array(arr: Uint8Array): number {
      return arr.length;
    }

    expect(acceptsUint8Array(key)).toBe(32);
  });
});
