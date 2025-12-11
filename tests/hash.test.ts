import { describe, expect, test } from 'bun:test';
import { hash, createHasher, hashBlake2b } from '../src/hash.ts';
import { toHex } from '../src/bytes.ts';

describe('hash', () => {
  test('returns 32-byte SHA-256 hash', async () => {
    const data = new TextEncoder().encode('hello world');
    const result = await hash(data);
    expect(result.length).toBe(32);
  });

  test('matches known test vector', async () => {
    const data = new TextEncoder().encode('hello world');
    const result = await hash(data);
    const hex = toHex(result);
    expect(hex).toBe('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');
  });

  test('handles empty input', async () => {
    const data = new Uint8Array(0);
    const result = await hash(data);
    const hex = toHex(result);
    expect(hex).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  test('handles large input', async () => {
    const data = new Uint8Array(1_000_000).fill(0x42);
    const result = await hash(data);
    expect(result.length).toBe(32);
  });

  test('produces different hashes for different inputs', async () => {
    const hash1 = await hash(new TextEncoder().encode('hello'));
    const hash2 = await hash(new TextEncoder().encode('world'));
    expect(toHex(hash1)).not.toBe(toHex(hash2));
  });

  test('produces identical hashes for identical inputs', async () => {
    const data = new TextEncoder().encode('test data');
    const hash1 = await hash(data);
    const hash2 = await hash(data);
    expect(toHex(hash1)).toBe(toHex(hash2));
  });
});

describe('createHasher', () => {
  test('produces same hash as hashBlake2b', async () => {
    const data = new TextEncoder().encode('hello world');
    const singleShot = await hashBlake2b(data);

    const hasher = await createHasher();
    hasher.update(data);
    const streaming = await hasher.digest();

    expect(toHex(streaming)).toBe(toHex(singleShot));
  });

  test('handles multiple updates', async () => {
    const hasher = await createHasher();
    hasher.update(new TextEncoder().encode('hello'));
    hasher.update(new TextEncoder().encode(' '));
    hasher.update(new TextEncoder().encode('world'));
    const result = await hasher.digest();

    const expected = await hashBlake2b(new TextEncoder().encode('hello world'));
    expect(toHex(result)).toBe(toHex(expected));
  });

  test('handles empty updates', async () => {
    const hasher = await createHasher();
    hasher.update(new Uint8Array(0));
    hasher.update(new TextEncoder().encode('test'));
    hasher.update(new Uint8Array(0));
    const result = await hasher.digest();

    const expected = await hashBlake2b(new TextEncoder().encode('test'));
    expect(toHex(result)).toBe(toHex(expected));
  });

  test('handles no updates', async () => {
    const hasher = await createHasher();
    const result = await hasher.digest();

    const expected = await hashBlake2b(new Uint8Array(0));
    expect(toHex(result)).toBe(toHex(expected));
  });

  test('handles large chunks', async () => {
    const chunk1 = new Uint8Array(500_000).fill(0x41);
    const chunk2 = new Uint8Array(500_000).fill(0x42);

    const hasher = await createHasher();
    hasher.update(chunk1);
    hasher.update(chunk2);
    const streaming = await hasher.digest();

    const combined = new Uint8Array(1_000_000);
    combined.set(chunk1, 0);
    combined.set(chunk2, 500_000);
    const singleShot = await hashBlake2b(combined);

    expect(toHex(streaming)).toBe(toHex(singleShot));
  });
});

describe('hashBlake2b', () => {
  test('returns 32-byte hash by default', async () => {
    const data = new TextEncoder().encode('hello world');
    const result = await hashBlake2b(data);
    expect(result.length).toBe(32);
  });

  test('supports custom output length', async () => {
    const data = new TextEncoder().encode('test');
    const hash16 = await hashBlake2b(data, 16);
    const hash64 = await hashBlake2b(data, 64);

    expect(hash16.length).toBe(16);
    expect(hash64.length).toBe(64);
  });

  test('handles empty input', async () => {
    const result = await hashBlake2b(new Uint8Array(0));
    expect(result.length).toBe(32);
  });

  test('produces different hashes for different inputs', async () => {
    const hash1 = await hashBlake2b(new TextEncoder().encode('hello'));
    const hash2 = await hashBlake2b(new TextEncoder().encode('world'));
    expect(toHex(hash1)).not.toBe(toHex(hash2));
  });

  test('produces identical hashes for identical inputs', async () => {
    const data = new TextEncoder().encode('test data');
    const hash1 = await hashBlake2b(data);
    const hash2 = await hashBlake2b(data);
    expect(toHex(hash1)).toBe(toHex(hash2));
  });

  test('different from SHA-256', async () => {
    const data = new TextEncoder().encode('hello world');
    const sha256 = await hash(data);
    const blake2b = await hashBlake2b(data);
    expect(toHex(sha256)).not.toBe(toHex(blake2b));
  });
});
