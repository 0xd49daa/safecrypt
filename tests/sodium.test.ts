import { describe, expect, test } from 'bun:test';
import { getSodium, preloadSodium } from '../src/sodium.ts';

describe('getSodium', () => {
  test('returns libsodium instance', async () => {
    const sodium = await getSodium();
    expect(sodium).toBeDefined();
    expect(typeof sodium.crypto_secretbox_KEYBYTES).toBe('number');
  });

  test('returns same instance on multiple calls', async () => {
    const sodium1 = await getSodium();
    const sodium2 = await getSodium();
    expect(sodium1).toBe(sodium2);
  });

  test('handles concurrent initialization', async () => {
    const promises = Array.from({ length: 10 }, () => getSodium());
    const instances = await Promise.all(promises);

    const first = instances[0]!;
    for (const instance of instances) {
      expect(instance).toBe(first);
    }
  });

  test('provides working crypto functions', async () => {
    const sodium = await getSodium();
    const randomBytes = sodium.randombytes_buf(32);
    expect(randomBytes).toBeInstanceOf(Uint8Array);
    expect(randomBytes.length).toBe(32);
  });
});

describe('preloadSodium', () => {
  test('initializes sodium without returning instance', async () => {
    const result = await preloadSodium();
    expect(result).toBeUndefined();
  });

  test('makes subsequent getSodium calls faster', async () => {
    await preloadSodium();
    const sodium = await getSodium();
    expect(sodium).toBeDefined();
  });
});
