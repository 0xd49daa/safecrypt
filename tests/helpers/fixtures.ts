import { generateKey } from '../../src/encryption.ts';
import { deriveSeed, deriveEncryptionKeyPair } from '../../src/key-derivation.ts';
import type { SymmetricKey, Seed } from '../../src/branded.ts';
import type { X25519KeyPair } from '../../src/key-derivation.ts';

export const TEST_MNEMONIC_12 =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

export const TEST_MNEMONIC_24 =
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon art';

export const TEST_PASSPHRASE = 'TREZOR';

export async function createTestKey(): Promise<SymmetricKey> {
  return generateKey();
}

export async function createTestSeed(mnemonic = TEST_MNEMONIC_12): Promise<Seed> {
  return deriveSeed(mnemonic);
}

export async function createTestKeyPair(index = 0, mnemonic = TEST_MNEMONIC_12): Promise<X25519KeyPair> {
  const seed = await createTestSeed(mnemonic);
  return deriveEncryptionKeyPair(seed, index);
}

export function createTestData(size: number): Uint8Array {
  const data = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    data[i] = i % 256;
  }
  return data;
}

export function createRandomData(size: number): Uint8Array {
  const data = new Uint8Array(size);
  crypto.getRandomValues(data);
  return data;
}

export const SIZES = {
  EMPTY: 0,
  TINY: 16,
  SMALL: 1024,
  MEDIUM: 64 * 1024,
  LARGE: 1024 * 1024,
  VERY_LARGE: 10 * 1024 * 1024,
} as const;

export const CHUNK_SIZE = 64 * 1024;
export const CHUNK_OVERHEAD = 17;
