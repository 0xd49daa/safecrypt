import { describe, expect, test } from 'bun:test';
import {
  deriveSeed,
  deriveSubkey,
  deriveEncryptionKeyPair,
  deriveIdentityKeyPair,
  CONTEXT_CRUST,
  CONTEXT_ICP,
  CONTEXT_ENCRYPT,
} from '../src/key-derivation.ts';
import { toHex } from '../src/bytes.ts';
import { SIZES } from '../src/types.ts';
import type { Seed } from '../src/branded.ts';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('deriveSeed', () => {
  test('derives 64-byte seed from valid mnemonic', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    expect(seed.length).toBe(SIZES.SEED);
  });

  test('produces deterministic seed', async () => {
    const seed1 = await deriveSeed(TEST_MNEMONIC);
    const seed2 = await deriveSeed(TEST_MNEMONIC);
    expect(toHex(seed1)).toBe(toHex(seed2));
  });

  test('handles optional passphrase', async () => {
    const seedNoPass = await deriveSeed(TEST_MNEMONIC);
    const seedWithPass = await deriveSeed(TEST_MNEMONIC, 'mypassword');
    expect(toHex(seedNoPass)).not.toBe(toHex(seedWithPass));
  });

  test('same passphrase produces same seed', async () => {
    const seed1 = await deriveSeed(TEST_MNEMONIC, 'password');
    const seed2 = await deriveSeed(TEST_MNEMONIC, 'password');
    expect(toHex(seed1)).toBe(toHex(seed2));
  });

  test('throws INVALID_MNEMONIC for invalid mnemonic', async () => {
    await expect(deriveSeed('invalid mnemonic words')).rejects.toThrow();
  });

  test('throws INVALID_MNEMONIC for wrong word count', async () => {
    await expect(deriveSeed('abandon abandon abandon')).rejects.toThrow();
  });

  test('rejects multiple spaces between words', async () => {
    await expect(
      deriveSeed('abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about')
    ).rejects.toThrow('mnemonic must have single spaces between words');
  });

  test('rejects uppercase letters', async () => {
    await expect(
      deriveSeed('Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about')
    ).rejects.toThrow('mnemonic must be lowercase');
  });

  test('trims leading and trailing whitespace', async () => {
    const seedNormal = await deriveSeed(TEST_MNEMONIC);
    const seedTrimmed = await deriveSeed('  ' + TEST_MNEMONIC + '  ');
    expect(toHex(seedNormal)).toBe(toHex(seedTrimmed));
  });

  test('works with 24-word mnemonic', async () => {
    const mnemonic24 = generateMnemonic(wordlist, 256);
    const seed = await deriveSeed(mnemonic24);
    expect(seed.length).toBe(SIZES.SEED);
  });
});

describe('deriveSubkey', () => {
  test('derives 32-byte subkey', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    const subkey = await deriveSubkey(seed, 0, CONTEXT_ENCRYPT);
    expect(subkey.length).toBe(32);
  });

  test('produces different keys for different indices', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    const subkey0 = await deriveSubkey(seed, 0, CONTEXT_ENCRYPT);
    const subkey1 = await deriveSubkey(seed, 1, CONTEXT_ENCRYPT);
    expect(toHex(subkey0)).not.toBe(toHex(subkey1));
  });

  test('produces different keys for different contexts', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    const subkeyCrust = await deriveSubkey(seed, 0, CONTEXT_CRUST);
    const subkeyIcp = await deriveSubkey(seed, 0, CONTEXT_ICP);
    const subkeyEncrypt = await deriveSubkey(seed, 0, CONTEXT_ENCRYPT);

    expect(toHex(subkeyCrust)).not.toBe(toHex(subkeyIcp));
    expect(toHex(subkeyCrust)).not.toBe(toHex(subkeyEncrypt));
    expect(toHex(subkeyIcp)).not.toBe(toHex(subkeyEncrypt));
  });

  test('produces deterministic subkeys', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    const subkey1 = await deriveSubkey(seed, 0, CONTEXT_ENCRYPT);
    const subkey2 = await deriveSubkey(seed, 0, CONTEXT_ENCRYPT);
    expect(toHex(subkey1)).toBe(toHex(subkey2));
  });

  test('throws INVALID_SEED_SIZE for short input', async () => {
    const shortSeed = new Uint8Array(32);
    await expect(deriveSubkey(shortSeed as unknown as Seed, 0, CONTEXT_ENCRYPT)).rejects.toThrow('Invalid seed size');
  });

  test('throws INVALID_SEED_SIZE for oversized input', async () => {
    const longSeed = new Uint8Array(128);
    await expect(deriveSubkey(longSeed as unknown as Seed, 0, CONTEXT_ENCRYPT)).rejects.toThrow('Invalid seed size');
  });

  test('both halves of seed influence derived key', async () => {
    const seed1 = new Uint8Array(64).fill(0);
    const seed2 = new Uint8Array(64).fill(0);
    seed2[63] = 1;

    const subkey1 = await deriveSubkey(seed1 as unknown as Seed, 0, CONTEXT_ENCRYPT);
    const subkey2 = await deriveSubkey(seed2 as unknown as Seed, 0, CONTEXT_ENCRYPT);

    expect(toHex(subkey1)).not.toBe(toHex(subkey2));
  });
});

describe('deriveEncryptionKeyPair', () => {
  test('derives valid X25519 keypair', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    const keypair = await deriveEncryptionKeyPair(seed, 0);

    expect(keypair.publicKey.length).toBe(SIZES.X25519_PUBLIC_KEY);
    expect(keypair.privateKey.length).toBe(SIZES.X25519_PRIVATE_KEY);
  });

  test('produces deterministic keypairs', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    const keypair1 = await deriveEncryptionKeyPair(seed, 0);
    const keypair2 = await deriveEncryptionKeyPair(seed, 0);

    expect(toHex(keypair1.publicKey)).toBe(toHex(keypair2.publicKey));
    expect(toHex(keypair1.privateKey)).toBe(toHex(keypair2.privateKey));
  });

  test('produces different keypairs for different indices', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    const keypair0 = await deriveEncryptionKeyPair(seed, 0);
    const keypair1 = await deriveEncryptionKeyPair(seed, 1);

    expect(toHex(keypair0.publicKey)).not.toBe(toHex(keypair1.publicKey));
    expect(toHex(keypair0.privateKey)).not.toBe(toHex(keypair1.privateKey));
  });

  test('produces different keypairs for different seeds', async () => {
    const seed1 = await deriveSeed(TEST_MNEMONIC);
    const mnemonic2 = generateMnemonic(wordlist, 128);
    const seed2 = await deriveSeed(mnemonic2);

    const keypair1 = await deriveEncryptionKeyPair(seed1, 0);
    const keypair2 = await deriveEncryptionKeyPair(seed2, 0);

    expect(toHex(keypair1.publicKey)).not.toBe(toHex(keypair2.publicKey));
  });
});

describe('deriveIdentityKeyPair', () => {
  test('derives valid Ed25519 keypair', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    const keypair = await deriveIdentityKeyPair(seed, CONTEXT_CRUST, 0);

    expect(keypair.publicKey.length).toBe(SIZES.ED25519_PUBLIC_KEY);
    expect(keypair.privateKey.length).toBe(SIZES.ED25519_PRIVATE_KEY);
  });

  test('produces deterministic keypairs', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    const keypair1 = await deriveIdentityKeyPair(seed, CONTEXT_CRUST, 0);
    const keypair2 = await deriveIdentityKeyPair(seed, CONTEXT_CRUST, 0);

    expect(toHex(keypair1.publicKey)).toBe(toHex(keypair2.publicKey));
    expect(toHex(keypair1.privateKey)).toBe(toHex(keypair2.privateKey));
  });

  test('produces different keypairs for different contexts', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    const keypairCrust = await deriveIdentityKeyPair(seed, CONTEXT_CRUST, 0);
    const keypairIcp = await deriveIdentityKeyPair(seed, CONTEXT_ICP, 0);

    expect(toHex(keypairCrust.publicKey)).not.toBe(toHex(keypairIcp.publicKey));
  });

  test('produces different keypairs for different indices', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    const keypair0 = await deriveIdentityKeyPair(seed, CONTEXT_CRUST, 0);
    const keypair1 = await deriveIdentityKeyPair(seed, CONTEXT_CRUST, 1);

    expect(toHex(keypair0.publicKey)).not.toBe(toHex(keypair1.publicKey));
  });
});

describe('context constants', () => {
  test('CONTEXT_CRUST is 8 bytes', () => {
    expect(CONTEXT_CRUST.length).toBe(SIZES.KDF_CONTEXT);
  });

  test('CONTEXT_ICP is 8 bytes', () => {
    expect(CONTEXT_ICP.length).toBe(SIZES.KDF_CONTEXT);
  });

  test('CONTEXT_ENCRYPT is 8 bytes', () => {
    expect(CONTEXT_ENCRYPT.length).toBe(SIZES.KDF_CONTEXT);
  });
});

describe('determinism across calls', () => {
  test('same mnemonic + index produces identical keys across multiple derivations', async () => {
    const mnemonic = generateMnemonic(wordlist, 256);

    const seed1 = await deriveSeed(mnemonic);
    const encKp1 = await deriveEncryptionKeyPair(seed1, 0);
    const crustKp1 = await deriveIdentityKeyPair(seed1, CONTEXT_CRUST, 0);
    const icpKp1 = await deriveIdentityKeyPair(seed1, CONTEXT_ICP, 0);

    const seed2 = await deriveSeed(mnemonic);
    const encKp2 = await deriveEncryptionKeyPair(seed2, 0);
    const crustKp2 = await deriveIdentityKeyPair(seed2, CONTEXT_CRUST, 0);
    const icpKp2 = await deriveIdentityKeyPair(seed2, CONTEXT_ICP, 0);

    expect(toHex(encKp1.publicKey)).toBe(toHex(encKp2.publicKey));
    expect(toHex(encKp1.privateKey)).toBe(toHex(encKp2.privateKey));
    expect(toHex(crustKp1.publicKey)).toBe(toHex(crustKp2.publicKey));
    expect(toHex(crustKp1.privateKey)).toBe(toHex(crustKp2.privateKey));
    expect(toHex(icpKp1.publicKey)).toBe(toHex(icpKp2.publicKey));
    expect(toHex(icpKp1.privateKey)).toBe(toHex(icpKp2.privateKey));
  });
});
