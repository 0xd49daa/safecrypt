import { describe, expect, test } from 'bun:test';
import {
  deriveSeed,
  deriveSubkey,
  deriveEncryptionKeyPair,
  deriveIdentityKeyPair,
} from '../src/key-derivation.ts';

// Test contexts for domain separation (8 characters each)
const CONTEXT_IDENTITY = 'identity';
const CONTEXT_SIGNING = 'signing_';
const CONTEXT_ENCRYPT = 'encrypt_';
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
    const subkeyIdentity = await deriveSubkey(seed, 0, CONTEXT_IDENTITY);
    const subkeySigning = await deriveSubkey(seed, 0, CONTEXT_SIGNING);
    const subkeyEncrypt = await deriveSubkey(seed, 0, CONTEXT_ENCRYPT);

    expect(toHex(subkeyIdentity)).not.toBe(toHex(subkeySigning));
    expect(toHex(subkeyIdentity)).not.toBe(toHex(subkeyEncrypt));
    expect(toHex(subkeySigning)).not.toBe(toHex(subkeyEncrypt));
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
    const keypair = await deriveIdentityKeyPair(seed, CONTEXT_IDENTITY, 0);

    expect(keypair.publicKey.length).toBe(SIZES.ED25519_PUBLIC_KEY);
    expect(keypair.privateKey.length).toBe(SIZES.ED25519_PRIVATE_KEY);
  });

  test('produces deterministic keypairs', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    const keypair1 = await deriveIdentityKeyPair(seed, CONTEXT_IDENTITY, 0);
    const keypair2 = await deriveIdentityKeyPair(seed, CONTEXT_IDENTITY, 0);

    expect(toHex(keypair1.publicKey)).toBe(toHex(keypair2.publicKey));
    expect(toHex(keypair1.privateKey)).toBe(toHex(keypair2.privateKey));
  });

  test('produces different keypairs for different contexts', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    const keypairIdentity = await deriveIdentityKeyPair(seed, CONTEXT_IDENTITY, 0);
    const keypairSigning = await deriveIdentityKeyPair(seed, CONTEXT_SIGNING, 0);

    expect(toHex(keypairIdentity.publicKey)).not.toBe(toHex(keypairSigning.publicKey));
  });

  test('produces different keypairs for different indices', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    const keypair0 = await deriveIdentityKeyPair(seed, CONTEXT_IDENTITY, 0);
    const keypair1 = await deriveIdentityKeyPair(seed, CONTEXT_IDENTITY, 1);

    expect(toHex(keypair0.publicKey)).not.toBe(toHex(keypair1.publicKey));
  });
});

describe('context validation', () => {
  test('CONTEXT_IDENTITY is 8 characters', () => {
    expect(CONTEXT_IDENTITY.length).toBe(SIZES.KDF_CONTEXT);
  });

  test('CONTEXT_SIGNING is 8 characters', () => {
    expect(CONTEXT_SIGNING.length).toBe(SIZES.KDF_CONTEXT);
  });

  test('CONTEXT_ENCRYPT is 8 characters', () => {
    expect(CONTEXT_ENCRYPT.length).toBe(SIZES.KDF_CONTEXT);
  });

  test('throws INVALID_CONTEXT_SIZE for short context', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    await expect(deriveSubkey(seed, 0, 'short')).rejects.toThrow('Invalid context size');
  });

  test('throws INVALID_CONTEXT_SIZE for long context', async () => {
    const seed = await deriveSeed(TEST_MNEMONIC);
    await expect(deriveSubkey(seed, 0, 'toolongcontext')).rejects.toThrow('Invalid context size');
  });
});

describe('determinism across calls', () => {
  test('same mnemonic + index produces identical keys across multiple derivations', async () => {
    const mnemonic = generateMnemonic(wordlist, 256);

    const seed1 = await deriveSeed(mnemonic);
    const encKp1 = await deriveEncryptionKeyPair(seed1, 0);
    const identityKp1 = await deriveIdentityKeyPair(seed1, CONTEXT_IDENTITY, 0);
    const signingKp1 = await deriveIdentityKeyPair(seed1, CONTEXT_SIGNING, 0);

    const seed2 = await deriveSeed(mnemonic);
    const encKp2 = await deriveEncryptionKeyPair(seed2, 0);
    const identityKp2 = await deriveIdentityKeyPair(seed2, CONTEXT_IDENTITY, 0);
    const signingKp2 = await deriveIdentityKeyPair(seed2, CONTEXT_SIGNING, 0);

    expect(toHex(encKp1.publicKey)).toBe(toHex(encKp2.publicKey));
    expect(toHex(encKp1.privateKey)).toBe(toHex(encKp2.privateKey));
    expect(toHex(identityKp1.publicKey)).toBe(toHex(identityKp2.publicKey));
    expect(toHex(identityKp1.privateKey)).toBe(toHex(identityKp2.privateKey));
    expect(toHex(signingKp1.publicKey)).toBe(toHex(signingKp2.publicKey));
    expect(toHex(signingKp1.privateKey)).toBe(toHex(signingKp2.privateKey));
  });
});
