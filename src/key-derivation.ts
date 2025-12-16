import { mnemonicToSeed, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { getSodium } from './sodium.ts';
import { invalidMnemonic, invalidSeedSize } from './errors.ts';
import { SIZES } from './types.ts';
import { unsafe } from './branded.ts';
import { secureZero } from './memory.ts';
import type { Seed, X25519PublicKey, X25519PrivateKey, Ed25519PublicKey, Ed25519PrivateKey } from './branded.ts';
import type { KdfContext } from './types.ts';

/** KDF context for Crust network identity keys */
export const CONTEXT_CRUST: KdfContext = 'crust___';
/** KDF context for ICP canister identity keys */
export const CONTEXT_ICP: KdfContext = 'icp_____';
/** KDF context for X25519 encryption keys */
export const CONTEXT_ENCRYPT: KdfContext = 'encrypt_';

/**
 * Derives a 64-byte seed from a BIP-39 mnemonic phrase.
 * @param mnemonic - 12 or 24 word BIP-39 mnemonic (lowercase, single spaces)
 * @param passphrase - Optional BIP-39 passphrase for additional security
 * @returns 64-byte seed for key derivation
 * @throws {EncryptionError} INVALID_MNEMONIC if mnemonic is invalid
 */
export async function deriveSeed(mnemonic: string, passphrase: string = ''): Promise<Seed> {
  const trimmed = mnemonic.trim();

  // Reject non-canonical input (uppercase, multiple spaces) for better typo detection
  // BIP-39 mnemonics should be lowercase with single spaces between words
  if (trimmed !== trimmed.toLowerCase()) {
    throw invalidMnemonic('mnemonic must be lowercase');
  }
  if (/\s{2,}/.test(trimmed)) {
    throw invalidMnemonic('mnemonic must have single spaces between words');
  }

  if (!validateMnemonic(trimmed, wordlist)) {
    throw invalidMnemonic('invalid BIP-39 mnemonic');
  }

  // @scure/bip39 handles NFKD normalization internally
  const seed = await mnemonicToSeed(trimmed, passphrase);
  return unsafe.asSeed(seed);
}

export async function deriveSubkey(
  masterKey: Uint8Array,
  subkeyId: number,
  context: KdfContext
): Promise<Uint8Array> {
  if (masterKey.length !== SIZES.SEED) {
    throw invalidSeedSize(masterKey.length, SIZES.SEED);
  }

  const sodium = await getSodium();

  const kdfKey = sodium.crypto_generichash(32, masterKey);
  const subkey = sodium.crypto_kdf_derive_from_key(32, subkeyId, context, kdfKey);
  secureZero(kdfKey);

  return subkey;
}

/** X25519 keypair for encryption and key exchange */
export type X25519KeyPair = {
  readonly publicKey: X25519PublicKey;
  readonly privateKey: X25519PrivateKey;
};

/** Ed25519 keypair for signing and identity */
export type Ed25519KeyPair = {
  readonly publicKey: Ed25519PublicKey;
  readonly privateKey: Ed25519PrivateKey;
};

/**
 * Derives an X25519 keypair for encryption from the master seed.
 * @param seed - 64-byte seed from deriveSeed()
 * @param index - Key index for derivation (use different indices for different keys)
 * @returns X25519 keypair for use with key wrapping functions
 */
export async function deriveEncryptionKeyPair(seed: Seed, index: number): Promise<X25519KeyPair> {
  const subkey = await deriveSubkey(seed, index, CONTEXT_ENCRYPT);
  const sodium = await getSodium();
  const keypair = sodium.crypto_box_seed_keypair(subkey);
  secureZero(subkey);

  return {
    publicKey: unsafe.asX25519PublicKey(keypair.publicKey),
    privateKey: unsafe.asX25519PrivateKey(keypair.privateKey),
  };
}

/**
 * Derives an Ed25519 keypair for signing/identity from the master seed.
 * @param seed - 64-byte seed from deriveSeed()
 * @param context - KDF context (CONTEXT_CRUST, CONTEXT_ICP, etc.)
 * @param index - Key index for derivation
 * @returns Ed25519 keypair for signing operations
 */
export async function deriveIdentityKeyPair(
  seed: Seed,
  context: KdfContext,
  index: number
): Promise<Ed25519KeyPair> {
  const subkey = await deriveSubkey(seed, index, context);
  const sodium = await getSodium();
  const keypair = sodium.crypto_sign_seed_keypair(subkey);
  secureZero(subkey);

  return {
    publicKey: unsafe.asEd25519PublicKey(keypair.publicKey),
    privateKey: unsafe.asEd25519PrivateKey(keypair.privateKey),
  };
}
