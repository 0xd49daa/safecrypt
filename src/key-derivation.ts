import { mnemonicToSeed, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { getSodium } from './sodium.ts';
import { invalidMnemonic, invalidSeedSize } from './errors.ts';
import { SIZES } from './types.ts';
import { unsafe } from './branded.ts';
import { secureZero } from './memory.ts';
import type { Seed, X25519PublicKey, X25519PrivateKey, Ed25519PublicKey, Ed25519PrivateKey } from './branded.ts';
import type { KdfContext } from './types.ts';

export const CONTEXT_CRUST: KdfContext = 'crust___';
export const CONTEXT_ICP: KdfContext = 'icp_____';
export const CONTEXT_ENCRYPT: KdfContext = 'encrypt_';

export async function deriveSeed(mnemonic: string, passphrase: string = ''): Promise<Seed> {
  const normalized = mnemonic.trim().toLowerCase().replace(/\s+/g, ' ');

  if (!validateMnemonic(normalized, wordlist)) {
    throw invalidMnemonic('invalid BIP-39 mnemonic');
  }

  const seed = await mnemonicToSeed(normalized, passphrase);
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

export type X25519KeyPair = {
  readonly publicKey: X25519PublicKey;
  readonly privateKey: X25519PrivateKey;
};

export type Ed25519KeyPair = {
  readonly publicKey: Ed25519PublicKey;
  readonly privateKey: Ed25519PrivateKey;
};

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
