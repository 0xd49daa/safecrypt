import { getSodium } from './sodium.ts';
import { asSalt, unsafe } from './branded.ts';
import { decryptionFailed, invalidKeySize, unsupportedVersion } from './errors.ts';
import { secureZero } from './memory.ts';
import { SIZES } from './types.ts';
import type { Salt, SymmetricKey } from './branded.ts';
import type { PasswordEncryptedData } from './types.ts';

const SUPPORTED_VERSIONS = [1] as const;
let emptyPasswordWarningShown = false;

/**
 * Derives a symmetric key from a password using Argon2id.
 * Uses OPSLIMIT_INTERACTIVE/MEMLIMIT_INTERACTIVE for ~100ms derivation.
 *
 * @param password - User-provided password (empty passwords are allowed but provide no security)
 * @param salt - 16-byte random salt (generate with randomBytes(16))
 * @returns 32-byte symmetric key
 * @throws {EncryptionError} INVALID_KEY_SIZE if salt is not exactly 16 bytes
 *
 * @example
 * const salt = await randomBytes(16);
 * const key = await deriveKeyFromPassword("user-password", salt);
 */
export async function deriveKeyFromPassword(
  password: string,
  salt: Salt | Uint8Array
): Promise<SymmetricKey> {
  // Warn about empty passwords (once per session)
  if (password.length === 0 && !emptyPasswordWarningShown) {
    emptyPasswordWarningShown = true;
    console.warn(
      '[safecrypt] Warning: Empty password provides no security. ' +
      'Consider requiring a minimum password length in your application.'
    );
  }

  // Validate salt size (asSalt throws if not 16 bytes)
  const validatedSalt = asSalt(salt);
  
  const sodium = await getSodium();

  const key = sodium.crypto_pwhash(
    SIZES.SYMMETRIC_KEY,
    password,
    validatedSalt,
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );

  return unsafe.asSymmetricKey(key);
}

/**
 * Encrypts data with a password using Argon2id + XChaCha20-Poly1305.
 *
 * Generates a random salt and nonce internally. The returned object
 * contains all data needed for decryption (except the password).
 *
 * @param plaintext - Data to encrypt (string or Uint8Array)
 * @param password - User-provided password
 * @returns Encrypted data with version, salt, nonce, and ciphertext
 *
 * @example
 * const encrypted = await encryptWithPassword("secret data", "user-password");
 * // Store encrypted object for later decryption
 */
export async function encryptWithPassword(
  plaintext: Uint8Array | string,
  password: string
): Promise<PasswordEncryptedData> {
  const sodium = await getSodium();

  // Convert string to bytes if needed
  const data =
    typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;

  // Generate random salt and nonce
  const salt = sodium.randombytes_buf(SIZES.PASSWORD_SALT);
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

  // Derive key from password
  const key = await deriveKeyFromPassword(password, salt);

  try {
    // Encrypt using XChaCha20-Poly1305 AEAD
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      data,
      null, // no additional data
      null, // no secret nonce
      nonce,
      key
    );

    return {
      version: 1,
      salt: unsafe.asSalt(salt),
      nonce: unsafe.asNonce(nonce),
      ciphertext: unsafe.asCiphertext(ciphertext),
    };
  } finally {
    secureZero(key);
  }
}

/**
 * Decrypts data encrypted with encryptWithPassword().
 *
 * @param encrypted - Data from encryptWithPassword()
 * @param password - Same password used for encryption
 * @returns Decrypted plaintext as Uint8Array
 * @throws {EncryptionError} DECRYPTION_FAILED if password is wrong or data is corrupted
 * @throws {EncryptionError} INVALID_KEY_SIZE if salt or nonce have invalid sizes
 *
 * @example
 * const decrypted = await decryptWithPassword(encrypted, "user-password");
 * const text = new TextDecoder().decode(decrypted);
 */
export async function decryptWithPassword(
  encrypted: PasswordEncryptedData,
  password: string
): Promise<Uint8Array> {
  // Validate version
  if (!SUPPORTED_VERSIONS.includes(encrypted.version as typeof SUPPORTED_VERSIONS[number])) {
    throw unsupportedVersion(encrypted.version, [...SUPPORTED_VERSIONS]);
  }
  
  // Validate input structure
  if (encrypted.salt.length !== SIZES.PASSWORD_SALT) {
    throw invalidKeySize(encrypted.salt.length, SIZES.PASSWORD_SALT);
  }
  if (encrypted.nonce.length !== SIZES.NONCE) {
    throw invalidKeySize(encrypted.nonce.length, SIZES.NONCE);
  }
  
  const sodium = await getSodium();

  // Derive same key from password + stored salt
  const key = await deriveKeyFromPassword(password, encrypted.salt);

  try {
    const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, // no secret nonce
      encrypted.ciphertext,
      null, // no additional data
      encrypted.nonce,
      key
    );
    return plaintext;
  } catch (error) {
    throw decryptionFailed(error instanceof Error ? error : undefined);
  } finally {
    secureZero(key);
  }
}
