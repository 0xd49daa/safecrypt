import { describe, expect, test } from 'bun:test';
import {
  deriveKeyFromPassword,
  encryptWithPassword,
  decryptWithPassword,
} from '../src/password.ts';
import { randomBytes } from '../src/memory.ts';
import { toHex } from '../src/bytes.ts';
import { ErrorCode } from '../src/errors.ts';
import { SIZES } from '../src/types.ts';

describe('deriveKeyFromPassword', () => {
  test('returns 32-byte SymmetricKey', async () => {
    const salt = await randomBytes(SIZES.PASSWORD_SALT);
    const key = await deriveKeyFromPassword('test-password', salt);
    expect(key.length).toBe(SIZES.SYMMETRIC_KEY);
  });

  test('same password + salt produces same key (deterministic)', async () => {
    const salt = await randomBytes(SIZES.PASSWORD_SALT);
    const key1 = await deriveKeyFromPassword('test-password', salt);
    const key2 = await deriveKeyFromPassword('test-password', salt);
    expect(toHex(key1)).toBe(toHex(key2));
  });

  test('different salt produces different key', async () => {
    const salt1 = await randomBytes(SIZES.PASSWORD_SALT);
    const salt2 = await randomBytes(SIZES.PASSWORD_SALT);
    const key1 = await deriveKeyFromPassword('test-password', salt1);
    const key2 = await deriveKeyFromPassword('test-password', salt2);
    expect(toHex(key1)).not.toBe(toHex(key2));
  });

  test('different password produces different key', async () => {
    const salt = await randomBytes(SIZES.PASSWORD_SALT);
    const key1 = await deriveKeyFromPassword('password1', salt);
    const key2 = await deriveKeyFromPassword('password2', salt);
    expect(toHex(key1)).not.toBe(toHex(key2));
  });

  test('handles empty password', async () => {
    const salt = await randomBytes(SIZES.PASSWORD_SALT);
    const key = await deriveKeyFromPassword('', salt);
    expect(key.length).toBe(SIZES.SYMMETRIC_KEY);
  });

  test('handles unicode password', async () => {
    const salt = await randomBytes(SIZES.PASSWORD_SALT);
    const key = await deriveKeyFromPassword('pässwörd-', salt);
    expect(key.length).toBe(SIZES.SYMMETRIC_KEY);
  });

  test('throws INVALID_KEY_SIZE for wrong salt size', async () => {
    const wrongSalt = new Uint8Array(8); // Wrong size, should be 16
    await expect(deriveKeyFromPassword('password', wrongSalt)).rejects.toMatchObject({
      code: ErrorCode.INVALID_KEY_SIZE,
    });
  });
});

describe('encryptWithPassword', () => {
  test('round-trips string plaintext', async () => {
    const plaintext = 'Hello, World!';
    const password = 'test-password';

    const encrypted = await encryptWithPassword(plaintext, password);
    const decrypted = await decryptWithPassword(encrypted, password);

    expect(new TextDecoder().decode(decrypted)).toBe(plaintext);
  });

  test('round-trips Uint8Array plaintext', async () => {
    const plaintext = new Uint8Array([1, 2, 3, 4, 5]);
    const password = 'test-password';

    const encrypted = await encryptWithPassword(plaintext, password);
    const decrypted = await decryptWithPassword(encrypted, password);

    expect(Array.from(decrypted)).toEqual([1, 2, 3, 4, 5]);
  });

  test('handles empty plaintext', async () => {
    const plaintext = new Uint8Array(0);
    const password = 'test-password';

    const encrypted = await encryptWithPassword(plaintext, password);
    const decrypted = await decryptWithPassword(encrypted, password);

    expect(decrypted.length).toBe(0);
  });

  test('handles empty string plaintext', async () => {
    const plaintext = '';
    const password = 'test-password';

    const encrypted = await encryptWithPassword(plaintext, password);
    const decrypted = await decryptWithPassword(encrypted, password);

    expect(new TextDecoder().decode(decrypted)).toBe('');
  });

  test('handles large plaintext', async () => {
    const plaintext = new Uint8Array(100_000).fill(0x42);
    const password = 'test-password';

    const encrypted = await encryptWithPassword(plaintext, password);
    const decrypted = await decryptWithPassword(encrypted, password);

    expect(decrypted.length).toBe(100_000);
    expect(decrypted.every((b) => b === 0x42)).toBe(true);
  });

  test('version is always 1', async () => {
    const encrypted = await encryptWithPassword('test', 'password');
    expect(encrypted.version).toBe(1);
  });

  test('salt is 16 bytes', async () => {
    const encrypted = await encryptWithPassword('test', 'password');
    expect(encrypted.salt.length).toBe(SIZES.PASSWORD_SALT);
  });

  test('nonce is 24 bytes', async () => {
    const encrypted = await encryptWithPassword('test', 'password');
    expect(encrypted.nonce.length).toBe(SIZES.NONCE);
  });

  test('ciphertext is plaintext length + 16 bytes (auth tag)', async () => {
    const plaintext = 'test data here';
    const encrypted = await encryptWithPassword(plaintext, 'password');
    const expectedLength = new TextEncoder().encode(plaintext).length + SIZES.AUTH_TAG;
    expect(encrypted.ciphertext.length).toBe(expectedLength);
  });

  test('generates unique salt per encryption', async () => {
    const salts = new Set<string>();

    // Reduced iterations due to Argon2id's intentional slowness (~100ms each)
    for (let i = 0; i < 10; i++) {
      const encrypted = await encryptWithPassword('test', 'password');
      salts.add(toHex(encrypted.salt));
    }

    expect(salts.size).toBe(10);
  });

  test('generates unique nonce per encryption', async () => {
    const nonces = new Set<string>();

    // Reduced iterations due to Argon2id's intentional slowness (~100ms each)
    for (let i = 0; i < 10; i++) {
      const encrypted = await encryptWithPassword('test', 'password');
      nonces.add(toHex(encrypted.nonce));
    }

    expect(nonces.size).toBe(10);
  });
});

describe('decryptWithPassword', () => {
  test('wrong password throws DECRYPTION_FAILED', async () => {
    const encrypted = await encryptWithPassword('secret', 'correct-password');

    await expect(decryptWithPassword(encrypted, 'wrong-password')).rejects.toMatchObject({
      code: ErrorCode.DECRYPTION_FAILED,
    });
  });

  test('tampered ciphertext throws DECRYPTION_FAILED', async () => {
    const encrypted = await encryptWithPassword('secret', 'password');

    // Tamper with ciphertext
    const tampered = {
      ...encrypted,
      ciphertext: new Uint8Array(encrypted.ciphertext),
    };
    tampered.ciphertext[0] = tampered.ciphertext[0]! ^ 0xff;

    await expect(decryptWithPassword(tampered, 'password')).rejects.toMatchObject({
      code: ErrorCode.DECRYPTION_FAILED,
    });
  });

  test('tampered salt produces wrong key and fails decryption', async () => {
    const encrypted = await encryptWithPassword('secret', 'password');

    // Tamper with salt
    const tampered = {
      ...encrypted,
      salt: new Uint8Array(encrypted.salt),
    };
    tampered.salt[0] = tampered.salt[0]! ^ 0xff;

    await expect(decryptWithPassword(tampered, 'password')).rejects.toMatchObject({
      code: ErrorCode.DECRYPTION_FAILED,
    });
  });

  test('tampered nonce fails decryption', async () => {
    const encrypted = await encryptWithPassword('secret', 'password');

    // Tamper with nonce
    const tampered = {
      ...encrypted,
      nonce: new Uint8Array(encrypted.nonce),
    };
    tampered.nonce[0] = tampered.nonce[0]! ^ 0xff;

    await expect(decryptWithPassword(tampered, 'password')).rejects.toMatchObject({
      code: ErrorCode.DECRYPTION_FAILED,
    });
  });

  test('invalid salt size throws INVALID_KEY_SIZE', async () => {
    const encrypted = await encryptWithPassword('secret', 'password');

    // Use wrong salt size
    const tampered = {
      ...encrypted,
      salt: new Uint8Array(8), // Wrong size
    };

    await expect(decryptWithPassword(tampered, 'password')).rejects.toMatchObject({
      code: ErrorCode.INVALID_KEY_SIZE,
    });
  });

  test('invalid nonce size throws INVALID_KEY_SIZE', async () => {
    const encrypted = await encryptWithPassword('secret', 'password');

    // Use wrong nonce size
    const tampered = {
      ...encrypted,
      nonce: new Uint8Array(12), // Wrong size
    };

    await expect(decryptWithPassword(tampered, 'password')).rejects.toMatchObject({
      code: ErrorCode.INVALID_KEY_SIZE,
    });
  });

  test('unsupported version throws UNSUPPORTED_VERSION', async () => {
    const encrypted = await encryptWithPassword('secret', 'password');

    const tampered = {
      ...encrypted,
      version: 99 as const,
    };

    await expect(decryptWithPassword(tampered as any, 'password')).rejects.toMatchObject({
      code: ErrorCode.UNSUPPORTED_VERSION,
    });
  });
});

describe('security properties', () => {
  test('same plaintext + password produces different ciphertext each time', async () => {
    const ciphertexts = new Set<string>();

    // Reduced iterations due to Argon2id's intentional slowness (~100ms each)
    for (let i = 0; i < 5; i++) {
      const encrypted = await encryptWithPassword('same data', 'same password');
      ciphertexts.add(toHex(encrypted.ciphertext));
    }

    // Each encryption should produce unique ciphertext due to random salt + nonce
    expect(ciphertexts.size).toBe(5);
  });

  test('handles passwords with special characters', async () => {
    const specialPasswords = [
      'p@$$w0rd!',
      '  spaces  ',
      '\t\n\r',
      '12345678901234567890',
      'a'.repeat(1000), // Very long password
    ];

    for (const password of specialPasswords) {
      const encrypted = await encryptWithPassword('test', password);
      const decrypted = await decryptWithPassword(encrypted, password);
      expect(new TextDecoder().decode(decrypted)).toBe('test');
    }
  });
});
