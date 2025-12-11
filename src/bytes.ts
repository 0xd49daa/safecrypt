import { invalidBase64 } from './errors';

const HEX_CHARS = '0123456789abcdef';

/**
 * Concatenate multiple Uint8Arrays into one.
 */
export function concat(...arrays: readonly Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Convert bytes to lowercase hex string.
 */
export function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i]!;
    hex += HEX_CHARS[byte >> 4];
    hex += HEX_CHARS[byte & 0x0f];
  }
  return hex;
}

/**
 * Parse hex string to bytes.
 * @throws Error if invalid hex
 */
export function fromHex(hex: string): Uint8Array {
  let normalizedHex = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  normalizedHex = normalizedHex.toLowerCase();

  if (normalizedHex.length % 2 !== 0) {
    throw new Error('Invalid hex string: odd length');
  }

  const bytes = new Uint8Array(normalizedHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const high = HEX_CHARS.indexOf(normalizedHex[i * 2]!);
    const low = HEX_CHARS.indexOf(normalizedHex[i * 2 + 1]!);
    if (high === -1 || low === -1) {
      throw new Error('Invalid hex string: invalid character');
    }
    bytes[i] = (high << 4) | low;
  }
  return bytes;
}

/**
 * Convert bytes to base64 string.
 */
export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

/**
 * Parse base64 string to bytes.
 * @throws EncryptionError with INVALID_BASE64 if input is not valid base64
 */
export function fromBase64(base64: string): Uint8Array {
  const decoded = Buffer.from(base64, 'base64');
  const reencoded = decoded.toString('base64');
  if (reencoded !== base64) {
    throw invalidBase64();
  }
  return new Uint8Array(decoded);
}

/**
 * Convert bytes to URL-safe base64 string (no padding).
 */
export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Parse URL-safe base64 string to bytes.
 * @throws Error if invalid base64url
 */
export function fromBase64Url(base64url: string): Uint8Array {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padding = (4 - (base64.length % 4)) % 4;
  base64 += '='.repeat(padding);
  return fromBase64(base64);
}

/**
 * Check if two byte arrays are equal.
 *
 * @warning NOT CONSTANT-TIME - DO NOT use for comparing secrets (keys, MACs, etc.)
 * This function uses early-return comparison which leaks timing information.
 * For secret comparison, use `constantTimeEqual` from memory.ts instead.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Create a copy of a byte array.
 */
export function copy(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

/**
 * Create a view into a byte array (no copy).
 */
export function slice(bytes: Uint8Array, start: number, length: number): Uint8Array {
  return new Uint8Array(bytes.buffer, bytes.byteOffset + start, length);
}
