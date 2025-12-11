import { getSodium } from './sodium.ts';

/**
 * Attempt to zero out sensitive data in memory.
 *
 * @security This function provides best-effort memory clearing.
 * In JavaScript/WASM environments, secure memory clearing cannot
 * be guaranteed due to:
 * - Garbage collector may copy data before clearing
 * - JIT optimizer may elide the clearing operation
 * - String interning may retain copies
 *
 * For high-security applications, consider native implementations.
 */
export function secureZero(bytes: Uint8Array): void {
  bytes.fill(0);
}

/**
 * Constant-time comparison of two byte arrays.
 * Prevents timing side-channel attacks.
 */
export async function constantTimeEqual(a: Uint8Array, b: Uint8Array): Promise<boolean> {
  if (a.length !== b.length) {
    return false;
  }
  const sodium = await getSodium();
  return sodium.memcmp(a, b);
}

/**
 * Fill array with cryptographically secure random bytes.
 */
export async function randomFill(bytes: Uint8Array): Promise<void> {
  const sodium = await getSodium();
  const random = sodium.randombytes_buf(bytes.length);
  bytes.set(random);
}

/**
 * Generate new array of cryptographically secure random bytes.
 */
export async function randomBytes(length: number): Promise<Uint8Array> {
  const sodium = await getSodium();
  return sodium.randombytes_buf(length);
}

/**
 * Execute callback with a temporary buffer that's zeroed after use.
 */
export async function withSecureBuffer<T>(
  size: number,
  fn: (buffer: Uint8Array) => T | Promise<T>
): Promise<T> {
  const buffer = new Uint8Array(size);
  try {
    return await fn(buffer);
  } finally {
    secureZero(buffer);
  }
}
