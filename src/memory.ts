import { getSodium, getSodiumSync } from './sodium.ts';

/**
 * Attempt to zero out sensitive data in memory.
 *
 * Uses libsodium's memzero() when available, which is designed to resist
 * compiler optimizations that might elide the clearing operation.
 *
 * @security This function provides best-effort memory clearing.
 * In JavaScript/WASM environments, secure memory clearing cannot
 * be fully guaranteed due to:
 * - Garbage collector may have copied data before clearing
 * - JIT optimizer may create copies during optimization
 * - String interning may retain copies of converted data
 *
 * For high-security applications, consider native implementations.
 */
export function secureZero(bytes: Uint8Array): void {
  const sodium = getSodiumSync();
  if (sodium) {
    sodium.memzero(bytes);
  } else {
    // Fallback if sodium not yet initialized (should be rare)
    bytes.fill(0);
  }
}

/**
 * Async version that guarantees sodium.memzero() is used.
 */
export async function secureZeroAsync(bytes: Uint8Array): Promise<void> {
  const sodium = await getSodium();
  sodium.memzero(bytes);
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
  sodium.memzero(random);
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
