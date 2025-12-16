import { getSodium } from './sodium.ts';
import { unsafe } from './branded.ts';
import type { ContentHash } from './branded.ts';
import type { StreamingHasher } from './types.ts';

/**
 * SHA-256 hash (IPFS-compatible content addressing).
 */
export async function hash(data: Uint8Array): Promise<ContentHash> {
  // Uint8Array.from creates a new ArrayBuffer, satisfying BufferSource typing
  const copy = Uint8Array.from(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', copy);
  return unsafe.asContentHash(new Uint8Array(hashBuffer));
}

/**
 * Streaming BLAKE2b-256 hasher for large inputs.
 * Note: Uses different algorithm than hash() - do not mix.
 */
export async function createBlake2bHasher(): Promise<StreamingHasher> {
  const sodium = await getSodium();
  const state = sodium.crypto_generichash_init(null, 32);

  return {
    update(data: Uint8Array): void {
      sodium.crypto_generichash_update(state, data);
    },
    async digest(): Promise<Uint8Array> {
      return sodium.crypto_generichash_final(state, 32);
    },
  };
}

/**
 * Single-shot BLAKE2b hash with configurable output length.
 */
export async function hashBlake2b(
  data: Uint8Array,
  outlen: number = 32
): Promise<Uint8Array> {
  const sodium = await getSodium();
  return sodium.crypto_generichash(outlen, data);
}
