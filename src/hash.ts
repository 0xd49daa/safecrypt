import { getSodium } from './sodium.ts';
import { unsafe } from './branded.ts';
import type { ContentHash } from './branded.ts';
import type { StreamingHasher } from './types.ts';

export async function hash(data: Uint8Array): Promise<ContentHash> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return unsafe.asContentHash(new Uint8Array(hashBuffer));
}

export async function createHasher(): Promise<StreamingHasher> {
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

export async function hashBlake2b(
  data: Uint8Array,
  outlen: number = 32
): Promise<Uint8Array> {
  const sodium = await getSodium();
  return sodium.crypto_generichash(outlen, data);
}
