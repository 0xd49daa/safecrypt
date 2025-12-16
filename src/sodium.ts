import type libsodium from 'libsodium-wrappers';

let sodiumInstance: typeof libsodium | null = null;
let initPromise: Promise<typeof libsodium> | null = null;

async function initializeSodium(): Promise<typeof libsodium> {
  const sodium = await import('libsodium-wrappers');
  await sodium.default.ready;
  sodiumInstance = sodium.default;
  return sodiumInstance;
}

/**
 * Gets the initialized libsodium instance (lazy initialization).
 * @returns Initialized libsodium instance
 */
export async function getSodium(): Promise<typeof libsodium> {
  if (sodiumInstance) {
    return sodiumInstance;
  }
  if (!initPromise) {
    initPromise = initializeSodium();
  }
  return initPromise;
}

/**
 * Get the sodium instance synchronously if already initialized.
 * Returns null if sodium hasn't been initialized yet.
 */
export function getSodiumSync(): typeof libsodium | null {
  return sodiumInstance;
}

/**
 * Preloads libsodium WASM module. Call during app startup to avoid latency on first crypto operation.
 */
export async function preloadSodium(): Promise<void> {
  await getSodium();
}
