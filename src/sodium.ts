import type libsodium from 'libsodium-wrappers';

let sodiumInstance: typeof libsodium | null = null;
let initPromise: Promise<typeof libsodium> | null = null;

async function initializeSodium(): Promise<typeof libsodium> {
  const sodium = await import('libsodium-wrappers');
  await sodium.default.ready;
  sodiumInstance = sodium.default;
  return sodiumInstance;
}

export async function getSodium(): Promise<typeof libsodium> {
  if (sodiumInstance) {
    return sodiumInstance;
  }
  if (!initPromise) {
    initPromise = initializeSodium();
  }
  return initPromise;
}

export async function preloadSodium(): Promise<void> {
  await getSodium();
}
