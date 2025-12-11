import {
  generateKey,
  createEncryptStream,
  createDecryptStream,
  hash,
  wrapKeySeal as wrapKeySealFn,
  wrapKeyAuthenticated as wrapKeyAuthenticatedFn,
  deriveSeed,
  deriveEncryptionKeyPair,
  preloadSodium,
  asContentHash,
  secureZero,
} from '../../src/index.ts';
import type {
  CryptoWorkerAPI,
  EncryptFileRequest,
  EncryptFileResponse,
  DecryptFileRequest,
  DecryptFileResponse,
  WrapKeySealRequest,
  WrapKeySealResponse,
  WrapKeyAuthenticatedRequest,
  WrapKeyAuthenticatedResponse,
  DeriveKeysRequest,
  DeriveKeysResponse,
} from './types.ts';

const DEFAULT_CHUNK_SIZE = 64 * 1024;
const CHUNK_OVERHEAD = 17;

async function encryptFile(request: EncryptFileRequest): Promise<EncryptFileResponse> {
  const { plaintext, fileId } = request;

  const key = await generateKey();
  const stream = await createEncryptStream(key, fileId);

  const chunks: Uint8Array[] = [];
  let offset = 0;

  while (offset < plaintext.length) {
    const end = Math.min(offset + DEFAULT_CHUNK_SIZE, plaintext.length);
    const chunk = plaintext.subarray(offset, end);
    const isLast = end === plaintext.length;
    const encrypted = stream.push(chunk, isLast);
    chunks.push(encrypted);
    offset = end;
  }

  stream.dispose();

  const ciphertext = concatenateChunks(chunks);
  const plaintextHash = await hash(plaintext);

  return {
    key,
    header: stream.header,
    ciphertext,
    hash: asContentHash(plaintextHash),
  };
}

async function decryptFile(request: DecryptFileRequest): Promise<DecryptFileResponse> {
  const { key, header, ciphertext, fileId } = request;

  const stream = await createDecryptStream(key, header, fileId);
  const encryptedChunkSize = DEFAULT_CHUNK_SIZE + CHUNK_OVERHEAD;

  const chunks: Uint8Array[] = [];
  let offset = 0;

  while (offset < ciphertext.length) {
    const remainingBytes = ciphertext.length - offset;
    const chunkSize = Math.min(encryptedChunkSize, remainingBytes);
    const chunk = ciphertext.subarray(offset, offset + chunkSize);
    const { plaintext: decrypted } = stream.pull(chunk);
    chunks.push(decrypted);
    offset += chunkSize;
  }

  stream.finalize();
  stream.dispose();

  const plaintext = concatenateChunks(chunks);
  const plaintextHash = await hash(plaintext);

  return {
    plaintext,
    hash: asContentHash(plaintextHash),
  };
}

async function wrapKeySeal(request: WrapKeySealRequest): Promise<WrapKeySealResponse> {
  const { key, recipientPublicKey } = request;
  const sealed = await wrapKeySealFn(key, recipientPublicKey);
  return { sealed };
}

async function wrapKeyAuthenticated(
  request: WrapKeyAuthenticatedRequest
): Promise<WrapKeyAuthenticatedResponse> {
  const { key, recipientPublicKey, senderKeyPair } = request;
  const wrapped = await wrapKeyAuthenticatedFn(key, recipientPublicKey, senderKeyPair);
  return { wrapped };
}

async function deriveKeys(request: DeriveKeysRequest): Promise<DeriveKeysResponse> {
  const { mnemonic, passphrase, encryptionIndex } = request;

  const seed = await deriveSeed(mnemonic, passphrase);
  const encryptionKeyPair = await deriveEncryptionKeyPair(seed, encryptionIndex);
  secureZero(seed);

  return {
    encryptionKeyPair,
  };
}

async function preload(): Promise<void> {
  await preloadSodium();
}

function concatenateChunks(chunks: Uint8Array[]): Uint8Array {
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

export const workerAPI: CryptoWorkerAPI = {
  encryptFile,
  decryptFile,
  wrapKeySeal,
  wrapKeyAuthenticated,
  deriveKeys,
  preload,
};

export type { CryptoWorkerAPI };
