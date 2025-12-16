import { getSodium } from './sodium.ts';
import { unsafe, asSymmetricKey, asNonce, asSecretstreamHeader } from './branded.ts';
import { decryptionFailed, segmentAuthFailed, streamTruncated } from './errors.ts';
import { secureZero } from './memory.ts';
import type { SymmetricKey, Nonce, FileId, SecretstreamHeader } from './branded.ts';
import type { EncryptedData, EncryptStream, DecryptStream } from './types.ts';

export async function generateKey(): Promise<SymmetricKey> {
  const sodium = await getSodium();
  const key = sodium.randombytes_buf(32);
  return unsafe.asSymmetricKey(key);
}

export async function encrypt(
  plaintext: Uint8Array,
  key: SymmetricKey,
  context?: Uint8Array
): Promise<EncryptedData> {
  asSymmetricKey(key); // Runtime validation
  const sodium = await getSodium();
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    context ?? null,
    null,
    nonce,
    key
  );

  return {
    nonce: unsafe.asNonce(nonce),
    ciphertext: unsafe.asCiphertext(ciphertext),
  };
}

export async function decrypt(
  ciphertext: Uint8Array,
  nonce: Nonce,
  key: SymmetricKey,
  context?: Uint8Array
): Promise<Uint8Array> {
  asNonce(nonce); // Runtime validation
  asSymmetricKey(key); // Runtime validation
  const sodium = await getSodium();

  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      context ?? null,
      nonce,
      key
    );
  } catch (error) {
    throw decryptionFailed(error instanceof Error ? error : undefined);
  }
}

export async function createEncryptStream(
  key: SymmetricKey,
  fileId?: FileId
): Promise<EncryptStream> {
  asSymmetricKey(key); // Runtime validation
  const sodium = await getSodium();
  const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  // Keep internal copy for zeroization; return copies to callers
  const internalHeader = new Uint8Array(header);

  return {
    // Return a copy so internal header can be zeroed without affecting callers
    get header(): SecretstreamHeader {
      return unsafe.asSecretstreamHeader(new Uint8Array(internalHeader));
    },
    push(chunk: Uint8Array, isFinal: boolean): Uint8Array {
      const tag = isFinal
        ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;

      return sodium.crypto_secretstream_xchacha20poly1305_push(
        state,
        chunk,
        fileId ?? null,
        tag
      );
    },
    dispose(): void {
      // Best-effort zeroization of accessible buffers.
      // Note: The secretstream state lives in WASM linear memory and cannot
      // be directly zeroed from JS. It will be garbage collected.
      sodium.memzero(internalHeader);
    },
  };
}

export async function createDecryptStream(
  key: SymmetricKey,
  header: SecretstreamHeader,
  fileId?: FileId
): Promise<DecryptStream> {
  asSymmetricKey(key); // Runtime validation
  asSecretstreamHeader(header); // Runtime validation
  const sodium = await getSodium();
  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
  let chunkIndex = 0;
  let receivedFinal = false;
  let errorOccurred = false;
  let finalizeCalled = false;

  return {
    pull(encryptedChunk: Uint8Array): { plaintext: Uint8Array; isFinal: boolean } {
      let result;
      try {
        result = sodium.crypto_secretstream_xchacha20poly1305_pull(
          state,
          encryptedChunk,
          fileId ?? null
        );
      } catch (error) {
        // libsodium throws TypeError for malformed input (e.g., truncated chunks)
        errorOccurred = true;
        throw segmentAuthFailed(chunkIndex, error instanceof Error ? error : undefined);
      }

      // libsodium returns false on authentication failure
      if (!result) {
        errorOccurred = true;
        throw segmentAuthFailed(chunkIndex);
      }

      const isFinal = result.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
      if (isFinal) {
        receivedFinal = true;
      }
      chunkIndex++;

      return { plaintext: result.message, isFinal };
    },
    finalize(): void {
      finalizeCalled = true;
      if (!receivedFinal) {
        throw streamTruncated();
      }
    },
    dispose(): void {
      // Fail-safe: Ensure truncation is detected even if caller forgets finalize()
      // Skip check if:
      // - finalize() was already called (user explicitly checked)
      // - an error already occurred (caller already knows stream is invalid)
      if (!receivedFinal && !finalizeCalled && !errorOccurred) {
        throw streamTruncated();
      }
      // Note: The secretstream state lives in WASM linear memory and cannot
      // be directly zeroed from JS. It will be garbage collected.
      // The header parameter is owned by the caller and not zeroed here.
    },
  };
}
