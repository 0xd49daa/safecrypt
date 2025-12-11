import { getSodium } from './sodium.ts';
import { unsafe } from './branded.ts';
import { decryptionFailed, segmentAuthFailed, streamTruncated, EncryptionError } from './errors.ts';
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
  const sodium = await getSodium();
  const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);

  return {
    header: unsafe.asSecretstreamHeader(header),
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
      // Best-effort: state will be garbage collected
    },
  };
}

export async function createDecryptStream(
  key: SymmetricKey,
  header: SecretstreamHeader,
  fileId?: FileId
): Promise<DecryptStream> {
  const sodium = await getSodium();
  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
  let chunkIndex = 0;
  let receivedFinal = false;

  return {
    pull(encryptedChunk: Uint8Array): { plaintext: Uint8Array; isFinal: boolean } {
      try {
        const result = sodium.crypto_secretstream_xchacha20poly1305_pull(
          state,
          encryptedChunk,
          fileId ?? null
        );

        if (result === false) {
          throw segmentAuthFailed(chunkIndex);
        }

        const isFinal = result.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
        if (isFinal) {
          receivedFinal = true;
        }
        chunkIndex++;

        return { plaintext: result.message, isFinal };
      } catch (error) {
        if (error instanceof EncryptionError) {
          throw error;
        }
        throw segmentAuthFailed(chunkIndex, error instanceof Error ? error : undefined);
      }
    },
    finalize(): void {
      if (!receivedFinal) {
        throw streamTruncated();
      }
    },
    dispose(): void {
      // Best-effort: state will be garbage collected
    },
  };
}
