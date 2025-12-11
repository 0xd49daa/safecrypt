# Phase 3: Encryption — Technical Specification

## Overview

Phase 3 implements the `EncryptionProvider` with single-shot XChaCha20-Poly1305 encryption and streaming encryption via `crypto_secretstream`. This provides the core symmetric encryption capabilities for file encryption.

## Files to Implement

| File | Purpose | Dependencies |
|------|---------|--------------|
| `src/encryption.ts` | Symmetric encryption (single-shot + streaming) | sodium.ts, branded.ts, types.ts, errors.ts |

---

## 1. src/encryption.ts — EncryptionProvider

### Purpose

Provide symmetric encryption for:
- Small data (<64KB): Single-shot XChaCha20-Poly1305
- Large files: Streaming via `crypto_secretstream` with chunked AEAD

### API

```typescript
import type { SymmetricKey, Nonce, FileId, SecretstreamHeader } from './branded.ts';
import type { EncryptedData, EncryptStream, DecryptStream } from './types.ts';

export async function generateKey(): Promise<SymmetricKey>;

export async function encrypt(
  plaintext: Uint8Array,
  key: SymmetricKey,
  context?: Uint8Array
): Promise<EncryptedData>;

export async function decrypt(
  ciphertext: Uint8Array,
  nonce: Nonce,
  key: SymmetricKey,
  context?: Uint8Array
): Promise<Uint8Array>;

export async function createEncryptStream(
  key: SymmetricKey,
  fileId?: FileId
): Promise<EncryptStream>;

export async function createDecryptStream(
  key: SymmetricKey,
  header: SecretstreamHeader,
  fileId?: FileId
): Promise<DecryptStream>;
```

### Implementation Details

#### generateKey()

```typescript
import { getSodium } from './sodium.ts';
import { unsafe } from './branded.ts';
import type { SymmetricKey } from './branded.ts';

export async function generateKey(): Promise<SymmetricKey> {
  const sodium = await getSodium();
  const key = sodium.randombytes_buf(32);
  return unsafe.asSymmetricKey(key);
}
```

**CRITICAL**: Generate a unique key for EACH file. Never reuse symmetric keys.

#### encrypt(plaintext, key, context?)

```typescript
import { getSodium } from './sodium.ts';
import { unsafe } from './branded.ts';
import type { SymmetricKey } from './branded.ts';
import type { EncryptedData } from './types.ts';

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
```

**Key points**:
1. Generate random 24-byte nonce (XChaCha20 nonce space is large enough for random generation)
2. Pass `context` as AAD (Additional Authenticated Data) for context binding
3. Return `{ nonce, ciphertext }` — caller must store nonce with ciphertext

#### decrypt(ciphertext, nonce, key, context?)

```typescript
import { getSodium } from './sodium.ts';
import { decryptionFailed } from './errors.ts';
import type { SymmetricKey, Nonce } from './branded.ts';

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
```

**Key points**:
1. Throws `DECRYPTION_FAILED` on authentication failure
2. Same `context` must be provided as during encryption
3. First parameter is `null` (no secret nonce in IETF variant)

#### createEncryptStream(key, fileId?)

```typescript
import { getSodium } from './sodium.ts';
import { unsafe } from './branded.ts';
import type { SymmetricKey, FileId } from './branded.ts';
import type { EncryptStream } from './types.ts';

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
      // Best-effort state clearing - libsodium.js doesn't expose state internals
      // State object will be garbage collected
    },
  };
}
```

**Key points**:
1. Returns header (24 bytes) that must be stored for decryption
2. `push()` encrypts one chunk at a time
3. Pass `TAG_FINAL` on last chunk for truncation protection
4. `fileId` as AAD prevents chunk swapping between files (defense-in-depth)

#### createDecryptStream(key, header, fileId?)

```typescript
import { getSodium } from './sodium.ts';
import { segmentAuthFailed, streamTruncated } from './errors.ts';
import type { SymmetricKey, SecretstreamHeader, FileId } from './branded.ts';
import type { DecryptStream } from './types.ts';

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
      if (receivedFinal) {
        throw streamTruncated();
      }

      try {
        const result = sodium.crypto_secretstream_xchacha20poly1305_pull(
          state,
          encryptedChunk,
          fileId ?? null
        );

        const isFinal = result.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
        if (isFinal) {
          receivedFinal = true;
        }

        chunkIndex++;
        return { plaintext: result.message, isFinal };
      } catch (error) {
        throw segmentAuthFailed(chunkIndex, error instanceof Error ? error : undefined);
      }
    },
    dispose(): void {
      // Best-effort state clearing
    },
  };
}
```

**Key points**:
1. Initialize with header from encryption
2. `pull()` decrypts one chunk, returns plaintext + final flag
3. Throws `SEGMENT_AUTH_FAILED` on chunk authentication failure
4. Caller must verify `isFinal === true` after last chunk (or call a finalize method)

---

## 2. Wire Formats

### Single-Shot Encryption

| Component | Size |
|-----------|------|
| Nonce | 24 bytes |
| Ciphertext | plaintext.length + 16 bytes (auth tag) |

**Storage format**: Caller decides. Typical: `[nonce (24)][ciphertext (len + 16)]`

### Streaming Encryption

| Component | Size |
|-----------|------|
| Header | 24 bytes |
| Chunk overhead | 17 bytes per chunk (16-byte tag + 1-byte flag) |

**Wire format**: `[Header (24)][Chunk 0 (data + 17)]...[Chunk N with TAG_FINAL]`

**Default chunk size**: 64KB (defined in `SIZES.DEFAULT_CHUNK`)

---

## 3. Error Handling

| Scenario | Error | Code |
|----------|-------|------|
| Key not 32 bytes | `invalidKeySize()` | `INVALID_KEY_SIZE` |
| Nonce not 24 bytes | `invalidNonceSize()` | `INVALID_NONCE_SIZE` |
| Auth tag mismatch (single-shot) | `decryptionFailed()` | `DECRYPTION_FAILED` |
| Auth tag mismatch (chunk) | `segmentAuthFailed(index)` | `SEGMENT_AUTH_FAILED` |
| Missing TAG_FINAL | `streamTruncated()` | `STREAM_TRUNCATED` |
| Invalid header size | `invalidStreamHeader()` | `INVALID_STREAM_HEADER` |

---

## 4. Updates to src/index.ts

Add Phase 3 exports:

```typescript
// encryption.ts
export {
  generateKey,
  encrypt,
  decrypt,
  createEncryptStream,
  createDecryptStream,
} from './encryption.ts';
```

---

## 5. Test Requirements

### tests/encryption.test.ts

```typescript
describe('encryption', () => {
  describe('generateKey', () => {
    it('returns 32-byte SymmetricKey');
    it('generates unique keys on each call');
    it('keys are cryptographically random');
  });

  describe('encrypt/decrypt', () => {
    it('round-trips plaintext correctly');
    it('handles empty plaintext');
    it('handles large plaintext');
    it('includes context in authentication');
    it('different context fails decryption');
    it('wrong key fails with DECRYPTION_FAILED');
    it('wrong nonce fails with DECRYPTION_FAILED');
    it('tampered ciphertext fails with DECRYPTION_FAILED');
    it('generates unique nonce per encryption');
  });

  describe('createEncryptStream/createDecryptStream', () => {
    it('round-trips single chunk');
    it('round-trips multiple chunks');
    it('handles empty chunks');
    it('detects truncated stream (missing TAG_FINAL)');
    it('detects chunk reordering');
    it('detects chunk tampering with SEGMENT_AUTH_FAILED');
    it('wrong key fails authentication');
    it('wrong header fails authentication');
    it('fileId mismatch fails authentication');
    it('handles large number of chunks (100+)');
  });

  describe('security properties', () => {
    it('nonces are unique across many encryptions');
    it('keys are unique across many generations');
    it('context commitment: encrypt with A, decrypt with B fails');
    it('no plaintext leakage on auth failure');
  });
});
```

---

## 6. Implementation Order

1. **generateKey()** — Simple, no dependencies beyond sodium
2. **encrypt()** — Single-shot encryption
3. **decrypt()** — Single-shot decryption
4. **createEncryptStream()** — Streaming encryption
5. **createDecryptStream()** — Streaming decryption
6. **Update src/index.ts** — Export new functions
7. **Tests** — Comprehensive test coverage

---

## 7. Security Considerations

### Nonce Uniqueness

XChaCha20 uses 192-bit nonces. With random generation:
- Collision probability after 2^96 messages: ~50%
- Safe for billions of encryptions per key

**Rule**: Always generate fresh random nonce. Never reuse.

### Key Per File

**CRITICAL**: Each file MUST have a unique symmetric key.
- Key reuse with nonce collision → catastrophic plaintext leakage
- Key wrapping (Phase 4) handles key distribution

### AAD (Additional Authenticated Data)

- Single-shot: `context` binds encryption to purpose (e.g., "manifest", "chunk")
- Streaming: `fileId` binds chunks to specific file, preventing cross-file chunk swapping

### Memory Considerations

- libsodium.js uses WebAssembly memory, not directly accessible for wiping
- State objects cannot be securely cleared in JavaScript
- Document limitation: keys in memory are extractable by local attackers

---

## 8. libsodium Function Reference

| Operation | libsodium Function |
|-----------|-------------------|
| Key generation | `randombytes_buf(32)` |
| Nonce generation | `randombytes_buf(24)` |
| Single-shot encrypt | `crypto_aead_xchacha20poly1305_ietf_encrypt` |
| Single-shot decrypt | `crypto_aead_xchacha20poly1305_ietf_decrypt` |
| Stream init (encrypt) | `crypto_secretstream_xchacha20poly1305_init_push` |
| Stream push | `crypto_secretstream_xchacha20poly1305_push` |
| Stream init (decrypt) | `crypto_secretstream_xchacha20poly1305_init_pull` |
| Stream pull | `crypto_secretstream_xchacha20poly1305_pull` |
| Tag constants | `crypto_secretstream_xchacha20poly1305_TAG_MESSAGE`, `TAG_FINAL` |

---

## 9. Usage Examples

### Single-Shot Encryption

```typescript
import { generateKey, encrypt, decrypt } from '@filemanager/encryption';

const key = await generateKey();
const plaintext = new TextEncoder().encode('Hello, World!');

const { nonce, ciphertext } = await encrypt(plaintext, key);
const decrypted = await decrypt(ciphertext, nonce, key);

console.log(new TextDecoder().decode(decrypted)); // "Hello, World!"
```

### Streaming Encryption

```typescript
import { generateKey, createEncryptStream, createDecryptStream } from '@filemanager/encryption';
import { asSecretstreamHeader } from '@filemanager/encryption';

const key = await generateKey();
const chunks = [chunk1, chunk2, chunk3]; // Uint8Array[]

// Encrypt
const encryptStream = await createEncryptStream(key);
const header = encryptStream.header;
const encryptedChunks = chunks.map((chunk, i) =>
  encryptStream.push(chunk, i === chunks.length - 1)
);
encryptStream.dispose();

// Decrypt
const decryptStream = await createDecryptStream(key, header);
const decryptedChunks: Uint8Array[] = [];
for (const encChunk of encryptedChunks) {
  const { plaintext, isFinal } = decryptStream.pull(encChunk);
  decryptedChunks.push(plaintext);
  if (isFinal) break;
}
decryptStream.dispose();
```

---

## 10. Known Limitations

### State Disposal

`dispose()` on streams is best-effort. JavaScript cannot guarantee memory clearing:
- WebAssembly memory is managed by the runtime
- Garbage collection timing is unpredictable
- State remains in memory until GC runs

### Streaming Memory

Each stream maintains internal state (~100 bytes). For many concurrent streams, memory usage scales linearly.

### Browser Main Thread

For files >10MB, encryption should run in Web Worker to prevent UI blocking. This library provides primitives; worker orchestration is caller's responsibility.
