# Web Worker Example

This example demonstrates offloading cryptographic operations to a Web Worker to prevent UI blocking for large files (>10MB).

## Usage

### Direct API (Same Thread)

For simplicity or when Web Workers are not needed:

```typescript
import { workerAPI, shouldUseWorker } from '@filemanager/encryption/examples/worker';
import { generateKey, createEncryptStream } from '@filemanager/encryption';

async function encryptFile(file: File) {
  const plaintext = new Uint8Array(await file.arrayBuffer());

  if (shouldUseWorker(file.size)) {
    // Large file: use worker API
    const result = await workerAPI.encryptFile({ plaintext });
    return {
      key: result.key,
      header: result.header,
      ciphertext: result.ciphertext,
      hash: result.hash,
    };
  }

  // Small file: direct encryption
  const key = await generateKey();
  // ... direct encryption logic
}
```

### With Comlink (Separate Thread)

For actual Web Worker usage with Comlink:

```typescript
// worker.ts
import * as Comlink from 'comlink';
import { workerAPI } from '@filemanager/encryption/examples/worker';

Comlink.expose(workerAPI);
```

```typescript
// main.ts
import * as Comlink from 'comlink';
import type { CryptoWorkerAPI } from '@filemanager/encryption/examples/worker';

const worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' });
const api = Comlink.wrap<CryptoWorkerAPI>(worker);

// Preload during app initialization
await api.preload();

// Encrypt file in worker
const result = await api.encryptFile({ plaintext });
```

## Architecture

```
┌─────────────────┐     Comlink      ┌─────────────────┐
│   Main Thread   │ ←───────────────→ │   Web Worker    │
│                 │    (postMessage)  │                 │
│  - UI rendering │                   │  - Encryption   │
│  - File I/O     │                   │  - Decryption   │
│  - User events  │                   │  - Key derive   │
│                 │                   │  - Hashing      │
└─────────────────┘                   └─────────────────┘
```

## API Reference

### encryptFile(request)

Encrypts plaintext using streaming encryption.

```typescript
type EncryptFileRequest = {
  plaintext: Uint8Array;
  fileId?: FileId;        // Optional AAD for defense-in-depth
};

type EncryptFileResponse = {
  key: SymmetricKey;      // Generated encryption key
  header: SecretstreamHeader;
  ciphertext: Uint8Array;
  hash: ContentHash;      // SHA-256 of plaintext
};
```

### decryptFile(request)

Decrypts ciphertext using streaming decryption.

```typescript
type DecryptFileRequest = {
  key: SymmetricKey;
  header: SecretstreamHeader;
  ciphertext: Uint8Array;
  fileId?: FileId;
};

type DecryptFileResponse = {
  plaintext: Uint8Array;
  hash: ContentHash;      // SHA-256 of plaintext
};
```

### wrapKeySeal(request)

Wraps a symmetric key using anonymous sealed box (self-encryption).

```typescript
type WrapKeySealRequest = {
  key: SymmetricKey;
  recipientPublicKey: X25519PublicKey;
};

type WrapKeySealResponse = {
  sealed: Uint8Array;     // 80 bytes
};
```

### wrapKeyAuthenticated(request)

Wraps a symmetric key with sender authentication (sharing).

```typescript
type WrapKeyAuthenticatedRequest = {
  key: SymmetricKey;
  recipientPublicKey: X25519PublicKey;
  senderKeyPair: X25519KeyPair;
};

type WrapKeyAuthenticatedResponse = {
  wrapped: AuthenticatedWrappedKey;
};
```

### deriveKeys(request)

Derives encryption keys from a BIP-39 mnemonic. The seed is derived internally and zeroized after use; only the derived keypair is returned.

```typescript
type DeriveKeysRequest = {
  mnemonic: string;
  passphrase?: string;
  encryptionIndex: number;
};

type DeriveKeysResponse = {
  encryptionKeyPair: X25519KeyPair;
};
```

### preload()

Preloads libsodium WASM module. Call during app initialization for faster first operation.

## When to Use Worker

| File Size | Recommendation |
|-----------|----------------|
| < 1MB | Main thread (overhead not worth it) |
| 1-10MB | Main thread (usually fast enough) |
| > 10MB | **Worker** (prevents UI jank) |
| > 100MB | Worker + progress reporting |

## Performance Characteristics

- **Worker startup**: ~50ms (WASM initialization)
- **Message passing overhead**: ~1-5ms per call
- **Encryption throughput**: ~100-200 MB/s (depends on hardware)

## Chunk Size

Default chunk size is 64KB, which provides a good balance between:
- Memory usage (peak ~128KB for 64KB chunks)
- Performance (minimal overhead per chunk)
- Progress granularity (can report every 64KB)

## Limitations

1. **No SharedArrayBuffer**: Data is copied between threads via structured clone
2. **Memory overhead**: Both threads hold data during transfer
3. **No streaming to worker**: Entire file must be loaded before encryption

## Dependencies

For Comlink integration:

```bash
bun add comlink
```

## Example: Full Flow

```typescript
import { workerAPI } from '@filemanager/encryption/examples/worker';
import { unwrapKeySeal } from '@filemanager/encryption';

// 1. Derive keys from mnemonic
const { encryptionKeyPair } = await workerAPI.deriveKeys({
  mnemonic: 'your 24-word mnemonic...',
  encryptionIndex: 0,
});

// 2. Encrypt file
const fileBuffer = await file.arrayBuffer();
const { key, header, ciphertext, hash } = await workerAPI.encryptFile({
  plaintext: new Uint8Array(fileBuffer),
});

// 3. Wrap key for storage
const { sealed } = await workerAPI.wrapKeySeal({
  key,
  recipientPublicKey: encryptionKeyPair.publicKey,
});

// 4. Store: header, ciphertext, sealed, hash

// 5. Later: decrypt
const unwrappedKey = await unwrapKeySeal(sealed, encryptionKeyPair);
const { plaintext } = await workerAPI.decryptFile({
  key: unwrappedKey,
  header,
  ciphertext,
});
```
