# Phase 5: Export, Testing & Web Worker — Technical Specification

## Overview

Phase 5 finalizes the library with comprehensive public exports, integration/security tests, and a Web Worker example for large file processing. This phase ensures the library is production-ready and provides patterns for browser integration.

**Deliverables:**
- **src/index.ts** — Complete public API exports (already implemented)
- **tests/integration/** — End-to-end encryption flows
- **tests/security/** — Attack vector coverage
- **examples/worker/** — Web Worker implementation for >10MB files

## Files to Implement

| File | Purpose | Dependencies |
|------|---------|--------------|
| `tests/integration/file-encryption.test.ts` | Full file encrypt/decrypt flows | All modules |
| `tests/integration/key-sharing.test.ts` | Multi-user key sharing flows | key-wrapping, key-derivation |
| `tests/integration/recovery.test.ts` | Mnemonic recovery scenarios | key-derivation, encryption |
| `tests/security/nonce-safety.test.ts` | Nonce uniqueness verification | encryption |
| `tests/security/context-commitment.test.ts` | AAD binding tests | encryption |
| `tests/security/stream-integrity.test.ts` | Chunk reordering/truncation | encryption |
| `tests/security/timing-attacks.test.ts` | Constant-time verification | memory |
| `examples/worker/crypto.worker.ts` | Comlink-based crypto worker | All modules |
| `examples/worker/index.ts` | Main thread API | crypto.worker.ts |
| `examples/worker/types.ts` | Shared types | — |

---

## 1. Public Exports (src/index.ts) ✅

The public API is already implemented. For reference, the complete export structure:

### Error Handling
```typescript
export {
  ErrorCode,
  EncryptionError,
  invalidKeySize,
  invalidNonceSize,
  decryptionFailed,
  segmentAuthFailed,
  streamTruncated,
  invalidStreamHeader,
  invalidMnemonic,
  senderMismatch,
} from './errors.ts';
```

### Type Definitions
```typescript
export type {
  EncryptedData,
  StreamHeader,
  KeyPair,
  X25519KeyPair,
  Ed25519KeyPair,
  SealedBox,
  AuthenticatedWrappedKey,
  MultiRecipientWrappedKey,
  EncryptStream,
  DecryptStream,
  StreamingHasher,
  KdfContext,
} from './types.ts';

export { SIZES } from './types.ts';
```

### Branded Types + Type Guards
```typescript
export type {
  SymmetricKey,
  Nonce,
  Ciphertext,
  FileId,
  SecretstreamHeader,
  X25519PublicKey,
  X25519PrivateKey,
  Ed25519PublicKey,
  Ed25519PrivateKey,
  ContentHash,
  Seed,
} from './branded.ts';

export {
  asSymmetricKey,
  asNonce,
  asCiphertext,
  asFileId,
  asSecretstreamHeader,
  asX25519PublicKey,
  asX25519PrivateKey,
  asEd25519PublicKey,
  asEd25519PrivateKey,
  asContentHash,
  asSeed,
  unsafe,
} from './branded.ts';
```

### Utilities
```typescript
// Byte utilities
export {
  concat,
  toHex,
  fromHex,
  toBase64,
  fromBase64,
  toBase64Url,
  fromBase64Url,
  equals,
  copy,
  slice,
} from './bytes.ts';

// Memory utilities
export {
  secureZero,
  constantTimeEqual,
  randomFill,
  randomBytes,
  withSecureBuffer,
} from './memory.ts';

// Sodium initialization
export { getSodium, preloadSodium } from './sodium.ts';
```

### Core Providers
```typescript
// Hashing
export { hash, createHasher, hashBlake2b } from './hash.ts';

// Key Derivation
export {
  CONTEXT_CRUST,
  CONTEXT_ICP,
  CONTEXT_ENCRYPT,
  deriveSeed,
  deriveSubkey,
  deriveEncryptionKeyPair,
  deriveIdentityKeyPair,
} from './key-derivation.ts';

// Encryption
export {
  generateKey,
  encrypt,
  decrypt,
  createEncryptStream,
  createDecryptStream,
} from './encryption.ts';

// Key Wrapping
export {
  wrapKeySeal,
  wrapKeySealMulti,
  unwrapKeySeal,
  wrapKeyAuthenticated,
  wrapKeyAuthenticatedMulti,
  unwrapKeyAuthenticated,
} from './key-wrapping.ts';
```

---

## 2. Integration Tests

### tests/integration/file-encryption.test.ts

End-to-end file encryption scenarios simulating real usage.

```typescript
describe('integration: file-encryption', () => {
  describe('single-shot encryption', () => {
    it('encrypts and decrypts small file (<64KB)');
    it('works with empty file');
    it('works with maximum single-shot size (64KB)');
    it('preserves exact file content after round-trip');
  });

  describe('streaming encryption', () => {
    it('encrypts and decrypts large file (1MB)');
    it('encrypts and decrypts very large file (100MB)');
    it('handles chunk boundaries correctly');
    it('produces consistent output for same input+key');
    it('streaming output differs from single-shot (different format)');
  });

  describe('file-to-file pipeline', () => {
    it('stages file → encrypt → hash → store CID');
    it('retrieves CID → decrypt → verify hash → restore file');
    it('handles binary files (images, PDFs)');
    it('handles text files with various encodings');
  });

  describe('error scenarios', () => {
    it('rejects corrupted encrypted data');
    it('rejects truncated stream');
    it('rejects wrong key');
    it('provides meaningful error messages');
  });
});
```

### tests/integration/key-sharing.test.ts

Multi-user key sharing scenarios.

```typescript
describe('integration: key-sharing', () => {
  describe('self-encryption (single user, multiple devices)', () => {
    it('user encrypts file on device A, decrypts on device B');
    it('same mnemonic produces same keypairs on different devices');
    it('sealed keys can be unwrapped by any device with mnemonic');
  });

  describe('user-to-user sharing', () => {
    it('Alice shares file with Bob using authenticated wrapping');
    it('Bob verifies file came from Alice');
    it('Carol cannot unwrap key intended for Bob');
    it('attacker cannot forge sender identity');
  });

  describe('multi-recipient sharing', () => {
    it('Alice shares file with Bob, Carol, and Dave');
    it('each recipient can independently decrypt');
    it('adding new recipient requires re-wrapping');
    it('removed recipient cannot decrypt new versions');
  });

  describe('key hierarchy', () => {
    it('derives consistent encryption keys from mnemonic');
    it('derives consistent identity keys from mnemonic');
    it('different indexes produce different keys');
    it('different contexts produce different keys');
  });
});
```

### tests/integration/recovery.test.ts

Mnemonic recovery and disaster recovery scenarios.

```typescript
describe('integration: recovery', () => {
  describe('mnemonic recovery', () => {
    it('recovers all keys from 24-word mnemonic');
    it('recovers keys with optional passphrase');
    it('same mnemonic always produces same seed');
    it('generates valid BIP-39 mnemonics');
  });

  describe('data recovery flow', () => {
    it('encrypted file + mnemonic → recovered plaintext');
    it('manifest recovery from mnemonic-derived wallet');
    it('recovers files shared by others');
  });

  describe('cross-platform recovery', () => {
    it('keys derived in browser work in Bun');
    it('keys derived in Bun work in browser');
    it('encrypted data portable across platforms');
  });

  describe('edge cases', () => {
    it('handles normalized vs non-normalized mnemonics');
    it('rejects invalid mnemonics');
    it('rejects invalid passphrase types');
  });
});
```

---

## 3. Security Tests

### tests/security/nonce-safety.test.ts

Verify nonce uniqueness to prevent catastrophic failures.

```typescript
describe('security: nonce-safety', () => {
  describe('single-shot encryption', () => {
    it('generates unique nonce for each encryption');
    it('10000 encryptions produce 10000 unique nonces');
    it('nonces are cryptographically random');
    it('nonce length is exactly 24 bytes');
  });

  describe('streaming encryption', () => {
    it('each stream has unique header');
    it('internal nonce counter increments per chunk');
    it('new stream with same key has different header');
  });

  describe('key wrapping', () => {
    it('authenticated wrapping uses unique nonce per call');
    it('multi-recipient uses unique nonce per recipient');
    it('sealed box uses ephemeral keypair (implicit nonce safety)');
  });

  describe('statistical tests', () => {
    it('nonce distribution passes chi-squared test');
    it('no detectable patterns in nonce sequence');
  });
});
```

### tests/security/context-commitment.test.ts

Verify AAD (associated data) binding prevents misuse.

```typescript
describe('security: context-commitment', () => {
  describe('single-shot context binding', () => {
    it('decryption fails with wrong context');
    it('decryption fails with missing context');
    it('decryption fails with extra context');
    it('empty context differs from no context');
  });

  describe('streaming fileId binding', () => {
    it('decryption fails with wrong fileId');
    it('decryption fails with missing fileId');
    it('chunks from different files cannot be mixed');
  });

  describe('cross-context attacks', () => {
    it('ciphertext from context A fails in context B');
    it('manifest ciphertext cannot decrypt as file');
    it('file ciphertext cannot decrypt as manifest');
  });
});
```

### tests/security/stream-integrity.test.ts

Verify streaming encryption detects all tampering.

```typescript
describe('security: stream-integrity', () => {
  describe('chunk reordering', () => {
    it('detects swapped chunks');
    it('detects reversed chunk order');
    it('detects duplicated chunks');
    it('detects chunk from different stream');
  });

  describe('truncation', () => {
    it('detects missing final chunk');
    it('detects stream cut short mid-chunk');
    it('detects missing header');
    it('TAG_FINAL required for successful decrypt');
  });

  describe('modification', () => {
    it('detects single bit flip in ciphertext');
    it('detects single bit flip in auth tag');
    it('detects single bit flip in header');
    it('detects chunk length modification');
  });

  describe('insertion', () => {
    it('detects extra chunks inserted');
    it('detects padding added to chunks');
    it('detects header duplication');
  });

  describe('replay', () => {
    it('old stream cannot be replayed with new fileId');
    it('chunks from old stream rejected in new stream');
  });
});
```

### tests/security/timing-attacks.test.ts

Verify constant-time operations.

```typescript
describe('security: timing-attacks', () => {
  describe('constantTimeEqual', () => {
    it('returns correct result for equal arrays');
    it('returns correct result for unequal arrays');
    it('timing independent of difference position');
    it('timing independent of number of differences');
  });

  describe('sender verification', () => {
    it('sender mismatch uses constant-time comparison');
    it('timing independent of public key similarity');
  });

  describe('key comparison', () => {
    it('key validation uses constant-time comparison');
    it('timing independent of key content');
  });

  // Note: True timing attack tests require statistical analysis
  // These tests verify the correct functions are called
  describe('implementation verification', () => {
    it('uses sodium.memcmp for comparisons');
    it('does not use === for byte array comparison');
    it('does not use early-exit loops for comparison');
  });
});
```

---

## 4. Web Worker Example

### examples/worker/types.ts

Shared types between main thread and worker.

```typescript
import type {
  SymmetricKey,
  FileId,
  EncryptedData,
  SecretstreamHeader,
  X25519KeyPair,
  X25519PublicKey,
  AuthenticatedWrappedKey,
  ContentHash,
  Seed,
} from '../../src/index.ts';

export type EncryptFileRequest = {
  plaintext: Uint8Array;
  fileId?: FileId;
};

export type EncryptFileResponse = {
  key: SymmetricKey;
  header: SecretstreamHeader;
  ciphertext: Uint8Array;
  hash: ContentHash;
};

export type DecryptFileRequest = {
  key: SymmetricKey;
  header: SecretstreamHeader;
  ciphertext: Uint8Array;
  fileId?: FileId;
};

export type DecryptFileResponse = {
  plaintext: Uint8Array;
  hash: ContentHash;
};

export type WrapKeyRequest = {
  key: SymmetricKey;
  recipientPublicKey: X25519PublicKey;
  senderKeyPair?: X25519KeyPair;
};

export type WrapKeyResponse = {
  wrapped: Uint8Array | AuthenticatedWrappedKey;
};

export type DeriveKeysRequest = {
  mnemonic: string;
  passphrase?: string;
  encryptionIndex: number;
};

export type DeriveKeysResponse = {
  seed: Seed;
  encryptionKeyPair: X25519KeyPair;
};

export type CryptoWorkerAPI = {
  encryptFile(request: EncryptFileRequest): Promise<EncryptFileResponse>;
  decryptFile(request: DecryptFileRequest): Promise<DecryptFileResponse>;
  wrapKey(request: WrapKeyRequest): Promise<WrapKeyResponse>;
  deriveKeys(request: DeriveKeysRequest): Promise<DeriveKeysResponse>;
  preload(): Promise<void>;
};
```

### examples/worker/crypto.worker.ts

Comlink-based crypto worker implementation.

```typescript
import * as Comlink from 'comlink';
import {
  generateKey,
  createEncryptStream,
  createDecryptStream,
  hash,
  wrapKeySeal,
  wrapKeyAuthenticated,
  deriveSeed,
  deriveEncryptionKeyPair,
  preloadSodium,
} from '../../src/index.ts';
import type {
  CryptoWorkerAPI,
  EncryptFileRequest,
  EncryptFileResponse,
  DecryptFileRequest,
  DecryptFileResponse,
  WrapKeyRequest,
  WrapKeyResponse,
  DeriveKeysRequest,
  DeriveKeysResponse,
} from './types.ts';

const DEFAULT_CHUNK_SIZE = 64 * 1024; // 64KB

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

  const ciphertext = concatenateChunks(chunks);
  const plaintextHash = await hash(plaintext);

  return {
    key,
    header: stream.header,
    ciphertext,
    hash: plaintextHash,
  };
}

async function decryptFile(request: DecryptFileRequest): Promise<DecryptFileResponse> {
  const { key, header, ciphertext, fileId } = request;

  const stream = await createDecryptStream(key, header, fileId);
  const chunkOverhead = 17; // 16-byte tag + 1-byte flag
  const encryptedChunkSize = DEFAULT_CHUNK_SIZE + chunkOverhead;

  const chunks: Uint8Array[] = [];
  let offset = 0;

  while (offset < ciphertext.length) {
    const remainingBytes = ciphertext.length - offset;
    const chunkSize = Math.min(encryptedChunkSize, remainingBytes);
    const chunk = ciphertext.subarray(offset, offset + chunkSize);
    const decrypted = stream.pull(chunk);
    chunks.push(decrypted);
    offset += chunkSize;
  }

  const plaintext = concatenateChunks(chunks);
  const plaintextHash = await hash(plaintext);

  return {
    plaintext,
    hash: plaintextHash,
  };
}

async function wrapKey(request: WrapKeyRequest): Promise<WrapKeyResponse> {
  const { key, recipientPublicKey, senderKeyPair } = request;

  if (senderKeyPair) {
    const wrapped = await wrapKeyAuthenticated(key, recipientPublicKey, senderKeyPair);
    return { wrapped };
  }

  const wrapped = await wrapKeySeal(key, recipientPublicKey);
  return { wrapped };
}

async function deriveKeys(request: DeriveKeysRequest): Promise<DeriveKeysResponse> {
  const { mnemonic, passphrase, encryptionIndex } = request;

  const seed = await deriveSeed(mnemonic, passphrase);
  const encryptionKeyPair = await deriveEncryptionKeyPair(seed, encryptionIndex);

  return {
    seed,
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

const api: CryptoWorkerAPI = {
  encryptFile,
  decryptFile,
  wrapKey,
  deriveKeys,
  preload,
};

Comlink.expose(api);
```

### examples/worker/index.ts

Main thread API wrapping the worker.

```typescript
import * as Comlink from 'comlink';
import type { CryptoWorkerAPI } from './types.ts';

export type { CryptoWorkerAPI } from './types.ts';
export type {
  EncryptFileRequest,
  EncryptFileResponse,
  DecryptFileRequest,
  DecryptFileResponse,
  WrapKeyRequest,
  WrapKeyResponse,
  DeriveKeysRequest,
  DeriveKeysResponse,
} from './types.ts';

let workerInstance: Worker | null = null;
let apiInstance: Comlink.Remote<CryptoWorkerAPI> | null = null;

export function getCryptoWorker(): Comlink.Remote<CryptoWorkerAPI> {
  if (apiInstance) {
    return apiInstance;
  }

  workerInstance = new Worker(
    new URL('./crypto.worker.ts', import.meta.url),
    { type: 'module' }
  );

  apiInstance = Comlink.wrap<CryptoWorkerAPI>(workerInstance);
  return apiInstance;
}

export async function preloadCryptoWorker(): Promise<void> {
  const api = getCryptoWorker();
  await api.preload();
}

export function terminateCryptoWorker(): void {
  if (workerInstance) {
    workerInstance.terminate();
    workerInstance = null;
    apiInstance = null;
  }
}

export async function shouldUseWorker(fileSize: number): Promise<boolean> {
  const WORKER_THRESHOLD = 10 * 1024 * 1024; // 10MB
  return fileSize > WORKER_THRESHOLD;
}
```

### examples/worker/README.md

Documentation for worker usage.

```markdown
# Web Worker Example

This example demonstrates offloading cryptographic operations to a Web Worker
to prevent UI blocking for large files (>10MB).

## Usage

```typescript
import {
  getCryptoWorker,
  preloadCryptoWorker,
  shouldUseWorker,
} from '@filemanager/encryption/examples/worker';
import { generateKey, createEncryptStream } from '@filemanager/encryption';

// Preload worker during app initialization
await preloadCryptoWorker();

async function encryptFile(file: File): Promise<EncryptedFile> {
  const plaintext = new Uint8Array(await file.arrayBuffer());

  if (await shouldUseWorker(file.size)) {
    // Large file: use worker
    const worker = getCryptoWorker();
    return worker.encryptFile({ plaintext });
  }

  // Small file: encrypt on main thread
  const key = await generateKey();
  const stream = await createEncryptStream(key);
  // ... main thread encryption
}
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

## When to Use Worker

| File Size | Recommendation |
|-----------|----------------|
| < 1MB | Main thread (overhead not worth it) |
| 1-10MB | Main thread (usually fast enough) |
| > 10MB | **Worker** (prevents UI jank) |
| > 100MB | Worker + progress reporting |

## Transfer vs Clone

Uint8Array data is transferred via structured clone (not transferable).
For very large files, consider streaming instead of loading entire file.

## Dependencies

- `comlink` - For ergonomic worker communication

```bash
bun add comlink
```
```

---

## 5. Test Organization

### Directory Structure

```
tests/
  # Unit tests (existing)
  errors.test.ts
  branded.test.ts
  bytes.test.ts
  memory.test.ts
  sodium.test.ts
  hash.test.ts
  key-derivation.test.ts
  encryption.test.ts
  key-wrapping.test.ts

  # Integration tests (new)
  integration/
    file-encryption.test.ts
    key-sharing.test.ts
    recovery.test.ts

  # Security tests (new)
  security/
    nonce-safety.test.ts
    context-commitment.test.ts
    stream-integrity.test.ts
    timing-attacks.test.ts

  # Test utilities
  helpers/
    fixtures.ts        # Test data generators
    assertions.ts      # Custom assertions
    mocks.ts           # Mock implementations
```

### Test Fixtures (tests/helpers/fixtures.ts)

```typescript
import { generateKey, deriveSeed, deriveEncryptionKeyPair } from '../../src/index.ts';
import type { SymmetricKey, Seed, X25519KeyPair } from '../../src/index.ts';

export const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon about';

export const TEST_PASSPHRASE = 'TREZOR';

export async function createTestKey(): Promise<SymmetricKey> {
  return generateKey();
}

export async function createTestSeed(): Promise<Seed> {
  return deriveSeed(TEST_MNEMONIC);
}

export async function createTestKeyPair(index = 0): Promise<X25519KeyPair> {
  const seed = await createTestSeed();
  return deriveEncryptionKeyPair(seed, index);
}

export function createTestData(size: number): Uint8Array {
  const data = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    data[i] = i % 256;
  }
  return data;
}

export const SIZES = {
  EMPTY: 0,
  TINY: 16,
  SMALL: 1024,
  MEDIUM: 64 * 1024,
  LARGE: 1024 * 1024,
  VERY_LARGE: 100 * 1024 * 1024,
};
```

### Custom Assertions (tests/helpers/assertions.ts)

```typescript
import { expect } from 'vitest';
import { equals } from '../../src/bytes.ts';

export function expectBytesEqual(actual: Uint8Array, expected: Uint8Array): void {
  expect(equals(actual, expected)).toBe(true);
}

export function expectBytesNotEqual(actual: Uint8Array, expected: Uint8Array): void {
  expect(equals(actual, expected)).toBe(false);
}

export function expectValidNonce(nonce: Uint8Array): void {
  expect(nonce.length).toBe(24);
  expect(nonce.some((b) => b !== 0)).toBe(true);
}

export function expectUniqueNonces(nonces: Uint8Array[]): void {
  const hexSet = new Set(nonces.map((n) => Array.from(n).join(',')));
  expect(hexSet.size).toBe(nonces.length);
}
```

---

## 6. Implementation Order

1. **Test helpers** — Create fixtures.ts and assertions.ts
2. **Integration tests** — file-encryption, key-sharing, recovery
3. **Security tests** — nonce-safety, context-commitment, stream-integrity, timing
4. **Worker types** — examples/worker/types.ts
5. **Worker implementation** — examples/worker/crypto.worker.ts
6. **Worker main thread** — examples/worker/index.ts
7. **Worker documentation** — examples/worker/README.md
8. **Final verification** — Run full test suite, verify 100% coverage

---

## 7. Test Coverage Requirements

### Minimum Coverage Thresholds

| Category | Lines | Branches | Functions |
|----------|-------|----------|-----------|
| Overall | 95% | 90% | 100% |
| src/encryption.ts | 100% | 95% | 100% |
| src/key-wrapping.ts | 100% | 95% | 100% |
| src/key-derivation.ts | 100% | 95% | 100% |

### Coverage Commands

```bash
# Run with coverage
bun test --coverage

# Generate coverage report
bun test --coverage --reporter=html

# Check coverage thresholds
bun test --coverage --coverageThreshold='{"global":{"lines":95}}'
```

---

## 8. Cross-Platform Testing

### Browser Testing

Use Vitest browser mode for browser-specific tests:

```typescript
// vitest.config.ts
export default defineConfig({
  test: {
    browser: {
      enabled: true,
      name: 'chromium',
      provider: 'playwright',
    },
  },
});
```

### Bun/Node Testing

Standard Vitest for server-side:

```bash
bun test
```

### Test Matrix

| Test | Browser | Bun |
|------|---------|-----|
| Unit tests | ✓ | ✓ |
| Integration tests | ✓ | ✓ |
| Security tests | ✓ | ✓ |
| Worker tests | ✓ | ✗ |

---

## 9. Documentation Updates

### README.md Updates

Add usage examples and API reference:

```markdown
## Quick Start

```typescript
import {
  generateKey,
  encrypt,
  decrypt,
  deriveSeed,
  deriveEncryptionKeyPair,
  wrapKeyAuthenticated,
  unwrapKeyAuthenticated,
} from '@filemanager/encryption';

// Generate encryption key
const key = await generateKey();

// Encrypt data
const { nonce, ciphertext } = await encrypt(plaintext, key);

// Decrypt data
const decrypted = await decrypt(ciphertext, nonce, key);

// Derive keys from mnemonic
const seed = await deriveSeed('your 24-word mnemonic here');
const keyPair = await deriveEncryptionKeyPair(seed, 0);

// Share key with another user
const wrapped = await wrapKeyAuthenticated(key, recipientPubKey, senderKeyPair);
const unwrapped = await unwrapKeyAuthenticated(wrapped, senderPubKey, recipientKeyPair);
```

## API Reference

See [API.md](./API.md) for complete API documentation.
```

---

## 10. Final Checklist

### Before Release

- [ ] All 196+ tests passing
- [ ] Integration tests cover all user flows
- [ ] Security tests cover all attack vectors
- [ ] Worker example functional in browser
- [ ] Coverage thresholds met
- [ ] No TypeScript errors
- [ ] No ESLint warnings
- [ ] README updated with examples
- [ ] CHANGELOG updated

### Performance Benchmarks

| Operation | Size | Target |
|-----------|------|--------|
| Single-shot encrypt | 64KB | < 5ms |
| Streaming encrypt | 1MB | < 50ms |
| Streaming encrypt | 100MB | < 3s |
| Key derivation | — | < 100ms |
| Key wrapping | — | < 1ms |

Run benchmarks:
```bash
bun run bench
```

---

## 11. Known Limitations

### Worker Limitations

1. **No SharedArrayBuffer** — Worker uses structured clone, not transfer
2. **Memory overhead** — Data copied between threads
3. **Startup cost** — Worker initialization adds ~50ms latency

### Test Limitations

1. **True timing tests** — Statistical timing analysis not practical in JS
2. **Memory tests** — Cannot verify secure memory clearing
3. **Browser-specific** — Some tests only meaningful in browser context

### Future Improvements

1. **Transferable streams** — Use TransformStream for true streaming
2. **OPFS integration** — Read/write directly from OPFS in worker
3. **Progress reporting** — Callback-based progress for large files
