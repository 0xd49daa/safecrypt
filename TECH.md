# @filemanager/encryptionv2 Technical Documentation

TypeScript encryption library for browser-first decentralized storage. Provides symmetric encryption, asymmetric key wrapping, key derivation, and hashing using libsodium.

## Installation

```bash
bun add @filemanager/encryptionv2
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `libsodium-wrappers` | 0.7.15 | Core cryptography (XChaCha20, X25519, Ed25519) |
| `@scure/bip39` | 1.4.0 | BIP-39 mnemonic handling |

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
  hash,
  preloadSodium,
} from '@filemanager/encryptionv2';

// Preload libsodium WASM (optional, recommended at app startup)
await preloadSodium();

// Generate a unique key for file encryption
const fileKey = await generateKey();

// Encrypt data
const plaintext = new TextEncoder().encode('Secret message');
const { nonce, ciphertext } = await encrypt(plaintext, fileKey);

// Decrypt data
const decrypted = await decrypt(ciphertext, nonce, fileKey);
```

---

## API Reference

### Encryption

#### `generateKey(): Promise<SymmetricKey>`

Generates a 32-byte cryptographically secure random key.

**CRITICAL: Generate a unique key for EACH file. Never reuse keys.**

```typescript
const fileKey = await generateKey();
```

#### `encrypt(plaintext, key, context?): Promise<EncryptedData>`

Single-shot XChaCha20-Poly1305 encryption for data < 64KB.

```typescript
const { nonce, ciphertext } = await encrypt(plaintext, key);
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `plaintext` | `Uint8Array` | Data to encrypt |
| `key` | `SymmetricKey` | 32-byte encryption key |
| `context` | `Uint8Array?` | Optional AAD for context binding |

**Returns:** `{ nonce: Uint8Array, ciphertext: Uint8Array }`

#### `decrypt(ciphertext, nonce, key, context?): Promise<Uint8Array>`

Decrypts data encrypted with `encrypt()`.

```typescript
const plaintext = await decrypt(ciphertext, nonce, key);
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `ciphertext` | `Uint8Array` | Encrypted data |
| `nonce` | `Nonce` | 24-byte nonce from encryption |
| `key` | `SymmetricKey` | 32-byte encryption key |
| `context` | `Uint8Array?` | Optional AAD (must match encryption) |

**Throws:** `EncryptionError` with code `DECRYPTION_FAILED` on authentication failure.

---

### Streaming Encryption

For files > 64KB, use streaming encryption via `crypto_secretstream`.

#### `createEncryptStream(key, fileId?): Promise<EncryptStream>`

Creates a streaming encryption context.

```typescript
const stream = await createEncryptStream(key, fileId);
const header = stream.header; // 24 bytes, store with ciphertext

let offset = 0;
const chunks: Uint8Array[] = [];
while (offset < plaintext.length) {
  const end = Math.min(offset + 64 * 1024, plaintext.length);
  const chunk = plaintext.subarray(offset, end);
  const isFinal = end === plaintext.length;
  chunks.push(stream.push(chunk, isFinal));
  offset = end;
}
stream.dispose();
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `SymmetricKey` | 32-byte encryption key |
| `fileId` | `FileId?` | Optional 32-byte file identifier for AAD |

**Returns:** `EncryptStream`

```typescript
type EncryptStream = {
  readonly header: Uint8Array;  // 24-byte stream header
  push(chunk: Uint8Array, isFinal: boolean): Uint8Array;
  dispose(): void;
};
```

#### `createDecryptStream(key, header, fileId?): Promise<DecryptStream>`

Creates a streaming decryption context.

```typescript
const stream = await createDecryptStream(key, header, fileId);
const decryptedChunks: Uint8Array[] = [];

for (const encryptedChunk of encryptedChunks) {
  const { plaintext, isFinal } = stream.pull(encryptedChunk);
  decryptedChunks.push(plaintext);
}

stream.finalize(); // Throws if TAG_FINAL not received
stream.dispose();
```

**Returns:** `DecryptStream`

```typescript
type DecryptStream = {
  pull(chunk: Uint8Array): { plaintext: Uint8Array; isFinal: boolean };
  finalize(): void;  // Must call after all chunks - verifies stream integrity
  dispose(): void;
};
```

**Throws:**
- `SEGMENT_AUTH_FAILED` - Chunk authentication failed
- `STREAM_TRUNCATED` - `finalize()` called without receiving TAG_FINAL

---

### Key Derivation

#### `deriveSeed(mnemonic, passphrase?): Promise<Seed>`

Derives a 64-byte seed from a BIP-39 mnemonic.

```typescript
const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const seed = await deriveSeed(mnemonic);

// With optional passphrase (changes derived keys)
const seedWithPassphrase = await deriveSeed(mnemonic, 'my-passphrase');
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `mnemonic` | `string` | 12 or 24 word BIP-39 mnemonic |
| `passphrase` | `string?` | Optional passphrase (default: `''`) |

**Throws:** `EncryptionError` with code `INVALID_MNEMONIC` for invalid mnemonics.

#### `deriveEncryptionKeyPair(seed, index): Promise<X25519KeyPair>`

Derives an X25519 keypair for encryption/key-wrapping.

```typescript
const keyPair = await deriveEncryptionKeyPair(seed, 0);
// keyPair.publicKey  - 32 bytes, share with others
// keyPair.privateKey - 32 bytes, keep secret
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `seed` | `Seed` | 64-byte seed from `deriveSeed()` |
| `index` | `number` | Key index (use different indexes for different purposes) |

#### `deriveIdentityKeyPair(seed, context, index): Promise<Ed25519KeyPair>`

Derives an Ed25519 keypair for signing/identity.

```typescript
import { CONTEXT_CRUST, CONTEXT_ICP } from '@filemanager/encryptionv2';

const crustIdentity = await deriveIdentityKeyPair(seed, CONTEXT_CRUST, 0);
const icpIdentity = await deriveIdentityKeyPair(seed, CONTEXT_ICP, 0);
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `seed` | `Seed` | 64-byte seed from `deriveSeed()` |
| `context` | `KdfContext` | `'crust___'`, `'icp_____'`, or `'encrypt_'` |
| `index` | `number` | Key index |

**Returns:** `Ed25519KeyPair`

```typescript
type Ed25519KeyPair = {
  readonly publicKey: Ed25519PublicKey;   // 32 bytes
  readonly privateKey: Ed25519PrivateKey; // 64 bytes
};
```

---

### Key Wrapping

#### `wrapKeyAuthenticated(key, recipientPub, senderKeyPair): Promise<AuthenticatedWrappedKey>`

Wraps a symmetric key for a recipient with sender authentication. **Use this for user-to-user sharing.**

```typescript
const wrappedKey = await wrapKeyAuthenticated(
  fileKey,
  bobKeyPair.publicKey,
  aliceKeyPair
);
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `SymmetricKey` | Key to wrap |
| `recipientPub` | `X25519PublicKey` | Recipient's public key |
| `senderKeyPair` | `X25519KeyPair` | Sender's full keypair |

**Returns:** `AuthenticatedWrappedKey`

```typescript
type AuthenticatedWrappedKey = {
  readonly nonce: Uint8Array;           // 24 bytes
  readonly ciphertext: Uint8Array;      // 48 bytes (32 + 16 tag)
  readonly senderPublicKey: X25519PublicKey;
};
```

#### `unwrapKeyAuthenticated(wrapped, expectedSenderPub, recipientKeyPair): Promise<SymmetricKey>`

Unwraps a key and verifies sender identity.

```typescript
const fileKey = await unwrapKeyAuthenticated(
  wrappedKey,
  aliceKeyPair.publicKey,  // Expected sender
  bobKeyPair               // Recipient's keypair
);
```

**Throws:**
- `SENDER_MISMATCH` - Sender public key doesn't match expected
- `DECRYPTION_FAILED` - Decryption failed (wrong recipient or corrupted)

#### `wrapKeyAuthenticatedMulti(key, recipientPubs, senderKeyPair): Promise<AuthenticatedWrappedKey[]>`

Wraps a key for multiple recipients.

```typescript
const wrappedKeys = await wrapKeyAuthenticatedMulti(
  fileKey,
  [bobKeyPair.publicKey, carolKeyPair.publicKey],
  aliceKeyPair
);
```

---

### Hashing

#### `hash(data): Promise<ContentHash>`

SHA-256 hash via Web Crypto API.

```typescript
const contentHash = await hash(fileData);
// Returns 32-byte ContentHash
```

#### `hashBlake2b(data, outlen?): Promise<Uint8Array>`

BLAKE2b hash via libsodium (faster than SHA-256).

```typescript
const hash = await hashBlake2b(data);       // 32 bytes default
const hash16 = await hashBlake2b(data, 16); // Custom output length
```

---

### Utilities

#### `toBase64(bytes): string` / `fromBase64(base64): Uint8Array`

Base64 encoding/decoding.

```typescript
import { toBase64, fromBase64 } from '@filemanager/encryptionv2';

const encoded = toBase64(bytes);
const decoded = fromBase64(encoded);
```

#### `secureZero(bytes): void`

Best-effort memory clearing.

```typescript
import { secureZero } from '@filemanager/encryptionv2';

secureZero(sensitiveData);
```

**Note:** JavaScript cannot guarantee secure memory clearing. Use as defense-in-depth.

#### `constantTimeEqual(a, b): Promise<boolean>`

Constant-time comparison (prevents timing attacks).

```typescript
import { constantTimeEqual } from '@filemanager/encryptionv2';

const isEqual = await constantTimeEqual(mac1, mac2);
```

#### `randomBytes(length): Promise<Uint8Array>`

Generate cryptographically secure random bytes.

```typescript
import { randomBytes } from '@filemanager/encryptionv2';

const nonce = await randomBytes(24);
```

#### `preloadSodium(): Promise<void>`

Preload libsodium WASM module. Call at app startup for faster first operation.

```typescript
import { preloadSodium } from '@filemanager/encryptionv2';

// At app initialization
await preloadSodium();
```

---

## Types

### Branded Types

The library uses branded types to prevent confusion at compile time:

```typescript
import type {
  SymmetricKey,        // 32-byte symmetric key
  Nonce,               // 24-byte nonce
  Ciphertext,          // Variable-length ciphertext
  FileId,              // 32-byte file identifier
  SecretstreamHeader,  // 24-byte stream header
  X25519PublicKey,     // 32-byte X25519 public key
  X25519PrivateKey,    // 32-byte X25519 private key
  Ed25519PublicKey,    // 32-byte Ed25519 public key
  Ed25519PrivateKey,   // 64-byte Ed25519 private key
  ContentHash,         // 32-byte SHA-256 hash
  Seed,                // 64-byte BIP-39 seed
} from '@filemanager/encryptionv2';
```

### Type Validators

```typescript
import { asContentHash } from '@filemanager/encryptionv2';

// Validates and brands a Uint8Array
const hash = asContentHash(someBytes); // Throws if not 32 bytes
```

### Data Types

```typescript
type EncryptedData = {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
};

type EncryptStream = {
  readonly header: Uint8Array;
  push(chunk: Uint8Array, isFinal: boolean): Uint8Array;
  dispose(): void;
};

type DecryptStream = {
  pull(chunk: Uint8Array): { plaintext: Uint8Array; isFinal: boolean };
  finalize(): void;
  dispose(): void;
};

type X25519KeyPair = {
  readonly publicKey: X25519PublicKey;
  readonly privateKey: X25519PrivateKey;
};

type Ed25519KeyPair = {
  readonly publicKey: Ed25519PublicKey;
  readonly privateKey: Ed25519PrivateKey;
};

type AuthenticatedWrappedKey = {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly senderPublicKey: X25519PublicKey;
};

type KdfContext = 'crust___' | 'icp_____' | 'encrypt_';
```

### Size Constants

```typescript
import { SIZES } from '@filemanager/encryptionv2';

SIZES.SYMMETRIC_KEY        // 32
SIZES.NONCE                // 24
SIZES.AUTH_TAG             // 16
SIZES.STREAM_HEADER        // 24
SIZES.STREAM_CHUNK_OVERHEAD // 17 (16 tag + 1 flag)
SIZES.X25519_PUBLIC_KEY    // 32
SIZES.X25519_PRIVATE_KEY   // 32
SIZES.ED25519_PUBLIC_KEY   // 32
SIZES.ED25519_PRIVATE_KEY  // 64
SIZES.SEED                 // 64
SIZES.SHA256               // 32
SIZES.SEALED_BOX           // 80
SIZES.KDF_CONTEXT          // 8
SIZES.DEFAULT_CHUNK        // 65536 (64KB)
```

---

## Error Handling

```typescript
import { EncryptionError, ErrorCode } from '@filemanager/encryptionv2';

try {
  await decrypt(ciphertext, nonce, wrongKey);
} catch (error) {
  if (EncryptionError.isEncryptionError(error)) {
    switch (error.code) {
      case ErrorCode.DECRYPTION_FAILED:
        // Authentication tag mismatch
        break;
      case ErrorCode.INVALID_KEY_SIZE:
        // Key not 32 bytes
        break;
      case ErrorCode.SEGMENT_AUTH_FAILED:
        // Streaming chunk auth failed
        break;
      case ErrorCode.STREAM_TRUNCATED:
        // Missing TAG_FINAL marker
        break;
      case ErrorCode.INVALID_MNEMONIC:
        // BIP-39 validation failed
        break;
      case ErrorCode.SENDER_MISMATCH:
        // Sender key doesn't match expected
        break;
    }
  }
}
```

### Error Codes

| Code | Meaning |
|------|---------|
| `INVALID_KEY_SIZE` | Key not expected size |
| `INVALID_NONCE_SIZE` | Nonce not 24 bytes |
| `DECRYPTION_FAILED` | Authentication tag mismatch |
| `SEGMENT_AUTH_FAILED` | Chunk authentication failed |
| `STREAM_TRUNCATED` | Missing TAG_FINAL marker |
| `INVALID_STREAM_HEADER` | Malformed stream header |
| `INVALID_MNEMONIC` | BIP-39 validation failed |
| `SENDER_MISMATCH` | Sender public key doesn't match expected |
| `INVALID_SEED_SIZE` | Seed not 64 bytes |
| `INVALID_BASE64` | Invalid base64 string |

---

## Usage Examples

### File Encryption (Single-shot)

```typescript
import { generateKey, encrypt, decrypt, hash } from '@filemanager/encryptionv2';

async function encryptFile(fileData: Uint8Array) {
  const key = await generateKey();
  const { nonce, ciphertext } = await encrypt(fileData, key);
  const contentHash = await hash(ciphertext);

  return { key, nonce, ciphertext, contentHash };
}

async function decryptFile(ciphertext: Uint8Array, nonce: Nonce, key: SymmetricKey) {
  return await decrypt(ciphertext, nonce, key);
}
```

### Streaming File Encryption (Large Files)

```typescript
import { generateKey, createEncryptStream, createDecryptStream, hash, asFileId } from '@filemanager/encryptionv2';

const CHUNK_SIZE = 64 * 1024; // 64KB

async function encryptLargeFile(fileData: Uint8Array) {
  const key = await generateKey();
  const fileId = asFileId(await hash(fileData));

  const stream = await createEncryptStream(key, fileId);
  const header = stream.header;
  const chunks: Uint8Array[] = [];

  let offset = 0;
  while (offset < fileData.length) {
    const end = Math.min(offset + CHUNK_SIZE, fileData.length);
    const chunk = fileData.subarray(offset, end);
    const isFinal = end === fileData.length;
    chunks.push(stream.push(chunk, isFinal));
    offset = end;
  }
  stream.dispose();

  return { key, header, chunks, fileId };
}

async function decryptLargeFile(
  key: SymmetricKey,
  header: SecretstreamHeader,
  encryptedChunks: Uint8Array[],
  fileId?: FileId
) {
  const stream = await createDecryptStream(key, header, fileId);
  const decryptedChunks: Uint8Array[] = [];

  for (const chunk of encryptedChunks) {
    const { plaintext } = stream.pull(chunk);
    decryptedChunks.push(plaintext);
  }

  stream.finalize(); // Verify stream integrity
  stream.dispose();

  return concatenate(decryptedChunks);
}
```

### Self-Encryption (Single User, Multiple Devices)

```typescript
import {
  deriveSeed,
  deriveEncryptionKeyPair,
  generateKey,
  encrypt,
  decrypt,
  wrapKeySeal,
  unwrapKeySeal,
} from '@filemanager/encryptionv2';

// Device A: Encrypt and store
async function encryptOnDeviceA(mnemonic: string, plaintext: Uint8Array) {
  const seed = await deriveSeed(mnemonic);
  const keyPair = await deriveEncryptionKeyPair(seed, 0);

  const fileKey = await generateKey();
  const { nonce, ciphertext } = await encrypt(plaintext, fileKey);
  const sealedKey = await wrapKeySeal(fileKey, keyPair.publicKey);

  return { nonce, ciphertext, sealedKey };
}

// Device B: Recover and decrypt
async function decryptOnDeviceB(
  mnemonic: string,
  nonce: Nonce,
  ciphertext: Uint8Array,
  sealedKey: Uint8Array
) {
  const seed = await deriveSeed(mnemonic);
  const keyPair = await deriveEncryptionKeyPair(seed, 0);

  const fileKey = await unwrapKeySeal(sealedKey, keyPair);
  return await decrypt(ciphertext, nonce, fileKey);
}
```

### User-to-User Sharing

```typescript
import {
  deriveSeed,
  deriveEncryptionKeyPair,
  generateKey,
  encrypt,
  decrypt,
  wrapKeyAuthenticated,
  unwrapKeyAuthenticated,
} from '@filemanager/encryptionv2';

// Alice shares with Bob
async function shareFile(
  aliceMnemonic: string,
  bobPublicKey: X25519PublicKey,
  plaintext: Uint8Array
) {
  const aliceSeed = await deriveSeed(aliceMnemonic);
  const aliceKeyPair = await deriveEncryptionKeyPair(aliceSeed, 0);

  const fileKey = await generateKey();
  const { nonce, ciphertext } = await encrypt(plaintext, fileKey);

  const wrappedKey = await wrapKeyAuthenticated(
    fileKey,
    bobPublicKey,
    aliceKeyPair
  );

  return { nonce, ciphertext, wrappedKey };
}

// Bob receives from Alice
async function receiveFile(
  bobMnemonic: string,
  alicePublicKey: X25519PublicKey,
  nonce: Nonce,
  ciphertext: Uint8Array,
  wrappedKey: AuthenticatedWrappedKey
) {
  const bobSeed = await deriveSeed(bobMnemonic);
  const bobKeyPair = await deriveEncryptionKeyPair(bobSeed, 0);

  // Verifies Alice is the sender
  const fileKey = await unwrapKeyAuthenticated(
    wrappedKey,
    alicePublicKey,
    bobKeyPair
  );

  return await decrypt(ciphertext, nonce, fileKey);
}
```

### Multi-Recipient Sharing

```typescript
import {
  generateKey,
  encrypt,
  wrapKeyAuthenticatedMulti,
  unwrapKeyAuthenticated,
} from '@filemanager/encryptionv2';

async function shareWithMultiple(
  senderKeyPair: X25519KeyPair,
  recipientPublicKeys: X25519PublicKey[],
  plaintext: Uint8Array
) {
  const fileKey = await generateKey();
  const { nonce, ciphertext } = await encrypt(plaintext, fileKey);

  const wrappedKeys = await wrapKeyAuthenticatedMulti(
    fileKey,
    recipientPublicKeys,
    senderKeyPair
  );

  // wrappedKeys[i] corresponds to recipientPublicKeys[i]
  return { nonce, ciphertext, wrappedKeys };
}
```

---

## Web Worker Integration

For files > 10MB, run crypto operations in a Web Worker to prevent UI blocking.

The library provides a reference implementation in `examples/worker/`:

```typescript
import { workerAPI, shouldUseWorker, WORKER_FILE_SIZE_THRESHOLD } from '@filemanager/encryptionv2/examples/worker';

// Check if file should use worker
if (shouldUseWorker(fileSize)) {
  // Use worker API
  const result = await workerAPI.encryptFile({ plaintext, fileId });
}
```

### Worker API

```typescript
type CryptoWorkerAPI = {
  encryptFile(request: EncryptFileRequest): Promise<EncryptFileResponse>;
  decryptFile(request: DecryptFileRequest): Promise<DecryptFileResponse>;
  wrapKeySeal(request: WrapKeySealRequest): Promise<WrapKeySealResponse>;
  wrapKeyAuthenticated(request: WrapKeyAuthenticatedRequest): Promise<WrapKeyAuthenticatedResponse>;
  deriveKeys(request: DeriveKeysRequest): Promise<DeriveKeysResponse>;
  preload(): Promise<void>;
};
```

---

## Cryptographic Primitives

| Primitive | Algorithm | libsodium Function |
|-----------|-----------|-------------------|
| Symmetric (single) | XChaCha20-Poly1305 | `crypto_aead_xchacha20poly1305_ietf` |
| Symmetric (stream) | XChaCha20-Poly1305 | `crypto_secretstream_xchacha20poly1305` |
| Key wrapping (auth) | X25519 + XSalsa20-Poly1305 | `crypto_box_easy` |
| Key wrapping (anon) | X25519 + XSalsa20-Poly1305 | `crypto_box_seal` |
| Key derivation | HKDF | `crypto_kdf_derive_from_key` |
| Hashing (SHA-256) | SHA-256 | Web Crypto API |
| Hashing (BLAKE2b) | BLAKE2b | `crypto_generichash` |
| Signing keys | Ed25519 | `crypto_sign_seed_keypair` |
| Encryption keys | X25519 | `crypto_box_seed_keypair` |
| Random | CSPRNG | `randombytes_buf` |

---

## Wire Formats

### Single-shot Encryption

```
{ nonce: Uint8Array(24), ciphertext: Uint8Array(plaintext.length + 16) }
```

### Streaming Encryption

```
[Header (24 bytes)][Chunk 0 (data + 17)]...[Chunk N with TAG_FINAL]
```

- Header: 24 bytes
- Chunk overhead: 17 bytes (16-byte tag + 1-byte flag)
- Default chunk size: 64KB

### Authenticated Wrapped Key

```
{
  nonce: Uint8Array(24),
  ciphertext: Uint8Array(48),  // 32-byte key + 16-byte tag
  senderPublicKey: Uint8Array(32)
}
```

---

## Security Considerations

### Library Guarantees

- Cryptographic correctness via libsodium
- No unverified plaintext release
- Protection against chunk reordering/truncation/swapping
- Nonce uniqueness (random 192-bit nonces)
- Key derivation determinism

### Library Cannot Guarantee

- Memory security against local attackers
- Protection against compromised browser/OS
- Side-channel resistance in JS runtime
- Secure memory clearing (JavaScript limitation)

### Best Practices

1. **Generate unique key for EACH file** - Never reuse symmetric keys
2. **Use authenticated wrapping for sharing** - Never use anonymous `wrapKeySeal` for user-to-user
3. **Call `finalize()` on decrypt streams** - Prevents truncation attacks
4. **Use Web Worker for files > 10MB** - Prevents UI blocking
5. **Clear sensitive data** - Call `secureZero()` on keys after use (best effort)
6. **Validate mnemonic source** - Only accept user-controlled mnemonics

---

## Browser Compatibility

| Browser | Minimum Version |
|---------|-----------------|
| Chrome | 90+ |
| Firefox | 90+ |
| Safari | 15+ |
| Edge | 90+ |

Requires:
- WebAssembly support
- Web Crypto API
- ES2020+ (async/await, BigInt)

---

## Bundle Size

| Component | Size |
|-----------|------|
| libsodium WASM | ~150KB |
| JS wrapper | ~15KB |
| @scure/bip39 + wordlist | ~200KB |
| **Total** | ~400KB |

---

## Testing

```bash
bun test                 # Run all tests
bun test --watch         # Watch mode
bun test src/hash.test.ts  # Single file
```

Test categories:
- Unit tests - Each function in isolation
- Integration tests - Full encrypt/decrypt flows
- Security tests - Nonce safety, timing attacks, stream integrity
