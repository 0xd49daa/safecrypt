# Phase 1: Foundation — Technical Specification

## Overview

Phase 1 establishes the foundational layer for `@filemanager/encryption`: project configuration, error handling, type system, and low-level utilities. All subsequent phases depend on these primitives.

**Deliverables:**
- Project setup (package.json, tsconfig.json)
- `src/errors.ts`
- `src/types.ts`
- `src/branded.ts`
- `src/bytes.ts`
- `src/memory.ts`

---

## 1. Project Setup

### 1.1 Package Configuration

**package.json:**

```json
{
  "name": "@filemanager/encryption",
  "version": "0.1.0",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "types": "./dist/index.d.ts"
    }
  },
  "files": ["dist"],
  "scripts": {
    "build": "tsc",
    "test": "bun test",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "libsodium-wrappers": "0.7.15",
    "@scure/bip39": "1.4.0"
  },
  "devDependencies": {
    "@types/libsodium-wrappers": "0.7.14",
    "typescript": "^5.0.0"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
```

### 1.2 TypeScript Configuration

**tsconfig.json:**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "lib": ["ES2022", "DOM"],
    "outDir": "dist",
    "rootDir": "src",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "noPropertyAccessFromIndexSignature": true,
    "exactOptionalPropertyTypes": true,
    "forceConsistentCasingInFileNames": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

### 1.3 Directory Structure

```
@filemanager/encryption/
├── package.json
├── tsconfig.json
├── src/
│   ├── errors.ts
│   ├── types.ts
│   ├── branded.ts
│   ├── bytes.ts
│   ├── memory.ts
│   └── index.ts      # (placeholder, full exports in Phase 5)
└── tests/
    ├── errors.test.ts
    ├── branded.test.ts
    ├── bytes.test.ts
    └── memory.test.ts
```

---

## 2. Error Handling (`src/errors.ts`)

### 2.1 Design

All errors extend a base `EncryptionError` class with:
- Unique error code (string constant)
- Human-readable message
- Optional cause for error chaining

Error codes are exported as a const object for type safety and IDE autocompletion.

### 2.2 Error Codes

| Code | Meaning | When Thrown |
|------|---------|-------------|
| `INVALID_KEY_SIZE` | Key is not 32 bytes | Key validation fails |
| `INVALID_NONCE_SIZE` | Nonce is not 24 bytes | Nonce validation fails |
| `DECRYPTION_FAILED` | Authentication tag mismatch | Single-shot decrypt fails |
| `SEGMENT_AUTH_FAILED` | Chunk authentication failed | Streaming decrypt chunk fails |
| `STREAM_TRUNCATED` | Missing TAG_FINAL marker | Stream ends without final tag |
| `INVALID_STREAM_HEADER` | Malformed stream header | Header validation fails |
| `INVALID_MNEMONIC` | BIP-39 checksum/word invalid | Mnemonic validation fails |
| `SENDER_MISMATCH` | Sender pubkey doesn't match | Authenticated unwrap verification fails |

### 2.3 Interface

```typescript
// Error codes as const for type safety
export const ErrorCode = {
  INVALID_KEY_SIZE: 'INVALID_KEY_SIZE',
  INVALID_NONCE_SIZE: 'INVALID_NONCE_SIZE',
  DECRYPTION_FAILED: 'DECRYPTION_FAILED',
  SEGMENT_AUTH_FAILED: 'SEGMENT_AUTH_FAILED',
  STREAM_TRUNCATED: 'STREAM_TRUNCATED',
  INVALID_STREAM_HEADER: 'INVALID_STREAM_HEADER',
  INVALID_MNEMONIC: 'INVALID_MNEMONIC',
  SENDER_MISMATCH: 'SENDER_MISMATCH',
} as const;

export type ErrorCode = typeof ErrorCode[keyof typeof ErrorCode];

export class EncryptionError extends Error {
  readonly code: ErrorCode;
  readonly cause?: Error;
  
  constructor(code: ErrorCode, message: string, cause?: Error);
  
  // Type guard
  static isEncryptionError(error: unknown): error is EncryptionError;
}

// Convenience factory functions
export function invalidKeySize(actual: number, expected?: number): EncryptionError;
export function invalidNonceSize(actual: number, expected?: number): EncryptionError;
export function decryptionFailed(cause?: Error): EncryptionError;
export function segmentAuthFailed(segmentIndex: number, cause?: Error): EncryptionError;
export function streamTruncated(): EncryptionError;
export function invalidStreamHeader(reason: string): EncryptionError;
export function invalidMnemonic(reason: string): EncryptionError;
export function senderMismatch(): EncryptionError;
```

### 2.4 Implementation Notes

- Factory functions include context in messages (e.g., "Invalid key size: got 16 bytes, expected 32")
- `cause` parameter enables error chaining from underlying libsodium errors
- `isEncryptionError` type guard enables safe error handling in catch blocks

---

## 3. Core Types (`src/types.ts`)

### 3.1 Design

Plain interfaces for data structures. These are NOT branded types (those live in `branded.ts`). These represent composite structures used across the library.

### 3.2 Interface

```typescript
/**
 * Result of single-shot encryption.
 * Nonce is prepended for transport/storage convenience.
 */
export interface EncryptedData {
  /** 24-byte random nonce */
  readonly nonce: Uint8Array;
  /** Ciphertext including 16-byte auth tag */
  readonly ciphertext: Uint8Array;
}

/**
 * Header for crypto_secretstream.
 * Must be stored alongside encrypted chunks for decryption.
 */
export interface StreamHeader {
  /** 24-byte stream header from crypto_secretstream_init_push */
  readonly header: Uint8Array;
}

/**
 * Generic keypair structure.
 * Used for both X25519 (encryption) and Ed25519 (signing) keypairs.
 */
export interface KeyPair<TPub extends Uint8Array, TPriv extends Uint8Array> {
  readonly publicKey: TPub;
  readonly privateKey: TPriv;
}

/**
 * X25519 keypair for encryption/key-wrapping operations.
 */
export interface X25519KeyPair {
  readonly publicKey: Uint8Array;  // 32 bytes
  readonly privateKey: Uint8Array; // 32 bytes
}

/**
 * Ed25519 keypair for signing/identity operations.
 */
export interface Ed25519KeyPair {
  readonly publicKey: Uint8Array;  // 32 bytes
  readonly privateKey: Uint8Array; // 64 bytes (seed + public key)
}

/**
 * Sealed box result (anonymous encryption).
 * Total size: 32 (ephemeral pk) + 16 (tag) + 32 (key) = 80 bytes
 */
export interface SealedBox {
  readonly sealed: Uint8Array; // 80 bytes total
}

/**
 * Authenticated wrapped key result.
 * Includes sender info for verification.
 */
export interface AuthenticatedWrappedKey {
  /** 24-byte nonce */
  readonly nonce: Uint8Array;
  /** Ciphertext: 32-byte key + 16-byte tag = 48 bytes */
  readonly ciphertext: Uint8Array;
  /** Sender's X25519 public key for verification */
  readonly senderPublicKey: Uint8Array;
}

/**
 * Multi-recipient wrapped key.
 * Same key wrapped for multiple recipients.
 */
export interface MultiRecipientWrappedKey<T extends SealedBox | AuthenticatedWrappedKey> {
  /** Array of wrapped keys, one per recipient (same order as input pubkeys) */
  readonly wrappedKeys: readonly T[];
}

/**
 * Streaming encryption state.
 * Returned by createChunkedEncryptStream.
 */
export interface EncryptStream {
  /** Stream header (must be stored for decryption) */
  readonly header: Uint8Array;
  
  /** Encrypt next chunk. Returns ciphertext with auth tag. */
  push(chunk: Uint8Array, isFinal: boolean): Uint8Array;
  
  /** Clean up state (best-effort memory clearing) */
  dispose(): void;
}

/**
 * Streaming decryption state.
 * Returned by createChunkedDecryptStream.
 */
export interface DecryptStream {
  /** Decrypt next chunk. Returns plaintext. Throws on auth failure. */
  pull(chunk: Uint8Array): { plaintext: Uint8Array; isFinal: boolean };
  
  /** Clean up state */
  dispose(): void;
}

/**
 * Streaming hasher interface.
 */
export interface StreamingHasher {
  /** Update hash with more data */
  update(data: Uint8Array): void;
  
  /** Finalize and return hash. Hasher cannot be used after this. */
  digest(): Promise<Uint8Array>;
}

/**
 * Key derivation context (8 bytes, padded/truncated as needed).
 */
export type KdfContext = 
  | 'crust___'  // Crust identity keys
  | 'icp_____'  // ICP identity keys  
  | 'encrypt_'; // Encryption keys
```

### 3.3 Size Constants

```typescript
/** Cryptographic size constants */
export const SIZES = {
  /** Symmetric key size (XChaCha20-Poly1305) */
  SYMMETRIC_KEY: 32,
  
  /** XChaCha20-Poly1305 nonce size */
  NONCE: 24,
  
  /** Poly1305 authentication tag size */
  AUTH_TAG: 16,
  
  /** crypto_secretstream header size */
  STREAM_HEADER: 24,
  
  /** crypto_secretstream per-chunk overhead */
  STREAM_CHUNK_OVERHEAD: 17,
  
  /** X25519 public key size */
  X25519_PUBLIC_KEY: 32,
  
  /** X25519 private key size */
  X25519_PRIVATE_KEY: 32,
  
  /** Ed25519 public key size */
  ED25519_PUBLIC_KEY: 32,
  
  /** Ed25519 private key size (includes public key) */
  ED25519_PRIVATE_KEY: 64,
  
  /** BIP-39 seed size */
  SEED: 64,
  
  /** SHA-256 output size */
  SHA256: 32,
  
  /** Sealed box total size for 32-byte payload */
  SEALED_BOX: 80,
  
  /** KDF context string size */
  KDF_CONTEXT: 8,
  
  /** Default chunk size for streaming encryption */
  DEFAULT_CHUNK: 64 * 1024, // 64KB
} as const;
```

---

## 4. Branded Types (`src/branded.ts`)

### 4.1 Design

Branded types prevent accidental misuse of byte arrays at compile time. A `SymmetricKey` cannot be passed where a `Nonce` is expected, even though both are `Uint8Array` at runtime.

Pattern: `Uint8Array & { readonly __brand: 'TypeName' }`

Type guards validate at runtime boundaries (user input, deserialization).

### 4.2 Interface

```typescript
// ============================================================
// Branded Type Definitions
// ============================================================

/** 32-byte symmetric encryption key */
export type SymmetricKey = Uint8Array & { readonly __brand: 'SymmetricKey' };

/** 24-byte nonce */
export type Nonce = Uint8Array & { readonly __brand: 'Nonce' };

/** Encrypted ciphertext (variable length) */
export type Ciphertext = Uint8Array & { readonly __brand: 'Ciphertext' };

/** Unique file identifier (content hash) */
export type FileId = Uint8Array & { readonly __brand: 'FileId' };

/** 24-byte crypto_secretstream header */
export type SecretstreamHeader = Uint8Array & { readonly __brand: 'SecretstreamHeader' };

/** 32-byte X25519 public key */
export type X25519PublicKey = Uint8Array & { readonly __brand: 'X25519PublicKey' };

/** 32-byte X25519 private key */
export type X25519PrivateKey = Uint8Array & { readonly __brand: 'X25519PrivateKey' };

/** 32-byte Ed25519 public key */
export type Ed25519PublicKey = Uint8Array & { readonly __brand: 'Ed25519PublicKey' };

/** 64-byte Ed25519 private key */
export type Ed25519PrivateKey = Uint8Array & { readonly __brand: 'Ed25519PrivateKey' };

/** 32-byte SHA-256 content hash */
export type ContentHash = Uint8Array & { readonly __brand: 'ContentHash' };

/** 64-byte BIP-39 derived seed */
export type Seed = Uint8Array & { readonly __brand: 'Seed' };

// ============================================================
// Type Guards (Runtime Validation)
// ============================================================

/**
 * Validate and brand as SymmetricKey.
 * @throws EncryptionError if not exactly 32 bytes
 */
export function asSymmetricKey(bytes: Uint8Array): SymmetricKey;

/**
 * Validate and brand as Nonce.
 * @throws EncryptionError if not exactly 24 bytes
 */
export function asNonce(bytes: Uint8Array): Nonce;

/**
 * Brand as Ciphertext (no size validation — variable length).
 */
export function asCiphertext(bytes: Uint8Array): Ciphertext;

/**
 * Validate and brand as FileId.
 * @throws EncryptionError if not exactly 32 bytes
 */
export function asFileId(bytes: Uint8Array): FileId;

/**
 * Validate and brand as SecretstreamHeader.
 * @throws EncryptionError if not exactly 24 bytes
 */
export function asSecretstreamHeader(bytes: Uint8Array): SecretstreamHeader;

/**
 * Validate and brand as X25519PublicKey.
 * @throws EncryptionError if not exactly 32 bytes
 */
export function asX25519PublicKey(bytes: Uint8Array): X25519PublicKey;

/**
 * Validate and brand as X25519PrivateKey.
 * @throws EncryptionError if not exactly 32 bytes
 */
export function asX25519PrivateKey(bytes: Uint8Array): X25519PrivateKey;

/**
 * Validate and brand as Ed25519PublicKey.
 * @throws EncryptionError if not exactly 32 bytes
 */
export function asEd25519PublicKey(bytes: Uint8Array): Ed25519PublicKey;

/**
 * Validate and brand as Ed25519PrivateKey.
 * @throws EncryptionError if not exactly 64 bytes
 */
export function asEd25519PrivateKey(bytes: Uint8Array): Ed25519PrivateKey;

/**
 * Validate and brand as ContentHash.
 * @throws EncryptionError if not exactly 32 bytes
 */
export function asContentHash(bytes: Uint8Array): ContentHash;

/**
 * Validate and brand as Seed.
 * @throws EncryptionError if not exactly 64 bytes
 */
export function asSeed(bytes: Uint8Array): Seed;

// ============================================================
// Unsafe Branding (No Validation)
// ============================================================

/**
 * Brand without validation. Use only when source is trusted
 * (e.g., output from libsodium functions).
 */
export const unsafe: {
  asSymmetricKey(bytes: Uint8Array): SymmetricKey;
  asNonce(bytes: Uint8Array): Nonce;
  asCiphertext(bytes: Uint8Array): Ciphertext;
  asFileId(bytes: Uint8Array): FileId;
  asSecretstreamHeader(bytes: Uint8Array): SecretstreamHeader;
  asX25519PublicKey(bytes: Uint8Array): X25519PublicKey;
  asX25519PrivateKey(bytes: Uint8Array): X25519PrivateKey;
  asEd25519PublicKey(bytes: Uint8Array): Ed25519PublicKey;
  asEd25519PrivateKey(bytes: Uint8Array): Ed25519PrivateKey;
  asContentHash(bytes: Uint8Array): ContentHash;
  asSeed(bytes: Uint8Array): Seed;
};
```

### 4.3 Implementation Notes

- Type guards throw `EncryptionError` with appropriate code on validation failure
- `unsafe` namespace is for internal use where bytes come from trusted sources (libsodium output)
- Branded types are erased at runtime — zero overhead
- All branding functions return the same reference (no copy)

---

## 5. Byte Utilities (`src/bytes.ts`)

### 5.1 Design

Pure functions for byte array manipulation. No crypto operations, just encoding/decoding and concatenation.

### 5.2 Interface

```typescript
/**
 * Concatenate multiple Uint8Arrays into one.
 * @param arrays - Arrays to concatenate
 * @returns New Uint8Array containing all input bytes
 */
export function concat(...arrays: readonly Uint8Array[]): Uint8Array;

/**
 * Convert bytes to lowercase hex string.
 * @param bytes - Input bytes
 * @returns Hex string (lowercase, no prefix)
 */
export function toHex(bytes: Uint8Array): string;

/**
 * Parse hex string to bytes.
 * @param hex - Hex string (with or without 0x prefix, case-insensitive)
 * @returns Decoded bytes
 * @throws Error if invalid hex
 */
export function fromHex(hex: string): Uint8Array;

/**
 * Convert bytes to base64 string.
 * @param bytes - Input bytes
 * @returns Base64 encoded string (standard alphabet)
 */
export function toBase64(bytes: Uint8Array): string;

/**
 * Parse base64 string to bytes.
 * @param base64 - Base64 string
 * @returns Decoded bytes
 * @throws Error if invalid base64
 */
export function fromBase64(base64: string): Uint8Array;

/**
 * Convert bytes to URL-safe base64 string.
 * @param bytes - Input bytes
 * @returns Base64url encoded string (no padding)
 */
export function toBase64Url(bytes: Uint8Array): string;

/**
 * Parse URL-safe base64 string to bytes.
 * @param base64url - Base64url string (with or without padding)
 * @returns Decoded bytes
 * @throws Error if invalid base64url
 */
export function fromBase64Url(base64url: string): Uint8Array;

/**
 * Check if two byte arrays are equal (not constant-time).
 * For non-sensitive comparisons only.
 * @param a - First array
 * @param b - Second array
 * @returns true if equal length and contents
 */
export function equals(a: Uint8Array, b: Uint8Array): boolean;

/**
 * Create a copy of a byte array.
 * @param bytes - Input bytes
 * @returns New Uint8Array with same contents
 */
export function copy(bytes: Uint8Array): Uint8Array;

/**
 * Create a view into a byte array (no copy).
 * @param bytes - Input bytes
 * @param start - Start offset
 * @param length - Length of view
 * @returns Uint8Array view (shares underlying buffer)
 */
export function slice(bytes: Uint8Array, start: number, length: number): Uint8Array;
```

### 5.3 Implementation Notes

- `concat` pre-calculates total length to avoid reallocations
- Hex/base64 use native TextEncoder/atob where available
- `equals` is NOT constant-time — use `memory.constantTimeEqual` for sensitive comparisons
- `slice` returns a view (not a copy) for efficiency

---

## 6. Memory Utilities (`src/memory.ts`)

### 6.1 Design

Best-effort memory security utilities. JavaScript/WASM cannot guarantee secure memory clearing, but we make reasonable attempts.

### 6.2 Interface

```typescript
/**
 * Attempt to zero out sensitive data in memory.
 * 
 * ⚠️ LIMITATION: JavaScript cannot guarantee memory is cleared.
 * GC may copy data, optimizer may elide writes, etc.
 * This is best-effort only.
 * 
 * @param bytes - Array to zero (modified in place)
 */
export function secureZero(bytes: Uint8Array): void;

/**
 * Constant-time comparison of two byte arrays.
 * Prevents timing side-channel attacks.
 * 
 * Uses libsodium's sodium_memcmp internally.
 * 
 * @param a - First array
 * @param b - Second array
 * @returns true if equal length and contents
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): Promise<boolean>;

/**
 * Fill array with cryptographically secure random bytes.
 * 
 * Uses libsodium's randombytes_buf internally.
 * 
 * @param bytes - Array to fill (modified in place)
 */
export function randomFill(bytes: Uint8Array): Promise<void>;

/**
 * Generate new array of cryptographically secure random bytes.
 * 
 * @param length - Number of bytes
 * @returns New Uint8Array filled with random bytes
 */
export function randomBytes(length: number): Promise<Uint8Array>;

/**
 * Execute callback with a temporary buffer that's zeroed after use.
 * 
 * @param size - Buffer size
 * @param fn - Callback receiving the buffer
 * @returns Result of callback
 */
export function withSecureBuffer<T>(
  size: number,
  fn: (buffer: Uint8Array) => T | Promise<T>
): Promise<T>;
```

### 6.3 Implementation Notes

- `secureZero` wraps `sodium.memzero()` when available, falls back to manual fill
- `constantTimeEqual` is async because it requires libsodium initialization
- `withSecureBuffer` ensures cleanup even if callback throws
- All random functions use libsodium's CSPRNG (via `randombytes_buf`)

### 6.4 Security Documentation

Include JSDoc comments documenting limitations:

```typescript
/**
 * @security This function provides best-effort memory clearing.
 * In JavaScript/WASM environments, secure memory clearing cannot
 * be guaranteed due to:
 * - Garbage collector may copy data before clearing
 * - JIT optimizer may elide the clearing operation
 * - String interning may retain copies
 * 
 * For high-security applications, consider native implementations.
 */
```

---

## 7. Testing Requirements

### 7.1 Test Files

| File | Coverage |
|------|----------|
| `tests/errors.test.ts` | Error creation, type guards, error chaining |
| `tests/branded.test.ts` | Type guards accept/reject, unsafe branding |
| `tests/bytes.test.ts` | All encoding roundtrips, edge cases |
| `tests/memory.test.ts` | Zero fills, random generation |

### 7.2 Test Cases

**errors.test.ts:**
- Each error code creates error with correct code and message
- Factory functions include context in message
- `isEncryptionError` returns true for EncryptionError, false for other errors
- Error cause is preserved

**branded.test.ts:**
- Type guards accept correctly sized arrays
- Type guards throw for wrong sizes
- `unsafe` namespace bypasses validation
- Branded values can be used as Uint8Array

**bytes.test.ts:**
- `concat` handles empty arrays, single array, multiple arrays
- `toHex`/`fromHex` roundtrip
- `fromHex` handles 0x prefix, uppercase
- `fromHex` throws on invalid characters, odd length
- `toBase64`/`fromBase64` roundtrip
- `toBase64Url`/`fromBase64Url` roundtrip
- `equals` returns true for equal arrays, false for different
- `slice` returns view (modification affects original)

**memory.test.ts:**
- `secureZero` fills with zeros
- `constantTimeEqual` returns true for equal, false for different
- `randomBytes` returns requested length
- `randomBytes` returns different values on each call
- `withSecureBuffer` zeros buffer after callback
- `withSecureBuffer` zeros buffer even on throw

---

## 8. Acceptance Criteria

### 8.1 Functional

- [ ] All dependencies installed and importable
- [ ] TypeScript compiles without errors
- [ ] All error codes defined and documented
- [ ] All branded types have type guards
- [ ] Byte utilities handle all encoding formats
- [ ] Memory utilities wrap libsodium correctly

### 8.2 Quality

- [ ] 100% test coverage for Phase 1 modules
- [ ] All public APIs have JSDoc comments
- [ ] Security limitations documented in memory.ts
- [ ] No any types in public API

### 8.3 Integration

- [ ] Modules import cleanly from each other
- [ ] No circular dependencies
- [ ] Exports work via package entry point

---

## 9. Dependencies on Later Phases

Phase 1 modules have no dependencies on later phases. They will be consumed by:

- **Phase 2:** `sodium.ts` uses `memory.ts`; `hash.ts` uses `bytes.ts`, `branded.ts`
- **Phase 3:** `encryption.ts` uses all Phase 1 modules
- **Phase 4:** `key-wrapping.ts` uses all Phase 1 modules

---

## 10. Open Questions

None for Phase 1. All decisions are straightforward utility implementations.

---

## Appendix: Quick Reference

### File → Exports

| File | Primary Exports |
|------|-----------------|
| `errors.ts` | `ErrorCode`, `EncryptionError`, factory functions |
| `types.ts` | Interfaces, `SIZES` constants |
| `branded.ts` | Branded types, type guards, `unsafe` namespace |
| `bytes.ts` | `concat`, `toHex`, `fromHex`, `toBase64`, `fromBase64`, etc. |
| `memory.ts` | `secureZero`, `constantTimeEqual`, `randomBytes`, `withSecureBuffer` |
