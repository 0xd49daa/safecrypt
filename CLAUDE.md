# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

General-purpose TypeScript encryption library providing symmetric encryption, asymmetric key wrapping, key derivation, and hashing using libsodium.

**Runtime:** Browser (primary), Bun (secondary)
**Foundation:** libsodium-wrappers + @scure/bip39

## Development Commands

```bash
bun install              # Install dependencies
bun test                 # Run tests
bun test --watch         # Run tests in watch mode
bun test src/hash.test.ts  # Run single test file
bun run index.ts         # Run entry point
```

## Architecture

### Planned File Structure

```
src/
  sodium.ts         # libsodium singleton initialization (lazy)
  encryption.ts     # EncryptionProvider (secretbox, secretstream)
  key-wrapping.ts   # KeyWrappingProvider (seal, box)
  hash.ts           # HashProvider (SHA-256, BLAKE2b)
  key-derivation.ts # KeyDerivation (BIP-39 + crypto_kdf)
  types.ts          # Type definitions
  branded.ts        # Branded types for type safety
  bytes.ts          # Byte utilities (concat, hex, base64)
  memory.ts         # Memory utilities (memzero)
  errors.ts         # Error classes
  index.ts          # Public exports
examples/worker/    # Web Worker implementation example
tests/              # Test suite
```

### Core Providers

**EncryptionProvider** — Symmetric encryption
- `encrypt/decrypt` — Single-shot XChaCha20-Poly1305 (<64KB)
- `createChunkedEncryptStream/createChunkedDecryptStream` — Streaming via crypto_secretstream
- `generateKey()` — 32-byte random key (CRITICAL: unique per file)

**KeyWrappingProvider** — Asymmetric key wrapping
- `crypto_box_seal` — Anonymous wrapping for self-encryption
- `crypto_box` — Authenticated wrapping for sharing (ALWAYS use for user-to-user)

**HashProvider** — Hashing
- `hash()` — SHA-256 via Web Crypto (IPFS compatibility)
- `hashBlake2b()` — Fast hashing for internal use

**KeyDerivation** — Key hierarchy
- BIP-39 mnemonic → 64-byte seed → crypto_kdf subkeys → purpose-specific keypairs

### Key Derivation Contexts (8 bytes)

Users define their own 8-character context strings for domain separation:

```typescript
// Example contexts (define your own)
const CONTEXT_AUTH = 'auth____';    // 8 chars
const CONTEXT_SIGN = 'signing_';    // 8 chars
```

| Keypair Function | Context | Keypair Type |
|------------------|---------|--------------|
| `deriveEncryptionKeyPair()` | `encrypt_` (internal) | X25519 |
| `deriveIdentityKeyPair()` | User-defined | Ed25519 |

Context must be exactly 8 ASCII characters.

## Cryptographic Primitives

| Primitive | Algorithm | libsodium Function |
|-----------|-----------|-------------------|
| Symmetric (single) | XChaCha20-Poly1305 | `crypto_secretbox` |
| Symmetric (stream) | XChaCha20-Poly1305 | `crypto_secretstream` |
| Key wrapping (anon) | X25519 + XSalsa20 | `crypto_box_seal` |
| Key wrapping (auth) | X25519 + XSalsa20 | `crypto_box_easy` |
| Key derivation | HKDF | `crypto_kdf_derive_from_key` |
| Hashing | SHA-256 | Web Crypto API |
| Hashing (fast) | BLAKE2b | `crypto_generichash` |
| Signing | Ed25519 | `crypto_sign_seed_keypair` |
| Random | CSPRNG | `randombytes_buf` |

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `libsodium-wrappers` | 0.7.15 | Core crypto |
| `@types/libsodium-wrappers` | 0.7.14 | TypeScript definitions |
| `@scure/bip39` | 1.4.0 | BIP-39 mnemonics |

## Critical Implementation Rules

1. **Generate unique key for EACH file** — Never reuse symmetric keys
2. **All operations async** — libsodium WASM init and Web Crypto are async
3. **Use branded types** — `SymmetricKey`, `Nonce`, `Ciphertext`, etc. for compile-time safety
4. **Prefer Uint8Array** — Accept Buffer as input (Uint8Array subclass)
5. **Use `crypto_box` for sharing** — Never use anonymous `crypto_box_seal` for user-to-user
6. **Pass fileId as AAD** — Defense-in-depth for chunked encryption
7. **Web Worker for >10MB files** — Prevents UI blocking

## Error Codes

| Code | Meaning |
|------|---------|
| `INVALID_KEY_SIZE` | Key not 32 bytes |
| `INVALID_NONCE_SIZE` | Nonce not 24 bytes |
| `DECRYPTION_FAILED` | Auth tag mismatch |
| `SEGMENT_AUTH_FAILED` | Chunk auth failed |
| `STREAM_TRUNCATED` | Missing TAG_FINAL |
| `INVALID_STREAM_HEADER` | Malformed header |
| `INVALID_MNEMONIC` | BIP-39 validation failed |
| `SENDER_MISMATCH` | Sender key doesn't match |
| `INVALID_CONTEXT_SIZE` | Context not 8 characters |

## Wire Formats

**Single-shot:** `{ nonce: Uint8Array(24), ciphertext: Uint8Array(len + 16) }`

**Streaming:** `[Header(24)][Chunk0(data + 17)]...[ChunkN with TAG_FINAL]`
- Header: 24 bytes
- Chunk overhead: 17 bytes (16-byte tag + 1-byte flag)
- Default chunk size: 64KB

**Sealed box (anon):** 80 bytes total
**Authenticated wrapped key:** 124 bytes total

## Security Boundaries

**Library guarantees:**
- Cryptographic correctness via libsodium
- No unverified plaintext release
- Nonce uniqueness, stream integrity

**Library cannot guarantee:**
- Memory security against local attackers
- Protection against compromised browser/OS
- Side-channel resistance in JS runtime

## Memory Hygiene

Use `sodium.memzero()` as best effort for key clearing. JavaScript cannot guarantee secure memory clearing — document this limitation.

## Testing Categories

1. Unit tests — Each function in isolation
2. Integration tests — Full encrypt/decrypt flows
3. Security tests — Context commitment, nonce safety, chunked AEAD
4. Cross-platform tests — Browser + Bun

Use libsodium official test vectors where available.
