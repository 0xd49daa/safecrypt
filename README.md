# @0xd49daa/safecrypt

A type-safe, opinionated encryption library built on libsodium. Designed to make the secure path the only path.

## Why This Library?

Most cryptographic libraries are toolboxes — they offer flexibility but require developers to be security experts to avoid mistakes. This library takes a different approach: **it makes secure defaults the only option**.

### The Problem with Existing Solutions

**1. Easy to Misuse**

Traditional crypto libraries expose too many knobs: cipher modes, padding schemes, key sizes, nonce handling. Each choice is an opportunity for error. A developer might accidentally reuse a nonce, pick a non-AEAD cipher, or mishandle key material.

**2. Type-Unsafe**

In JavaScript, keys, nonces, hashes, and ciphertext are all just `Uint8Array`. It's trivially easy to pass a nonce where a key is expected — and the code will happily run, producing garbage or worse.

```typescript
// Typical library - compiles fine, fails silently or catastrophically
encrypt(nonce, key, data)  // Oops, swapped key and nonce
```

**3. Low-Level APIs**

Most libraries provide primitives (`encrypt`, `decrypt`) but leave developers to figure out key wrapping, streaming encryption, and key derivation on their own.

### How This Library Solves It

**Opinionated Defaults**

One algorithm per task. No configuration needed. XChaCha20-Poly1305 for symmetric encryption. X25519 for key exchange. Ed25519 for signing. These are modern, secure, and hard to misuse.

**Branded Types**

The TypeScript compiler prevents you from mixing up cryptographic values:

```typescript
// This library - compile-time error
const key: SymmetricKey = generateKey();
const nonce: Nonce = ...;
encrypt(nonce, key, data)  // Error: Argument of type 'Nonce' is not assignable to 'SymmetricKey'
```

**Use-Case Driven APIs**

High-level APIs that map to real tasks:

- **Streaming encryption** — First-class support for large files with authenticated chunks
- **Key wrapping** — Secure key transport with `wrapKeyAuthenticated` and `wrapKeySeal`
- **Key derivation** — BIP-39 mnemonic → hierarchical key derivation built-in

## Installation

```bash
# JSR
bunx jsr add @0xd49daa/safecrypt

# Or with deno
deno add jsr:@0xd49daa/safecrypt
```

## Quick Start

```typescript
import {
  EncryptionProvider,
  KeyWrappingProvider,
  KeyDerivation
} from "@0xd49daa/safecrypt";

// Initialize (required once)
await EncryptionProvider.init();

// Generate a key and encrypt
const key = EncryptionProvider.generateKey();
const encrypted = await EncryptionProvider.encrypt(key, data);
const decrypted = await EncryptionProvider.decrypt(key, encrypted);

// Stream large files
const stream = EncryptionProvider.createChunkedEncryptStream(key, { fileId });
// ... pipe data through stream

// Wrap keys for sharing
const wrapped = KeyWrappingProvider.wrapKeyAuthenticated(
  fileKey,
  recipientPublicKey,
  senderSecretKey
);
```

## Core Concepts

| Provider | Purpose |
|----------|---------|
| `EncryptionProvider` | Symmetric encryption (single-shot & streaming) |
| `KeyWrappingProvider` | Asymmetric key wrapping (seal & authenticated) |
| `KeyDerivation` | BIP-39 mnemonic → deterministic key hierarchy |
| `HashProvider` | SHA-256 (IPFS compatible) & BLAKE2b |

## Cryptographic Primitives

| Task | Algorithm | Why |
|------|-----------|-----|
| Symmetric encryption | XChaCha20-Poly1305 | AEAD, 192-bit nonce (safe random), no key rotation needed |
| Key exchange | X25519 | Modern ECDH, 128-bit security |
| Signing | Ed25519 | Fast, deterministic, no nonce issues |
| Hashing | SHA-256 / BLAKE2b | SHA-256 for compatibility, BLAKE2b for speed |
| KDF | crypto_kdf (BLAKE2b) | Domain separation via context strings |

## Philosophy

> "While other solutions provide raw cryptographic blades and handles, this library provides safety knives designed for specific jobs."

- **Secure by default** — No insecure options to choose from
- **Type-safe** — Compiler catches mixing up keys, nonces, ciphertext
- **Batteries included** — Key derivation, wrapping, streaming out of the box
- **Minimal surface** — Less code = fewer bugs = easier audits

## License

MIT

## Links

- [Repository](https://github.com/0xd49daa/safecrypt)
- [JSR Package](https://jsr.io/@0xd49daa/safecrypt)
