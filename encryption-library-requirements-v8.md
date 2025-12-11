# Encryption Library Technical Requirements

## Overview

TypeScript encryption library for browser-first decentralized storage system. Provides symmetric encryption, asymmetric key wrapping, key derivation, and hashing primitives.

**Package:** `@filemanager/encryption`  
**Runtime:** Browser (primary), Bun/Node (secondary)  
**Foundation:** libsodium (via libsodium-wrappers) + @scure/bip39

---

## Design Decision: libsodium over Custom Implementation

| Approach | Pros | Cons |
|----------|------|------|
| Custom (Web Crypto + @noble) | Small bundle (~50KB), native AES-GCM | Must implement chunked AEAD ourselves, more audit surface |
| **libsodium (chosen)** | Battle-tested, audited, crypto_secretstream built-in | Larger bundle (~150KB WASM) |

**Why libsodium wins:**
- **crypto_secretstream** — handles chunked AEAD with reordering/truncation protection built-in
- **XChaCha20-Poly1305** — 192-bit nonce (safe for random generation), safer API
- **Security over bundle size** — 150KB acceptable for cryptographic correctness
- **Less code** — ~80% reduction in crypto implementation

**Library:** `libsodium-wrappers` v0.7.15 (official, actively maintained)

---

## Cryptographic Primitives

| Primitive | Algorithm | Library | Purpose |
|-----------|-----------|---------|---------|
| Symmetric (single-shot) | XChaCha20-Poly1305 | libsodium `crypto_secretbox` | Small data |
| Symmetric (streaming) | XChaCha20-Poly1305 | libsodium `crypto_secretstream` | Chunked file encryption |
| Key exchange | X25519 | libsodium `crypto_kx` / `crypto_box` | Multi-recipient wrapping |
| Anonymous encryption | X25519 + XSalsa20-Poly1305 | libsodium `crypto_box_seal` | Key wrapping (self) |
| Key derivation (seed) | HKDF-SHA256 | libsodium `crypto_kdf` | Seed → purpose-specific keys |
| Key derivation (password) | Argon2id | libsodium `crypto_pwhash` | Optional password protection |
| Hashing (default) | BLAKE2b-256 | libsodium `crypto_generichash` | Streaming-friendly content integrity |
| Hashing (compat) | SHA-256 (optional) | Web Crypto API | Legacy integrations when required |
| Signing | Ed25519 | libsodium `crypto_sign` | Identity (Crust/ICP) |
| BIP-39 mnemonics | — | @scure/bip39 | User key backup |

---

## Public API

### Core Interfaces

**EncryptionProvider**
- `encrypt(plaintext, key, context?)` — Single-shot XChaCha20-Poly1305 for small data (<64KB)
- `decrypt(ciphertext, key, context?)` — Single-shot decryption
- `createChunkedEncryptStream(key, fileId)` — Streaming encryption via crypto_secretstream
- `createChunkedDecryptStream(key, header, fileId)` — Streaming decryption
- `generateKey()` — Generate 32-byte random key (CRITICAL: unique per file)

**KeyWrappingProvider**
- `wrapKeySeal(key, recipientPub)` — Anonymous wrapping for self-encryption
- `wrapKeySealMulti(key, recipientPubs[])` — Multi-recipient anonymous
- `unwrapKeySeal(sealed, recipientKeyPair)` — Unwrap sealed box
- `wrapKeyAuthenticated(key, recipientPub, senderKeyPair)` — Authenticated wrapping for sharing
- `wrapKeyAuthenticatedMulti(key, recipientPubs[], senderKeyPair)` — Multi-recipient authenticated
- `unwrapKeyAuthenticated(wrapped, expectedSenderPub, recipientKeyPair)` — Unwrap with sender verification

**HashProvider**
- `hashBlake2b(data, outlen?)` — Default BLAKE2b hashing (32-byte default) via libsodium
- `createHasher()` — Streaming BLAKE2b for large inputs
- `hash(data)` — Optional SHA-256 helper via Web Crypto when legacy interop needs it

**KeyDerivation**
- `deriveSeed(mnemonic, passphrase?)` — BIP-39 mnemonic → 64-byte seed
- `deriveKey(masterKey, subkeyId, context)` — libsodium crypto_kdf
- `deriveEncryptionKeyPair(seed, index)` — X25519 keypair for encryption
- `deriveIdentityKeyPair(seed, purpose, index)` — Ed25519 keypair for Crust/ICP

### Type Safety (Branded Types)

Use branded types to prevent confusion between keys, ciphertexts, and nonces at compile time:
- `SymmetricKey`, `Nonce`, `Ciphertext`
- `FileId`, `SecretstreamHeader`
- `X25519PublicKey`, `X25519PrivateKey`
- `Ed25519PublicKey`, `Ed25519PrivateKey`
- `ContentHash`, `Seed`

### Buffer Policy

Prefer `Uint8Array` in our code; accept `Buffer` as input (it's a Uint8Array subclass in Node/Bun).

---

## Functional Requirements

### FR-1: Symmetric Encryption

| Spec | Value |
|------|-------|
| Algorithm | XChaCha20-Poly1305 |
| Key size | 256 bits (32 bytes) |
| Nonce | 24 bytes, random (safe due to large nonce space) |
| Auth tag | 16 bytes (Poly1305) |
| AAD | Optional context binding for manifests/wrapped keys |

**Output format:** `{ nonce: Uint8Array(24), ciphertext: Uint8Array(len + 16) }`

### FR-2: Key Generation

| Spec | Value |
|------|-------|
| Source | libsodium `randombytes_buf` (CSPRNG) |
| Size | 32 bytes (256 bits) |
| Rule | **CRITICAL: Generate unique key for EACH file** |

### FR-3: Asymmetric Key Wrapping

| Method | Sender Auth | Use Case |
|--------|-------------|----------|
| `crypto_box_seal` | ✗ No | Self-encryption (own devices) |
| `crypto_box` | ✓ Yes | **Sharing between users** |

**CRITICAL:** Always use authenticated methods (`crypto_box`) when sharing between users to prevent impersonation attacks.

**Wire formats:**
- SealedBox (anonymous): 80 bytes total
- AuthenticatedWrappedKey: 124 bytes total

### FR-4: Key Derivation

**Hierarchy:**
```
BIP-39 Mnemonic (24 words)
  → Seed (64 bytes) via PBKDF2 (@scure/bip39)
    → crypto_kdf subkeys (libsodium)
      → Purpose-specific keypairs
```

**Context strings (8 bytes):**

| Purpose | Context | Function |
|---------|---------|----------|
| Crust identity | `crust___` | `crypto_sign_seed_keypair` (Ed25519) |
| ICP identity | `icp_____` | `crypto_sign_seed_keypair` (Ed25519) |
| Encryption | `encrypt_` | `crypto_box_seed_keypair` (X25519) |

**Recovery guarantee:** Same mnemonic + index → identical keypairs across devices.

### FR-5: Hashing

| Spec | Value |
|------|-------|
| Algorithm | BLAKE2b-256 (default) |
| Output | 32 bytes (configurable for internal use) |
| Streaming | Required for large files |
| Library | libsodium `crypto_generichash` |
| Compatibility | SHA-256 helper available when an integration explicitly requires it |

### FR-6: Chunked Streaming Encryption

**Algorithm:** XChaCha20-Poly1305 via `crypto_secretstream`

| Feature | Provided by crypto_secretstream |
|---------|--------------------------------|
| Per-chunk authentication | ✓ Built-in |
| Reordering protection | ✓ Built-in (state machine) |
| Truncation protection | ✓ Built-in (TAG_FINAL) |
| Nonce handling | ✓ Automatic (internal counter) |

**Defense-in-depth:** `fileId` passed as AAD prevents chunk swapping even if keys collide due to bugs.

**Wire format:** `[Header (24 bytes)][Chunk 0 (data + 17)]...[Chunk N with TAG_FINAL]`

| Component | Size |
|-----------|------|
| Header | 24 bytes |
| Chunk overhead | 17 bytes (16-byte tag + 1-byte flag) |
| Default chunk size | 64KB |

---

## Non-Functional Requirements

### NFR-1: Browser Compatibility

| Target | Spec |
|--------|------|
| Browsers | Chrome 90+, Firefox 90+, Safari 15+ |
| Crypto backend | libsodium (WASM) |
| Hash API | libsodium `crypto_generichash` (BLAKE2b) |
| Module format | ESM |

**⚠️ Main thread blocking risk:** For files >10MB, run crypto in Web Worker.

### NFR-2: Async Operations

All crypto operations MUST be async (Promise-based):
- libsodium WASM init is async
- Streaming hashing uses libsodium and stays async for API consistency
- Consistent API

**Init pattern:** Lazy initialization with preload hint.

### NFR-3: Memory Efficiency

| Constraint | Solution |
|------------|----------|
| Large files | Chunked streaming (crypto_secretstream) |
| Peak memory | ~2x chunk size (128KB for 64KB chunks) |

**Memory scrubbing:** JavaScript cannot guarantee secure clearing. Use `sodium.memzero()` as best effort; document limitation.

### NFR-4: Security Properties

**Must provide:**
- Confidentiality (encryption)
- Integrity (authentication tags)
- No unverified plaintext release
- Protection against chunk reordering/truncation/swapping

**Cannot guarantee (browser limitation):**
- Memory security against local attackers
- Protection against compromised browser/OS
- Side-channel resistance in JS runtime

### NFR-5: Bundle Size

| Component | Size |
|-----------|------|
| libsodium WASM | ~150KB |
| JS wrapper | ~15KB |
| @scure/bip39 + wordlist | ~200KB |
| Total | ~400KB |

Tree-shaking applies to JS code but not WASM binary.

### NFR-6: Type Safety

Use branded types for compile-time safety. Export type guards (`asSymmetricKey`, `asX25519PublicKey`, etc.) for runtime validation at boundaries.

### NFR-7: Cryptographic Hygiene

- Constant-time comparison via `sodium.memcmp()`
- Memory clearing via `sodium.memzero()` (best effort)
- Random generation via `sodium.randombytes_buf()`
- Short key scope (clear after use)

### NFR-8: Web Worker Architecture

For files >10MB, offload crypto to Web Worker to prevent UI blocking.

**Pattern:** Main thread handles file I/O; worker handles crypto. Use Comlink for ergonomic API. Transfer `Uint8Array` via structured clone (zero-copy).

**Provided:** Example implementation in `examples/worker/`.

---

## Dependencies

### Required (Pinned)

| Package | Version | Purpose |
|---------|---------|---------|
| `libsodium-wrappers` | 0.7.15 | Core crypto (XChaCha20, X25519, Ed25519) |
| `@types/libsodium-wrappers` | 0.7.14 | TypeScript definitions |
| `@scure/bip39` | 1.4.0 | BIP-39 mnemonic handling |

### Usage by Primitive

| Primitive | libsodium function |
|-----------|-------------------|
| Symmetric encryption | `crypto_aead_xchacha20poly1305_ietf_*` |
| Streaming | `crypto_secretstream_xchacha20poly1305_*` |
| Key wrapping (anon) | `crypto_box_seal`, `crypto_box_seal_open` |
| Key wrapping (auth) | `crypto_box_easy`, `crypto_box_open_easy` |
| Key derivation | `crypto_kdf_derive_from_key` |
| Ed25519 keypair | `crypto_sign_seed_keypair` |
| X25519 keypair | `crypto_box_seed_keypair` |
| Random | `randombytes_buf` |
| Memory | `memzero`, `memcmp` |

---

## Error Handling

### Error Types

| Code | Meaning |
|------|---------|
| `INVALID_KEY_SIZE` | Key not 32 bytes |
| `INVALID_NONCE_SIZE` | Nonce not 24 bytes |
| `DECRYPTION_FAILED` | Auth tag mismatch |
| `SEGMENT_AUTH_FAILED` | Chunk auth failed |
| `STREAM_TRUNCATED` | Missing TAG_FINAL |
| `INVALID_STREAM_HEADER` | Malformed header |
| `INVALID_MNEMONIC` | BIP-39 validation failed |
| `SENDER_MISMATCH` | Sender public key doesn't match expected |

---

## Testing Requirements

### Test Categories

1. **Unit tests** — Each function in isolation
2. **Integration tests** — Full encrypt/decrypt flows
3. **Security tests** — Attack vector coverage
4. **Performance tests** — Large file benchmarks
5. **Cross-platform tests** — Browser + Node/Bun

### Key Security Tests

- Context commitment (different context → decryption fails)
- Nonce safety (unique per encryption)
- Key binding (wrong key → fails)
- Chunked AEAD (reordering, truncation, swapping detection)
- State machine (proper state transitions)
- Backpressure (memory bounds during streaming)

### Test Vectors

Use libsodium official test vectors where available; generate reproducible vectors for integration tests.

---

## Security Considerations

### Platform Threat Model

| Aspect | Browser Reality |
|--------|-----------------|
| Memory control | No secure wipe, GC unpredictable |
| Side-channels | Spectre mitigations help, not eliminate |
| Key storage | Memory or IndexedDB (extractable) |
| RNG quality | `crypto.getRandomValues()` — good |

### Accepted Tradeoffs

| Tradeoff | Rationale |
|----------|-----------|
| No guaranteed memory wipe | Browser-first requirement; document limitation |
| WASM bundle size | Security over bundle size |
| Main thread default | Simplicity; use Worker for large files |

### Recommendations by Risk Level

| Risk | Recommendation |
|------|----------------|
| Standard | Browser library + YubiKey for mnemonic |
| High | Native client (Rust/Go) for key operations |
| Critical | Air-gapped signing device, hardware wallet |

### What This Library Guarantees

- Cryptographic correctness via libsodium
- No unverified plaintext release
- Protection against network attackers
- Key derivation determinism
- Nonce uniqueness
- Stream integrity

### What This Library Cannot Guarantee

- Memory security against local attackers
- Protection against compromised browser/OS
- Side-channel resistance in JS runtime

---

## Deliverables

| File | Description |
|------|-------------|
| `src/sodium.ts` | libsodium initialization (singleton, lazy) |
| `src/encryption.ts` | EncryptionProvider (crypto_secretbox, crypto_secretstream) |
| `src/key-wrapping.ts` | KeyWrappingProvider (crypto_box_seal, crypto_box) |
| `src/hash.ts` | HashProvider (libsodium BLAKE2b, optional Web Crypto SHA-256 helper) |
| `src/key-derivation.ts` | KeyDerivation (BIP-39 + crypto_kdf) |
| `src/types.ts` | Type definitions |
| `src/branded.ts` | Branded types |
| `src/bytes.ts` | Byte utilities (concat, hex, base64) |
| `src/memory.ts` | Memory utilities (sodium_memzero) |
| `src/errors.ts` | Error classes |
| `src/index.ts` | Public exports |
| `examples/worker/` | Web Worker implementation example |
| `tests/` | Test suite |

---

## References

### libsodium
- [Documentation](https://doc.libsodium.org/)
- [crypto_secretstream](https://doc.libsodium.org/secret-key_cryptography/secretstream)
- [crypto_secretbox](https://doc.libsodium.org/secret-key_cryptography/secretbox)
- [crypto_box_seal](https://doc.libsodium.org/public-key_cryptography/sealed_boxes)
- [crypto_box](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption)
- [crypto_kdf](https://doc.libsodium.org/key_derivation)
- [libsodium.js](https://github.com/jedisct1/libsodium.js)

### Standards
- [RFC 7748 - X25519](https://datatracker.ietf.org/doc/html/rfc7748)
- [RFC 8032 - Ed25519](https://datatracker.ietf.org/doc/html/rfc8032)
- [RFC 5869 - HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [XChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)

### Other
- [age encryption](https://age-encryption.org/v1) — chunked AEAD design inspiration
- [@scure/bip39](https://github.com/paulmillr/scure-bip39)
- [Comlink](https://github.com/GoogleChromeLabs/comlink) — Web Worker communication
