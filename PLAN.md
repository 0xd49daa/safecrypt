# Implementation Plan

## Phase 1: Foundation ✅

1. **Project setup** ✅
   - Add dependencies: `libsodium-wrappers@0.7.15`, `@types/libsodium-wrappers@0.7.14`, `@scure/bip39@1.4.0`
   - Update package.json name to `@filemanager/encryption`

2. **src/errors.ts** ✅ — Error classes with codes
   - `INVALID_KEY_SIZE`, `INVALID_NONCE_SIZE`, `DECRYPTION_FAILED`, `SEGMENT_AUTH_FAILED`, `STREAM_TRUNCATED`, `INVALID_STREAM_HEADER`, `INVALID_MNEMONIC`, `SENDER_MISMATCH`

3. **src/types.ts** ✅ — Core type definitions
   - `EncryptedData`, `StreamHeader`, `KeyPair`, `WrappedKey`

4. **src/branded.ts** ✅ — Branded types + type guards
   - `SymmetricKey`, `Nonce`, `Ciphertext`, `FileId`, `SecretstreamHeader`
   - `X25519PublicKey`, `X25519PrivateKey`, `Ed25519PublicKey`, `Ed25519PrivateKey`
   - `ContentHash`, `Seed`
   - Type guards: `asSymmetricKey()`, `asX25519PublicKey()`, etc.

5. **src/bytes.ts** ✅ — Byte utilities
   - `concat()`, `toHex()`, `fromHex()`, `toBase64()`, `fromBase64()`

6. **src/memory.ts** ✅ — Memory utilities
   - `secureZero()` wrapping `sodium.memzero()`
   - `constantTimeEqual()` wrapping `sodium.memcmp()`

## Phase 2: Core Crypto ✅

7. **src/sodium.ts** ✅ — Singleton lazy init
   - `getSodium()` — Returns initialized libsodium instance (with race-condition protection)
   - `preloadSodium()` — Hint for early loading

8. **src/hash.ts** ✅ — HashProvider
   - `hash(data)` — SHA-256 via Web Crypto (IPFS CID compatible)
   - `createHasher()` — Streaming SHA-256 (accumulates chunks)
   - `hashBlake2b(data, outlen?)` — BLAKE2b via libsodium (default 32 bytes)

9. **src/key-derivation.ts** ✅ — KeyDerivation
   - `deriveSeed(mnemonic, passphrase?)` — BIP-39 → 64-byte seed (with validation + normalization)
   - `deriveSubkey(masterKey, subkeyId, context)` — crypto_kdf_derive_from_key
   - `deriveEncryptionKeyPair(seed, index)` — X25519 keypair via crypto_box_seed_keypair
   - `deriveIdentityKeyPair(seed, context, index)` — Ed25519 keypair via crypto_sign_seed_keypair
   - Context constants: `CONTEXT_CRUST`, `CONTEXT_ICP`, `CONTEXT_ENCRYPT`
   - Types: `X25519KeyPair`, `Ed25519KeyPair`

**Tests:** 137 tests passing (89 Phase 1 + 48 Phase 2)

## Phase 3: Encryption ✅

10. **src/encryption.ts** ✅ — EncryptionProvider
    - `generateKey()` — 32-byte random via `randombytes_buf`
    - `encrypt(plaintext, key, context?)` — Single-shot XChaCha20-Poly1305
    - `decrypt(ciphertext, nonce, key, context?)` — Single-shot decryption
    - `createEncryptStream(key, fileId?)` — crypto_secretstream push
    - `createDecryptStream(key, header, fileId?)` — crypto_secretstream pull

**Tests:** 166 tests passing (137 Phase 1+2 + 29 Phase 3)

## Phase 4: Key Wrapping ✅

11. **src/key-wrapping.ts** ✅ — KeyWrappingProvider
    - `wrapKeySeal(key, recipientPub)` — Anonymous seal (80 bytes output)
    - `wrapKeySealMulti(key, recipientPubs[])` — Multi-recipient anonymous
    - `unwrapKeySeal(sealed, recipientKeyPair)` — Unseal
    - `wrapKeyAuthenticated(key, recipientPub, senderKeyPair)` — Authenticated box (104 bytes)
    - `wrapKeyAuthenticatedMulti(key, recipientPubs[], senderKeyPair)` — Multi-recipient auth
    - `unwrapKeyAuthenticated(wrapped, expectedSenderPub, recipientKeyPair)` — Verify + unwrap

**Tests:** 196 tests passing (166 Phase 1-3 + 30 Phase 4)

## Phase 5: Export, Testing & Web Worker

12. **src/index.ts** ✅ — Public exports
    - Export all providers, types, branded types, utilities
    - Complete public API already implemented

13. **tests/integration/** — Integration tests
    - `file-encryption.test.ts` — Full file encrypt/decrypt flows
    - `key-sharing.test.ts` — Multi-user key sharing flows
    - `recovery.test.ts` — Mnemonic recovery scenarios

14. **tests/security/** — Security tests
    - `nonce-safety.test.ts` — Nonce uniqueness verification
    - `context-commitment.test.ts` — AAD binding tests
    - `stream-integrity.test.ts` — Chunk reordering/truncation
    - `timing-attacks.test.ts` — Constant-time verification

15. **examples/worker/** — Web Worker example
    - `types.ts` — Shared types (request/response)
    - `crypto.worker.ts` — Comlink-based worker implementation
    - `index.ts` — Main thread API
    - `README.md` — Usage documentation

**Target:** 250+ tests (196 existing + 50+ integration/security)
