# Phase 2: Core Crypto — Technical Specification

## Overview

Phase 2 implements the core cryptographic utilities: libsodium singleton, hashing, and key derivation. These provide the foundation for encryption and key wrapping in later phases.

## Files to Implement

| File | Purpose | Dependencies |
|------|---------|--------------|
| `src/sodium.ts` | libsodium singleton | libsodium-wrappers |
| `src/hash.ts` | SHA-256 + BLAKE2b hashing | sodium.ts, branded.ts |
| `src/key-derivation.ts` | BIP-39 + KDF | sodium.ts, branded.ts, @scure/bip39 |

---

## 1. src/sodium.ts — libsodium Singleton

### Purpose

Centralized libsodium initialization with lazy loading and preload hint.

### Migration Note

The existing `getSodium()` in `memory.ts` (lines 1-12) will be replaced with an import from this module. This is a **breaking internal change** — memory.ts must import from sodium.ts.

### API

```typescript
import type libsodium from 'libsodium-wrappers';

export async function getSodium(): Promise<typeof libsodium>;
export async function preloadSodium(): Promise<void>;
```

### Implementation

```typescript
import type libsodium from 'libsodium-wrappers';

let sodiumInstance: typeof libsodium | null = null;
let initPromise: Promise<typeof libsodium> | null = null;

export async function getSodium(): Promise<typeof libsodium> {
  if (sodiumInstance) {
    return sodiumInstance;
  }
  if (!initPromise) {
    initPromise = initializeSodium();
  }
  return initPromise;
}

async function initializeSodium(): Promise<typeof libsodium> {
  const sodium = await import('libsodium-wrappers');
  await sodium.default.ready;
  sodiumInstance = sodium.default;
  return sodiumInstance;
}

export async function preloadSodium(): Promise<void> {
  await getSodium();
}
```

### Key Design Decisions

1. **Race condition protection**: Use `initPromise` to prevent multiple concurrent initializations
2. **Return cached instance**: Once initialized, return immediately without async
3. **preloadSodium**: Simple wrapper for eager initialization at app startup

### Changes to memory.ts

Replace lines 1-12 with:

```typescript
import { getSodium } from './sodium.ts';
```

Remove the local `getSodium` function and `sodiumInstance` variable.

---

## 2. src/hash.ts — HashProvider

### Purpose

Provide SHA-256 (for IPFS CID compatibility) and BLAKE2b (for fast internal hashing).

### API

```typescript
import type { ContentHash } from './branded.ts';
import type { StreamingHasher } from './types.ts';

export async function hash(data: Uint8Array): Promise<ContentHash>;
export function createHasher(): StreamingHasher;
export async function hashBlake2b(data: Uint8Array, outlen?: number): Promise<Uint8Array>;
```

### Implementation Details

#### hash(data) — SHA-256 via Web Crypto

```typescript
import { unsafe } from './branded.ts';
import type { ContentHash } from './branded.ts';

export async function hash(data: Uint8Array): Promise<ContentHash> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return unsafe.asContentHash(new Uint8Array(hashBuffer));
}
```

**Why Web Crypto?** IPFS CIDs use SHA-256. Using Web Crypto ensures byte-identical hashes for CID verification.

#### createHasher() — Streaming SHA-256

Web Crypto does NOT support streaming directly. Workaround: accumulate chunks, hash on `digest()`.

```typescript
import type { StreamingHasher } from './types.ts';
import { unsafe } from './branded.ts';

export function createHasher(): StreamingHasher {
  const chunks: Uint8Array[] = [];
  let totalLength = 0;

  return {
    update(data: Uint8Array): void {
      chunks.push(data);
      totalLength += data.length;
    },
    async digest(): Promise<Uint8Array> {
      const combined = new Uint8Array(totalLength);
      let offset = 0;
      for (const chunk of chunks) {
        combined.set(chunk, offset);
        offset += chunk.length;
      }
      const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
      return new Uint8Array(hashBuffer);
    },
  };
}
```

**Limitation**: This accumulates all data in memory. For truly streaming use cases with large files, callers should hash chunks incrementally and combine differently.

#### hashBlake2b(data, outlen?) — BLAKE2b via libsodium

```typescript
import { getSodium } from './sodium.ts';

export async function hashBlake2b(
  data: Uint8Array,
  outlen: number = 32
): Promise<Uint8Array> {
  const sodium = await getSodium();
  return sodium.crypto_generichash(outlen, data);
}
```

**Output length**: Default 32 bytes (256 bits). libsodium supports 16-64 bytes.

### Type Definitions

The `StreamingHasher` type already exists in `types.ts`:

```typescript
export type StreamingHasher = {
  update(data: Uint8Array): void;
  digest(): Promise<Uint8Array>;
};
```

---

## 3. src/key-derivation.ts — KeyDerivation

### Purpose

Derive deterministic keys from BIP-39 mnemonic for:
- Crust blockchain identity (Ed25519)
- ICP canister identity (Ed25519)
- File encryption (X25519)

### API

```typescript
import type { Seed, X25519PublicKey, X25519PrivateKey, Ed25519PublicKey, Ed25519PrivateKey } from './branded.ts';
import type { KdfContext, X25519KeyPair, Ed25519KeyPair } from './types.ts';

export const CONTEXT_CRUST: KdfContext = 'crust___';
export const CONTEXT_ICP: KdfContext = 'icp_____';
export const CONTEXT_ENCRYPT: KdfContext = 'encrypt_';

export async function deriveSeed(mnemonic: string, passphrase?: string): Promise<Seed>;
export async function deriveSubkey(masterKey: Uint8Array, subkeyId: number, context: KdfContext): Promise<Uint8Array>;
export async function deriveEncryptionKeyPair(seed: Seed, index: number): Promise<X25519KeyPair>;
export async function deriveIdentityKeyPair(seed: Seed, context: KdfContext, index: number): Promise<Ed25519KeyPair>;
```

### Implementation Details

#### Context Constants

```typescript
import type { KdfContext } from './types.ts';

export const CONTEXT_CRUST: KdfContext = 'crust___';
export const CONTEXT_ICP: KdfContext = 'icp_____';
export const CONTEXT_ENCRYPT: KdfContext = 'encrypt_';
```

All contexts are exactly 8 bytes (padded with underscores).

#### deriveSeed(mnemonic, passphrase?)

```typescript
import { mnemonicToSeed, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { invalidMnemonic } from './errors.ts';
import { unsafe } from './branded.ts';
import type { Seed } from './branded.ts';

export async function deriveSeed(mnemonic: string, passphrase: string = ''): Promise<Seed> {
  const normalized = mnemonic.trim().toLowerCase().replace(/\s+/g, ' ');

  if (!validateMnemonic(normalized, wordlist)) {
    throw invalidMnemonic('invalid BIP-39 mnemonic');
  }

  const seed = await mnemonicToSeed(normalized, passphrase);
  return unsafe.asSeed(seed);
}
```

**Key points**:
1. Normalize mnemonic (trim, lowercase, collapse whitespace)
2. Validate against BIP-39 English wordlist
3. Throw `INVALID_MNEMONIC` error on failure
4. Return branded 64-byte Seed

#### deriveSubkey(masterKey, subkeyId, context)

```typescript
import { getSodium } from './sodium.ts';
import type { KdfContext } from './types.ts';

export async function deriveSubkey(
  masterKey: Uint8Array,
  subkeyId: number,
  context: KdfContext
): Promise<Uint8Array> {
  const sodium = await getSodium();
  return sodium.crypto_kdf_derive_from_key(
    32,
    subkeyId,
    context,
    masterKey.slice(0, 32)
  );
}
```

**Note**: `crypto_kdf_derive_from_key` expects a 32-byte master key. We slice the seed to 32 bytes.

#### deriveEncryptionKeyPair(seed, index)

```typescript
import { getSodium } from './sodium.ts';
import { unsafe } from './branded.ts';
import type { Seed } from './branded.ts';
import type { X25519KeyPair } from './types.ts';

export async function deriveEncryptionKeyPair(seed: Seed, index: number): Promise<X25519KeyPair> {
  const subkey = await deriveSubkey(seed, index, CONTEXT_ENCRYPT);
  const sodium = await getSodium();
  const keypair = sodium.crypto_box_seed_keypair(subkey);

  return {
    publicKey: unsafe.asX25519PublicKey(keypair.publicKey),
    privateKey: unsafe.asX25519PrivateKey(keypair.privateKey),
  };
}
```

#### deriveIdentityKeyPair(seed, context, index)

```typescript
import { getSodium } from './sodium.ts';
import { unsafe } from './branded.ts';
import type { Seed } from './branded.ts';
import type { KdfContext, Ed25519KeyPair } from './types.ts';

export async function deriveIdentityKeyPair(
  seed: Seed,
  context: KdfContext,
  index: number
): Promise<Ed25519KeyPair> {
  const subkey = await deriveSubkey(seed, index, context);
  const sodium = await getSodium();
  const keypair = sodium.crypto_sign_seed_keypair(subkey);

  return {
    publicKey: unsafe.asEd25519PublicKey(keypair.publicKey),
    privateKey: unsafe.asEd25519PrivateKey(keypair.privateKey),
  };
}
```

### Key Derivation Hierarchy

```
BIP-39 Mnemonic (24 words)
  │
  └─► deriveSeed(mnemonic) → Seed (64 bytes)
       │
       ├─► deriveSubkey(seed, 0, 'encrypt_') → 32-byte subkey
       │    └─► crypto_box_seed_keypair → X25519 keypair
       │
       ├─► deriveSubkey(seed, 0, 'crust___') → 32-byte subkey
       │    └─► crypto_sign_seed_keypair → Ed25519 keypair (Crust)
       │
       └─► deriveSubkey(seed, 0, 'icp_____') → 32-byte subkey
            └─► crypto_sign_seed_keypair → Ed25519 keypair (ICP)
```

**Index parameter**: Allows multiple keypairs for the same purpose. Index 0 is primary.

---

## 4. Updates to src/index.ts

Add Phase 2 exports:

```typescript
// sodium.ts
export { getSodium, preloadSodium } from './sodium.ts';

// hash.ts
export { hash, createHasher, hashBlake2b } from './hash.ts';

// key-derivation.ts
export {
  CONTEXT_CRUST,
  CONTEXT_ICP,
  CONTEXT_ENCRYPT,
  deriveSeed,
  deriveSubkey,
  deriveEncryptionKeyPair,
  deriveIdentityKeyPair,
} from './key-derivation.ts';
```

---

## 5. Test Requirements

### tests/sodium.test.ts

```typescript
describe('sodium', () => {
  describe('getSodium', () => {
    it('returns libsodium instance');
    it('returns same instance on multiple calls');
    it('handles concurrent initialization');
  });

  describe('preloadSodium', () => {
    it('initializes sodium without returning instance');
  });
});
```

### tests/hash.test.ts

```typescript
describe('hash', () => {
  describe('hash()', () => {
    it('returns 32-byte SHA-256 hash');
    it('matches known test vectors');
    it('handles empty input');
    it('handles large input');
  });

  describe('createHasher()', () => {
    it('produces same hash as single-shot');
    it('handles multiple updates');
    it('handles empty updates');
  });

  describe('hashBlake2b()', () => {
    it('returns 32-byte hash by default');
    it('supports custom output length');
    it('matches libsodium test vectors');
  });
});
```

### tests/key-derivation.test.ts

```typescript
describe('key-derivation', () => {
  describe('deriveSeed', () => {
    it('derives 64-byte seed from valid mnemonic');
    it('produces deterministic seed');
    it('handles optional passphrase');
    it('throws INVALID_MNEMONIC for invalid mnemonic');
    it('normalizes whitespace');
  });

  describe('deriveSubkey', () => {
    it('derives 32-byte subkey');
    it('produces different keys for different indices');
    it('produces different keys for different contexts');
  });

  describe('deriveEncryptionKeyPair', () => {
    it('derives valid X25519 keypair');
    it('produces deterministic keypairs');
    it('produces different keypairs for different indices');
  });

  describe('deriveIdentityKeyPair', () => {
    it('derives valid Ed25519 keypair');
    it('produces deterministic keypairs');
    it('produces different keypairs for different contexts');
    it('produces different keypairs for different indices');
  });

  describe('determinism', () => {
    it('same mnemonic + index produces identical keys across calls');
  });
});
```

---

## 6. Implementation Order

1. **src/sodium.ts** — Foundation for all crypto operations
2. **Update src/memory.ts** — Import getSodium from sodium.ts
3. **src/hash.ts** — Depends on sodium.ts
4. **src/key-derivation.ts** — Depends on sodium.ts
5. **Update src/index.ts** — Export new modules
6. **Tests** — One test file per module

---

## 7. Security Considerations

### Mnemonic Handling

- Mnemonics are sensitive. Callers should clear mnemonic strings after use
- Library cannot guarantee JavaScript string memory clearing

### Seed Handling

- 64-byte seed is the master secret
- Use `withSecureBuffer` pattern when possible
- Clear seeds after deriving keypairs

### Key Derivation Determinism

- **CRITICAL**: Same mnemonic + passphrase + context + index MUST produce identical keys
- This enables cross-device recovery
- Test this property explicitly

---

## 8. Known Limitations

### Streaming Hash Memory

`createHasher()` accumulates all chunks in memory before hashing. For files larger than available memory, callers should:
1. Hash file in fixed-size chunks
2. Use a different streaming approach

This is a Web Crypto limitation — it doesn't support incremental SHA-256.

### BLAKE2b Output Length

libsodium's `crypto_generichash` supports 16-64 bytes. No validation added — libsodium will throw on invalid lengths.
