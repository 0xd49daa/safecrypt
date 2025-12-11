# Phase 4: Key Wrapping — Technical Specification

## Overview

Phase 4 implements the `KeyWrappingProvider` with both anonymous (`crypto_box_seal`) and authenticated (`crypto_box`) key wrapping. This enables secure distribution of per-file symmetric keys to one or more recipients.

**Use cases:**
- **Self-encryption**: Wrap keys for own devices (anonymous seal)
- **Sharing**: Wrap keys for other users with sender authentication (authenticated box)

## Files to Implement

| File | Purpose | Dependencies |
|------|---------|--------------|
| `src/key-wrapping.ts` | Asymmetric key wrapping (seal + box) | sodium.ts, branded.ts, types.ts, errors.ts |

---

## 1. src/key-wrapping.ts — KeyWrappingProvider

### Purpose

Provide asymmetric key wrapping for:
- Anonymous encryption via `crypto_box_seal` (no sender authentication)
- Authenticated encryption via `crypto_box` (sender identity verified)

### API

```typescript
import type { SymmetricKey, X25519PublicKey, X25519PrivateKey } from './branded.ts';
import type { X25519KeyPair } from './key-derivation.ts';

// Anonymous sealing (self-encryption)
export async function wrapKeySeal(
  key: SymmetricKey,
  recipientPublicKey: X25519PublicKey
): Promise<Uint8Array>;

export async function wrapKeySealMulti(
  key: SymmetricKey,
  recipientPublicKeys: readonly X25519PublicKey[]
): Promise<readonly Uint8Array[]>;

export async function unwrapKeySeal(
  sealedKey: Uint8Array,
  recipientKeyPair: X25519KeyPair
): Promise<SymmetricKey>;

// Authenticated wrapping (sharing between users)
export type AuthenticatedWrappedKey = {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly senderPublicKey: X25519PublicKey;
};

export async function wrapKeyAuthenticated(
  key: SymmetricKey,
  recipientPublicKey: X25519PublicKey,
  senderKeyPair: X25519KeyPair
): Promise<AuthenticatedWrappedKey>;

export async function wrapKeyAuthenticatedMulti(
  key: SymmetricKey,
  recipientPublicKeys: readonly X25519PublicKey[],
  senderKeyPair: X25519KeyPair
): Promise<readonly AuthenticatedWrappedKey[]>;

export async function unwrapKeyAuthenticated(
  wrapped: AuthenticatedWrappedKey,
  expectedSenderPublicKey: X25519PublicKey,
  recipientKeyPair: X25519KeyPair
): Promise<SymmetricKey>;
```

### Implementation Details

#### wrapKeySeal(key, recipientPublicKey)

```typescript
import { getSodium } from './sodium.ts';
import type { SymmetricKey, X25519PublicKey } from './branded.ts';

export async function wrapKeySeal(
  key: SymmetricKey,
  recipientPublicKey: X25519PublicKey
): Promise<Uint8Array> {
  const sodium = await getSodium();
  return sodium.crypto_box_seal(key, recipientPublicKey);
}
```

**Key points:**
1. Generates ephemeral X25519 keypair internally
2. Output: 80 bytes (32-byte key + 48-byte overhead)
3. No sender authentication — recipient cannot verify who sent it
4. Use for self-encryption only (wrapping keys for own devices)

#### wrapKeySealMulti(key, recipientPublicKeys)

```typescript
import { getSodium } from './sodium.ts';
import type { SymmetricKey, X25519PublicKey } from './branded.ts';

export async function wrapKeySealMulti(
  key: SymmetricKey,
  recipientPublicKeys: readonly X25519PublicKey[]
): Promise<readonly Uint8Array[]> {
  const sodium = await getSodium();
  return recipientPublicKeys.map((pubKey) =>
    sodium.crypto_box_seal(key, pubKey)
  );
}
```

**Key points:**
1. Returns array of sealed boxes, one per recipient
2. Each recipient can only unseal their own box
3. Same symmetric key wrapped for all recipients

#### unwrapKeySeal(sealedKey, recipientKeyPair)

```typescript
import { getSodium } from './sodium.ts';
import { unsafe } from './branded.ts';
import { decryptionFailed } from './errors.ts';
import type { SymmetricKey } from './branded.ts';
import type { X25519KeyPair } from './key-derivation.ts';

export async function unwrapKeySeal(
  sealedKey: Uint8Array,
  recipientKeyPair: X25519KeyPair
): Promise<SymmetricKey> {
  const sodium = await getSodium();

  try {
    const key = sodium.crypto_box_seal_open(
      sealedKey,
      recipientKeyPair.publicKey,
      recipientKeyPair.privateKey
    );
    return unsafe.asSymmetricKey(key);
  } catch (error) {
    throw decryptionFailed(error instanceof Error ? error : undefined);
  }
}
```

**Key points:**
1. Requires both public and private key of recipient
2. Throws `DECRYPTION_FAILED` if wrong keypair or tampered
3. Returns unwrapped 32-byte symmetric key

#### wrapKeyAuthenticated(key, recipientPublicKey, senderKeyPair)

```typescript
import { getSodium } from './sodium.ts';
import { unsafe } from './branded.ts';
import type { SymmetricKey, X25519PublicKey } from './branded.ts';
import type { X25519KeyPair } from './key-derivation.ts';

export type AuthenticatedWrappedKey = {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly senderPublicKey: X25519PublicKey;
};

export async function wrapKeyAuthenticated(
  key: SymmetricKey,
  recipientPublicKey: X25519PublicKey,
  senderKeyPair: X25519KeyPair
): Promise<AuthenticatedWrappedKey> {
  const sodium = await getSodium();
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);

  const ciphertext = sodium.crypto_box_easy(
    key,
    nonce,
    recipientPublicKey,
    senderKeyPair.privateKey
  );

  return {
    nonce,
    ciphertext,
    senderPublicKey: senderKeyPair.publicKey,
  };
}
```

**Key points:**
1. Uses sender's private key — provides sender authentication
2. 24-byte random nonce (safe for random generation with X25519)
3. Output: nonce (24) + ciphertext (48) + senderPublicKey (32) = 104 bytes
4. **CRITICAL**: Always use this for sharing between users

#### wrapKeyAuthenticatedMulti(key, recipientPublicKeys, senderKeyPair)

```typescript
import { getSodium } from './sodium.ts';
import type { SymmetricKey, X25519PublicKey } from './branded.ts';
import type { X25519KeyPair } from './key-derivation.ts';
import type { AuthenticatedWrappedKey } from './key-wrapping.ts';

export async function wrapKeyAuthenticatedMulti(
  key: SymmetricKey,
  recipientPublicKeys: readonly X25519PublicKey[],
  senderKeyPair: X25519KeyPair
): Promise<readonly AuthenticatedWrappedKey[]> {
  const sodium = await getSodium();

  return recipientPublicKeys.map((recipientPubKey) => {
    const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);

    const ciphertext = sodium.crypto_box_easy(
      key,
      nonce,
      recipientPubKey,
      senderKeyPair.privateKey
    );

    return {
      nonce,
      ciphertext,
      senderPublicKey: senderKeyPair.publicKey,
    };
  });
}
```

**Key points:**
1. Fresh nonce for each recipient (CRITICAL for security)
2. Same sender public key in all wrapped keys
3. Each recipient independently verifies sender

#### unwrapKeyAuthenticated(wrapped, expectedSenderPublicKey, recipientKeyPair)

```typescript
import { getSodium } from './sodium.ts';
import { unsafe } from './branded.ts';
import { decryptionFailed, senderMismatch } from './errors.ts';
import { constantTimeEqual } from './memory.ts';
import type { SymmetricKey, X25519PublicKey } from './branded.ts';
import type { X25519KeyPair } from './key-derivation.ts';
import type { AuthenticatedWrappedKey } from './key-wrapping.ts';

export async function unwrapKeyAuthenticated(
  wrapped: AuthenticatedWrappedKey,
  expectedSenderPublicKey: X25519PublicKey,
  recipientKeyPair: X25519KeyPair
): Promise<SymmetricKey> {
  if (!constantTimeEqual(wrapped.senderPublicKey, expectedSenderPublicKey)) {
    throw senderMismatch();
  }

  const sodium = await getSodium();

  try {
    const key = sodium.crypto_box_open_easy(
      wrapped.ciphertext,
      wrapped.nonce,
      wrapped.senderPublicKey,
      recipientKeyPair.privateKey
    );
    return unsafe.asSymmetricKey(key);
  } catch (error) {
    throw decryptionFailed(error instanceof Error ? error : undefined);
  }
}
```

**Key points:**
1. **Verifies sender first** — throws `SENDER_MISMATCH` if public key doesn't match
2. Uses constant-time comparison to prevent timing attacks
3. Throws `DECRYPTION_FAILED` if tampered or wrong recipient
4. Caller must know expected sender to prevent impersonation

---

## 2. Wire Formats

### Sealed Box (Anonymous)

| Component | Size |
|-----------|------|
| Ephemeral public key | 32 bytes |
| Poly1305 auth tag | 16 bytes |
| Encrypted key | 32 bytes |
| **Total** | **80 bytes** |

libsodium handles format internally. Output is opaque 80-byte blob.

### Authenticated Wrapped Key

| Component | Size |
|-----------|------|
| Nonce | 24 bytes |
| Ciphertext (key + MAC) | 48 bytes (32 + 16) |
| Sender public key | 32 bytes |
| **Total** | **104 bytes** |

**Serialization format** (for storage/transmission):
```
[nonce (24)][ciphertext (48)][senderPublicKey (32)]
```

---

## 3. Type Definitions to Add

### Updates to src/types.ts

```typescript
/**
 * Size constants to add.
 */
export const SIZES = {
  // ... existing sizes ...
  SEALED_BOX: 80,
  CRYPTO_BOX_NONCE: 24,
  CRYPTO_BOX_MAC: 16,
  AUTHENTICATED_WRAPPED_KEY: 104,
} as const;
```

The `AuthenticatedWrappedKey` type is defined in `key-wrapping.ts` rather than `types.ts` since it's specific to that module.

---

## 4. Error Handling

| Scenario | Error | Code |
|----------|-------|------|
| Wrong recipient keypair (seal) | `decryptionFailed()` | `DECRYPTION_FAILED` |
| Tampered sealed box | `decryptionFailed()` | `DECRYPTION_FAILED` |
| Sender public key mismatch | `senderMismatch()` | `SENDER_MISMATCH` |
| Wrong recipient keypair (auth) | `decryptionFailed()` | `DECRYPTION_FAILED` |
| Tampered authenticated box | `decryptionFailed()` | `DECRYPTION_FAILED` |

---

## 5. Updates to src/index.ts

Add Phase 4 exports:

```typescript
// key-wrapping.ts
export {
  wrapKeySeal,
  wrapKeySealMulti,
  unwrapKeySeal,
  wrapKeyAuthenticated,
  wrapKeyAuthenticatedMulti,
  unwrapKeyAuthenticated,
} from './key-wrapping.ts';

export type { AuthenticatedWrappedKey } from './key-wrapping.ts';
```

---

## 6. Test Requirements

### tests/key-wrapping.test.ts

```typescript
describe('key-wrapping', () => {
  describe('wrapKeySeal/unwrapKeySeal', () => {
    it('round-trips symmetric key');
    it('different recipient keypair fails with DECRYPTION_FAILED');
    it('tampered sealed box fails with DECRYPTION_FAILED');
    it('produces 80-byte output');
    it('output is different each time (ephemeral keypair)');
  });

  describe('wrapKeySealMulti', () => {
    it('wraps for multiple recipients');
    it('each recipient can unwrap independently');
    it('recipient A cannot unwrap recipient B sealed box');
    it('handles empty recipient list');
    it('handles single recipient');
  });

  describe('wrapKeyAuthenticated/unwrapKeyAuthenticated', () => {
    it('round-trips symmetric key');
    it('includes correct sender public key');
    it('wrong expected sender fails with SENDER_MISMATCH');
    it('wrong recipient keypair fails with DECRYPTION_FAILED');
    it('tampered ciphertext fails with DECRYPTION_FAILED');
    it('tampered nonce fails with DECRYPTION_FAILED');
    it('produces 104-byte total output');
  });

  describe('wrapKeyAuthenticatedMulti', () => {
    it('wraps for multiple recipients with same sender');
    it('each recipient can unwrap and verify sender');
    it('uses unique nonce per recipient');
    it('recipient A cannot unwrap recipient B wrapped key');
    it('handles empty recipient list');
    it('handles single recipient');
  });

  describe('security properties', () => {
    it('sealed box provides no sender authentication');
    it('authenticated box sender cannot be forged');
    it('constant-time sender comparison prevents timing attacks');
    it('ephemeral keypair in seal provides forward secrecy');
    it('nonces are unique across multiple wrappings');
  });

  describe('interop with key-derivation', () => {
    it('works with deriveEncryptionKeyPair output');
    it('deterministic keypairs produce consistent results');
  });
});
```

---

## 7. Implementation Order

1. **wrapKeySeal()** — Anonymous sealing (simplest)
2. **unwrapKeySeal()** — Anonymous unsealing
3. **wrapKeySealMulti()** — Multi-recipient seal (trivial wrapper)
4. **wrapKeyAuthenticated()** — Authenticated wrapping
5. **unwrapKeyAuthenticated()** — Authenticated unwrapping with sender verification
6. **wrapKeyAuthenticatedMulti()** — Multi-recipient authenticated
7. **Update src/index.ts** — Export new functions
8. **Tests** — Comprehensive test coverage

---

## 8. Security Considerations

### When to Use Each Method

| Method | Use Case | Sender Auth |
|--------|----------|-------------|
| `wrapKeySeal` | Self-encryption (own devices) | ✗ No |
| `wrapKeyAuthenticated` | Sharing with other users | ✓ Yes |

**CRITICAL**: Never use `wrapKeySeal` for sharing between users. Without sender authentication, an attacker can replace the wrapped key with one they control.

### Sender Verification

`unwrapKeyAuthenticated` requires the caller to provide `expectedSenderPublicKey`:
- Caller must obtain sender's public key through a trusted channel
- Comparison uses constant-time equality to prevent timing attacks
- Verification happens before decryption attempt

### Forward Secrecy

- **Sealed box**: Provides forward secrecy via ephemeral keypair
- **Authenticated box**: No forward secrecy — compromise of sender's private key reveals all past wrapped keys

For long-term secrets, consider using sealed boxes even for sharing, and distribute sender identity through a separate authenticated channel.

### Nonce Safety

Authenticated wrapping uses random 24-byte nonces:
- Safe for random generation (collision probability negligible)
- Fresh nonce for each recipient in multi-recipient scenarios
- Never reuse nonces with same keypair

### Memory Considerations

- Unwrapped keys are 32-byte `Uint8Array` in JavaScript memory
- Cannot guarantee secure memory clearing (browser limitation)
- Minimize key lifetime — wrap/unwrap close to use

---

## 9. libsodium Function Reference

| Operation | libsodium Function |
|-----------|-------------------|
| Anonymous seal | `crypto_box_seal` |
| Anonymous unseal | `crypto_box_seal_open` |
| Authenticated encrypt | `crypto_box_easy` |
| Authenticated decrypt | `crypto_box_open_easy` |
| Nonce generation | `randombytes_buf(crypto_box_NONCEBYTES)` |

### Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `crypto_box_NONCEBYTES` | 24 | Nonce size |
| `crypto_box_MACBYTES` | 16 | Auth tag size |
| `crypto_box_SEALBYTES` | 48 | Sealed box overhead |
| `crypto_box_PUBLICKEYBYTES` | 32 | X25519 public key |
| `crypto_box_SECRETKEYBYTES` | 32 | X25519 private key |

---

## 10. Usage Examples

### Self-Encryption (Anonymous Seal)

```typescript
import { generateKey, wrapKeySeal, unwrapKeySeal } from '@filemanager/encryption';
import { deriveEncryptionKeyPair, deriveSeed } from '@filemanager/encryption';

// Generate per-file symmetric key
const fileKey = await generateKey();

// Derive recipient keypair from mnemonic
const seed = await deriveSeed('abandon abandon abandon ... about');
const myKeyPair = await deriveEncryptionKeyPair(seed, 0);

// Wrap key for self
const sealedKey = await wrapKeySeal(fileKey, myKeyPair.publicKey);

// Later: unwrap on same or different device
const unwrappedKey = await unwrapKeySeal(sealedKey, myKeyPair);
```

### Sharing Between Users (Authenticated)

```typescript
import {
  generateKey,
  wrapKeyAuthenticated,
  unwrapKeyAuthenticated,
  deriveEncryptionKeyPair,
  deriveSeed,
} from '@filemanager/encryption';

// Alice's keypair
const aliceSeed = await deriveSeed('alice mnemonic ...');
const aliceKeyPair = await deriveEncryptionKeyPair(aliceSeed, 0);

// Bob's keypair
const bobSeed = await deriveSeed('bob mnemonic ...');
const bobKeyPair = await deriveEncryptionKeyPair(bobSeed, 0);

// Alice generates file key and wraps for Bob
const fileKey = await generateKey();
const wrapped = await wrapKeyAuthenticated(
  fileKey,
  bobKeyPair.publicKey,
  aliceKeyPair
);

// Bob unwraps, verifying it came from Alice
const unwrappedKey = await unwrapKeyAuthenticated(
  wrapped,
  aliceKeyPair.publicKey, // Bob knows Alice's public key
  bobKeyPair
);
```

### Multi-Recipient Sharing

```typescript
import {
  generateKey,
  wrapKeyAuthenticatedMulti,
} from '@filemanager/encryption';

// Alice shares with Bob, Carol, and Dave
const fileKey = await generateKey();
const recipientPubKeys = [bobKeyPair.publicKey, carolKeyPair.publicKey, daveKeyPair.publicKey];

const wrappedKeys = await wrapKeyAuthenticatedMulti(
  fileKey,
  recipientPubKeys,
  aliceKeyPair
);

// wrappedKeys[0] for Bob, wrappedKeys[1] for Carol, wrappedKeys[2] for Dave
// Store alongside encrypted file, each recipient uses their own wrapped key
```

---

## 11. Known Limitations

### No Key Revocation

Once a key is wrapped for a recipient, there's no cryptographic way to revoke access. Key management (who can access what) is the caller's responsibility.

### Storage Size

Multi-recipient wrapping stores one wrapped key per recipient:
- Sealed: 80 bytes × N recipients
- Authenticated: 104 bytes × N recipients

For files shared with many users, consider a key hierarchy (wrap file key with group key, wrap group key for individuals).

### Sender Public Key in AuthenticatedWrappedKey

The sender's public key is stored in plaintext. This reveals who shared a file. If sender privacy is required, use additional encryption or anonymous sealed boxes with out-of-band sender verification.
