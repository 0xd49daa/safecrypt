# Issues

- Closed: Worker decryption does not enforce TAG_FINAL/truncation
  - Location: examples/worker/crypto.worker.ts:79
  - Resolution: Added `stream.finalize()` call after decryption loop to enforce TAG_FINAL verification.

- Closed: Worker key derivation leaks root seed to caller
  - Location: examples/worker/crypto.worker.ts:106-115, examples/worker/types.ts:60-62
  - Resolution: Removed `seed` from `DeriveKeysResponse` type; seed is now zeroized with `secureZero()` after deriving keypair.

- Closed: Secrets are not zeroized or disposed when no longer needed
  - Location: src/key-derivation.ts, src/types.ts
  - Resolution: Added `secureZero()` calls for intermediate buffers (`kdfKey`, `subkey`) in key derivation functions. Documented disposal requirements and libsodium state limitations in stream type definitions.

- Closed: Worker docs still reference returning `seed` in deriveKeys response
  - Location: examples/worker/README.md:144-158
  - Resolution: Updated README to show correct `DeriveKeysResponse` type (only `encryptionKeyPair`) and noted that seed is zeroized internally.
