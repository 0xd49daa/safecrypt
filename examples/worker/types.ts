import type {
  SymmetricKey,
  FileId,
  SecretstreamHeader,
  ContentHash,
  Seed,
  X25519PublicKey,
} from '../../src/index.ts';
import type { X25519KeyPair, AuthenticatedWrappedKey } from '../../src/index.ts';

export type EncryptFileRequest = {
  readonly plaintext: Uint8Array;
  readonly fileId?: FileId;
};

export type EncryptFileResponse = {
  readonly key: SymmetricKey;
  readonly header: SecretstreamHeader;
  readonly ciphertext: Uint8Array;
  readonly hash: ContentHash;
};

export type DecryptFileRequest = {
  readonly key: SymmetricKey;
  readonly header: SecretstreamHeader;
  readonly ciphertext: Uint8Array;
  readonly fileId?: FileId;
};

export type DecryptFileResponse = {
  readonly plaintext: Uint8Array;
  readonly hash: ContentHash;
};

export type WrapKeySealRequest = {
  readonly key: SymmetricKey;
  readonly recipientPublicKey: X25519PublicKey;
};

export type WrapKeySealResponse = {
  readonly sealed: Uint8Array;
};

export type WrapKeyAuthenticatedRequest = {
  readonly key: SymmetricKey;
  readonly recipientPublicKey: X25519PublicKey;
  readonly senderKeyPair: X25519KeyPair;
};

export type WrapKeyAuthenticatedResponse = {
  readonly wrapped: AuthenticatedWrappedKey;
};

export type DeriveKeysRequest = {
  readonly mnemonic: string;
  readonly passphrase?: string;
  readonly encryptionIndex: number;
};

export type DeriveKeysResponse = {
  readonly encryptionKeyPair: X25519KeyPair;
};

export type CryptoWorkerAPI = {
  encryptFile(request: EncryptFileRequest): Promise<EncryptFileResponse>;
  decryptFile(request: DecryptFileRequest): Promise<DecryptFileResponse>;
  wrapKeySeal(request: WrapKeySealRequest): Promise<WrapKeySealResponse>;
  wrapKeyAuthenticated(request: WrapKeyAuthenticatedRequest): Promise<WrapKeyAuthenticatedResponse>;
  deriveKeys(request: DeriveKeysRequest): Promise<DeriveKeysResponse>;
  preload(): Promise<void>;
};
