/**
 * Error codes for encryption operations.
 */
export const ErrorCode = {
  INVALID_KEY_SIZE: 'INVALID_KEY_SIZE',
  INVALID_NONCE_SIZE: 'INVALID_NONCE_SIZE',
  DECRYPTION_FAILED: 'DECRYPTION_FAILED',
  SEGMENT_AUTH_FAILED: 'SEGMENT_AUTH_FAILED',
  STREAM_TRUNCATED: 'STREAM_TRUNCATED',
  INVALID_STREAM_HEADER: 'INVALID_STREAM_HEADER',
  INVALID_MNEMONIC: 'INVALID_MNEMONIC',
  SENDER_MISMATCH: 'SENDER_MISMATCH',
  INVALID_SEED_SIZE: 'INVALID_SEED_SIZE',
  INVALID_BASE64: 'INVALID_BASE64',
} as const;

export type ErrorCode = (typeof ErrorCode)[keyof typeof ErrorCode];

/**
 * Base error class for all encryption-related errors.
 */
export class EncryptionError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string, cause?: Error) {
    super(message, cause !== undefined ? { cause } : undefined);
    this.name = 'EncryptionError';
    this.code = code;
  }

  static isEncryptionError(error: unknown): error is EncryptionError {
    return error instanceof EncryptionError;
  }
}

/**
 * Create error for invalid key size.
 */
export function invalidKeySize(actual: number, expected = 32): EncryptionError {
  return new EncryptionError(
    ErrorCode.INVALID_KEY_SIZE,
    `Invalid key size: got ${actual} bytes, expected ${expected}`
  );
}

/**
 * Create error for invalid nonce size.
 */
export function invalidNonceSize(actual: number, expected = 24): EncryptionError {
  return new EncryptionError(
    ErrorCode.INVALID_NONCE_SIZE,
    `Invalid nonce size: got ${actual} bytes, expected ${expected}`
  );
}

/**
 * Create error for decryption failure.
 */
export function decryptionFailed(cause?: Error): EncryptionError {
  return new EncryptionError(
    ErrorCode.DECRYPTION_FAILED,
    'Decryption failed: authentication tag mismatch',
    cause
  );
}

/**
 * Create error for segment authentication failure.
 */
export function segmentAuthFailed(segmentIndex: number, cause?: Error): EncryptionError {
  return new EncryptionError(
    ErrorCode.SEGMENT_AUTH_FAILED,
    `Segment authentication failed at index ${segmentIndex}`,
    cause
  );
}

/**
 * Create error for truncated stream.
 */
export function streamTruncated(): EncryptionError {
  return new EncryptionError(
    ErrorCode.STREAM_TRUNCATED,
    'Stream truncated: missing TAG_FINAL marker'
  );
}

/**
 * Create error for invalid stream header.
 */
export function invalidStreamHeader(reason: string): EncryptionError {
  return new EncryptionError(
    ErrorCode.INVALID_STREAM_HEADER,
    `Invalid stream header: ${reason}`
  );
}

/**
 * Create error for invalid mnemonic.
 */
export function invalidMnemonic(reason: string): EncryptionError {
  return new EncryptionError(
    ErrorCode.INVALID_MNEMONIC,
    `Invalid mnemonic: ${reason}`
  );
}

/**
 * Create error for sender mismatch.
 */
export function senderMismatch(): EncryptionError {
  return new EncryptionError(
    ErrorCode.SENDER_MISMATCH,
    'Sender public key does not match expected sender'
  );
}

export function invalidSeedSize(actual: number, expected = 64): EncryptionError {
  return new EncryptionError(
    ErrorCode.INVALID_SEED_SIZE,
    `Invalid seed size: got ${actual} bytes, expected ${expected}`
  );
}

export function invalidBase64(): EncryptionError {
  return new EncryptionError(ErrorCode.INVALID_BASE64, 'Invalid base64 string');
}
