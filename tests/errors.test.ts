import { describe, expect, test } from 'bun:test';
import {
  ErrorCode,
  EncryptionError,
  invalidKeySize,
  invalidNonceSize,
  decryptionFailed,
  segmentAuthFailed,
  streamTruncated,
  invalidStreamHeader,
  invalidMnemonic,
  senderMismatch,
} from '../src/errors.ts';

describe('ErrorCode', () => {
  test('has all expected error codes', () => {
    expect(ErrorCode.INVALID_KEY_SIZE).toBe('INVALID_KEY_SIZE');
    expect(ErrorCode.INVALID_NONCE_SIZE).toBe('INVALID_NONCE_SIZE');
    expect(ErrorCode.DECRYPTION_FAILED).toBe('DECRYPTION_FAILED');
    expect(ErrorCode.SEGMENT_AUTH_FAILED).toBe('SEGMENT_AUTH_FAILED');
    expect(ErrorCode.STREAM_TRUNCATED).toBe('STREAM_TRUNCATED');
    expect(ErrorCode.INVALID_STREAM_HEADER).toBe('INVALID_STREAM_HEADER');
    expect(ErrorCode.INVALID_MNEMONIC).toBe('INVALID_MNEMONIC');
    expect(ErrorCode.SENDER_MISMATCH).toBe('SENDER_MISMATCH');
  });
});

describe('EncryptionError', () => {
  test('creates error with code and message', () => {
    const error = new EncryptionError(ErrorCode.DECRYPTION_FAILED, 'test message');
    expect(error.code).toBe('DECRYPTION_FAILED');
    expect(error.message).toBe('test message');
    expect(error.name).toBe('EncryptionError');
    expect(error.cause).toBeUndefined();
  });

  test('preserves cause', () => {
    const cause = new Error('original error');
    const error = new EncryptionError(ErrorCode.DECRYPTION_FAILED, 'test', cause);
    expect(error.cause).toBe(cause);
  });

  test('isEncryptionError returns true for EncryptionError', () => {
    const error = new EncryptionError(ErrorCode.DECRYPTION_FAILED, 'test');
    expect(EncryptionError.isEncryptionError(error)).toBe(true);
  });

  test('isEncryptionError returns false for other errors', () => {
    expect(EncryptionError.isEncryptionError(new Error('test'))).toBe(false);
    expect(EncryptionError.isEncryptionError(null)).toBe(false);
    expect(EncryptionError.isEncryptionError(undefined)).toBe(false);
    expect(EncryptionError.isEncryptionError('string')).toBe(false);
  });
});

describe('factory functions', () => {
  test('invalidKeySize includes context', () => {
    const error = invalidKeySize(16, 32);
    expect(error.code).toBe('INVALID_KEY_SIZE');
    expect(error.message).toContain('16');
    expect(error.message).toContain('32');
  });

  test('invalidKeySize uses default expected size', () => {
    const error = invalidKeySize(16);
    expect(error.message).toContain('32');
  });

  test('invalidNonceSize includes context', () => {
    const error = invalidNonceSize(12, 24);
    expect(error.code).toBe('INVALID_NONCE_SIZE');
    expect(error.message).toContain('12');
    expect(error.message).toContain('24');
  });

  test('invalidNonceSize uses default expected size', () => {
    const error = invalidNonceSize(12);
    expect(error.message).toContain('24');
  });

  test('decryptionFailed preserves cause', () => {
    const cause = new Error('sodium error');
    const error = decryptionFailed(cause);
    expect(error.code).toBe('DECRYPTION_FAILED');
    expect(error.cause).toBe(cause);
  });

  test('decryptionFailed works without cause', () => {
    const error = decryptionFailed();
    expect(error.code).toBe('DECRYPTION_FAILED');
    expect(error.cause).toBeUndefined();
  });

  test('segmentAuthFailed includes segment index', () => {
    const error = segmentAuthFailed(5);
    expect(error.code).toBe('SEGMENT_AUTH_FAILED');
    expect(error.message).toContain('5');
  });

  test('streamTruncated creates correct error', () => {
    const error = streamTruncated();
    expect(error.code).toBe('STREAM_TRUNCATED');
    expect(error.message).toContain('TAG_FINAL');
  });

  test('invalidStreamHeader includes reason', () => {
    const error = invalidStreamHeader('wrong size');
    expect(error.code).toBe('INVALID_STREAM_HEADER');
    expect(error.message).toContain('wrong size');
  });

  test('invalidMnemonic includes reason', () => {
    const error = invalidMnemonic('checksum failed');
    expect(error.code).toBe('INVALID_MNEMONIC');
    expect(error.message).toContain('checksum failed');
  });

  test('senderMismatch creates correct error', () => {
    const error = senderMismatch();
    expect(error.code).toBe('SENDER_MISMATCH');
  });
});
