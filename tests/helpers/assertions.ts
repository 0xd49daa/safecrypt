import { expect } from 'bun:test';
import { bytesEqual, toHex } from '../../src/bytes.ts';

export function expectBytesEqual(actual: Uint8Array, expected: Uint8Array): void {
  expect(bytesEqual(actual, expected)).toBe(true);
}

export function expectBytesNotEqual(actual: Uint8Array, expected: Uint8Array): void {
  expect(bytesEqual(actual, expected)).toBe(false);
}

export function expectValidNonce(nonce: Uint8Array): void {
  expect(nonce.length).toBe(24);
  expect(nonce.some((b) => b !== 0)).toBe(true);
}

export function expectUniqueNonces(nonces: Uint8Array[]): void {
  const hexSet = new Set(nonces.map((n) => toHex(n)));
  expect(hexSet.size).toBe(nonces.length);
}

export function expectUniqueArrays(arrays: Uint8Array[]): void {
  const hexSet = new Set(arrays.map((a) => toHex(a)));
  expect(hexSet.size).toBe(arrays.length);
}

export function expectLength(arr: Uint8Array, length: number): void {
  expect(arr.length).toBe(length);
}
