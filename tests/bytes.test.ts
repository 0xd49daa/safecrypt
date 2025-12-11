import { describe, expect, test } from 'bun:test';
import {
  concat,
  toHex,
  fromHex,
  toBase64,
  fromBase64,
  toBase64Url,
  fromBase64Url,
  bytesEqual,
  copy,
  slice,
} from '../src/bytes.ts';
import { ErrorCode, EncryptionError } from '../src/errors.ts';

describe('concat', () => {
  test('concatenates multiple arrays', () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3, 4]);
    const c = new Uint8Array([5]);
    const result = concat(a, b, c);
    expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
  });

  test('handles empty arrays', () => {
    const a = new Uint8Array([1, 2]);
    const empty = new Uint8Array(0);
    expect(concat(a, empty)).toEqual(new Uint8Array([1, 2]));
    expect(concat(empty, a)).toEqual(new Uint8Array([1, 2]));
    expect(concat(empty, empty)).toEqual(new Uint8Array(0));
  });

  test('handles single array', () => {
    const a = new Uint8Array([1, 2, 3]);
    const result = concat(a);
    expect(result).toEqual(a);
    expect(result).not.toBe(a);
  });

  test('handles no arrays', () => {
    expect(concat()).toEqual(new Uint8Array(0));
  });
});

describe('toHex/fromHex', () => {
  test('roundtrips correctly', () => {
    const bytes = new Uint8Array([0x00, 0x0f, 0xf0, 0xff, 0xab, 0xcd]);
    const hex = toHex(bytes);
    expect(hex).toBe('000ff0ffabcd');
    expect(fromHex(hex)).toEqual(bytes);
  });

  test('produces lowercase hex', () => {
    const bytes = new Uint8Array([0xAB, 0xCD, 0xEF]);
    expect(toHex(bytes)).toBe('abcdef');
  });

  test('fromHex handles 0x prefix', () => {
    expect(fromHex('0xabcd')).toEqual(new Uint8Array([0xab, 0xcd]));
    expect(fromHex('0XABCD')).toEqual(new Uint8Array([0xab, 0xcd]));
  });

  test('fromHex handles uppercase', () => {
    expect(fromHex('ABCD')).toEqual(new Uint8Array([0xab, 0xcd]));
    expect(fromHex('AbCd')).toEqual(new Uint8Array([0xab, 0xcd]));
  });

  test('fromHex throws on odd length', () => {
    expect(() => fromHex('abc')).toThrow('odd length');
  });

  test('fromHex throws on invalid characters', () => {
    expect(() => fromHex('ghij')).toThrow('invalid character');
  });

  test('handles empty', () => {
    expect(toHex(new Uint8Array(0))).toBe('');
    expect(fromHex('')).toEqual(new Uint8Array(0));
  });
});

describe('toBase64/fromBase64', () => {
  test('roundtrips correctly', () => {
    const bytes = new Uint8Array([72, 101, 108, 108, 111]);
    const b64 = toBase64(bytes);
    expect(b64).toBe('SGVsbG8=');
    expect(fromBase64(b64)).toEqual(bytes);
  });

  test('handles empty', () => {
    expect(toBase64(new Uint8Array(0))).toBe('');
    expect(fromBase64('')).toEqual(new Uint8Array(0));
  });

  test('handles binary data', () => {
    const bytes = new Uint8Array([0, 127, 128, 255]);
    const b64 = toBase64(bytes);
    expect(fromBase64(b64)).toEqual(bytes);
  });

  test('handles large data without RangeError', () => {
    const largeBytes = new Uint8Array(200_000);
    for (let i = 0; i < largeBytes.length; i++) {
      largeBytes[i] = i % 256;
    }
    const b64 = toBase64(largeBytes);
    const decoded = fromBase64(b64);
    expect(decoded.length).toBe(largeBytes.length);
    expect(decoded[0]).toBe(0);
    expect(decoded[255]).toBe(255);
    expect(decoded[199_999]).toBe(199_999 % 256);
  });

  test('throws INVALID_BASE64 on invalid characters', () => {
    expect(() => fromBase64('@@')).toThrow(EncryptionError);
    try {
      fromBase64('@@');
    } catch (e) {
      expect((e as EncryptionError).code).toBe(ErrorCode.INVALID_BASE64);
    }
  });

  test('throws INVALID_BASE64 on malformed input', () => {
    expect(() => fromBase64('hello@world')).toThrow(EncryptionError);
    expect(() => fromBase64('!!!')).toThrow(EncryptionError);
    expect(() => fromBase64('abc')).toThrow(EncryptionError);
  });

  test('throws INVALID_BASE64 on whitespace', () => {
    expect(() => fromBase64('SGVs bG8=')).toThrow(EncryptionError);
    expect(() => fromBase64('SGVsbG8=\n')).toThrow(EncryptionError);
  });
});

describe('toBase64Url/fromBase64Url', () => {
  test('roundtrips correctly', () => {
    const bytes = new Uint8Array([0xfb, 0xef, 0xbe]);
    const b64url = toBase64Url(bytes);
    expect(b64url).not.toContain('+');
    expect(b64url).not.toContain('/');
    expect(b64url).not.toContain('=');
    expect(fromBase64Url(b64url)).toEqual(bytes);
  });

  test('handles padding correctly', () => {
    const bytes1 = new Uint8Array([1]);
    const bytes2 = new Uint8Array([1, 2]);
    const bytes3 = new Uint8Array([1, 2, 3]);

    expect(fromBase64Url(toBase64Url(bytes1))).toEqual(bytes1);
    expect(fromBase64Url(toBase64Url(bytes2))).toEqual(bytes2);
    expect(fromBase64Url(toBase64Url(bytes3))).toEqual(bytes3);
  });

  test('handles empty', () => {
    expect(toBase64Url(new Uint8Array(0))).toBe('');
    expect(fromBase64Url('')).toEqual(new Uint8Array(0));
  });

  test('replaces + with - and / with _', () => {
    const bytes = new Uint8Array([0xfb, 0xef, 0xbe, 0xfb]);
    const b64 = toBase64(bytes);
    const b64url = toBase64Url(bytes);

    if (b64.includes('+')) {
      expect(b64url).toContain('-');
    }
    if (b64.includes('/')) {
      expect(b64url).toContain('_');
    }
  });
});

describe('bytesEqual', () => {
  test('returns true for equal arrays', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    expect(bytesEqual(a, b)).toBe(true);
  });

  test('returns false for different contents', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 4]);
    expect(bytesEqual(a, b)).toBe(false);
  });

  test('returns false for different lengths', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2]);
    expect(bytesEqual(a, b)).toBe(false);
  });

  test('returns true for empty arrays', () => {
    expect(bytesEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });

  test('returns true for same reference', () => {
    const a = new Uint8Array([1, 2, 3]);
    expect(bytesEqual(a, a)).toBe(true);
  });
});

describe('copy', () => {
  test('creates independent copy', () => {
    const original = new Uint8Array([1, 2, 3]);
    const copied = copy(original);

    expect(copied).toEqual(original);
    expect(copied).not.toBe(original);

    copied[0] = 99;
    expect(original[0]).toBe(1);
  });

  test('handles empty array', () => {
    const original = new Uint8Array(0);
    const copied = copy(original);
    expect(copied).toEqual(original);
    expect(copied).not.toBe(original);
  });
});

describe('slice', () => {
  test('creates view into original array', () => {
    const original = new Uint8Array([1, 2, 3, 4, 5]);
    const sliced = slice(original, 1, 3);

    expect(sliced).toEqual(new Uint8Array([2, 3, 4]));

    sliced[0] = 99;
    expect(original[1]).toBe(99);
  });

  test('shares underlying buffer', () => {
    const original = new Uint8Array([1, 2, 3, 4, 5]);
    const sliced = slice(original, 2, 2);

    expect(sliced.buffer).toBe(original.buffer);
    expect(sliced.byteOffset).toBe(2);
    expect(sliced.length).toBe(2);
  });
});
