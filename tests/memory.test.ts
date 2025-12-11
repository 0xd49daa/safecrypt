import { describe, expect, test } from 'bun:test';
import {
  secureZero,
  constantTimeEqual,
  randomFill,
  randomBytes,
  withSecureBuffer,
} from '../src/memory.ts';

describe('secureZero', () => {
  test('fills array with zeros', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    secureZero(bytes);
    expect(bytes).toEqual(new Uint8Array([0, 0, 0, 0, 0]));
  });

  test('handles empty array', () => {
    const bytes = new Uint8Array(0);
    secureZero(bytes);
    expect(bytes.length).toBe(0);
  });

  test('handles large array', () => {
    const bytes = new Uint8Array(10000).fill(0xff);
    secureZero(bytes);
    expect(bytes.every((b) => b === 0)).toBe(true);
  });
});

describe('constantTimeEqual', () => {
  test('returns true for equal arrays', async () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 2, 3, 4, 5]);
    expect(await constantTimeEqual(a, b)).toBe(true);
  });

  test('returns false for different contents', async () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 2, 3, 4, 6]);
    expect(await constantTimeEqual(a, b)).toBe(false);
  });

  test('returns false for different lengths', async () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(await constantTimeEqual(a, b)).toBe(false);
  });

  test('returns true for empty arrays', async () => {
    expect(await constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });

  test('returns true for same reference', async () => {
    const a = new Uint8Array([1, 2, 3]);
    expect(await constantTimeEqual(a, a)).toBe(true);
  });
});

describe('randomFill', () => {
  test('fills array with random bytes', async () => {
    const bytes = new Uint8Array(32);
    await randomFill(bytes);

    const allZeros = bytes.every((b) => b === 0);
    expect(allZeros).toBe(false);
  });

  test('produces different values on each call', async () => {
    const a = new Uint8Array(32);
    const b = new Uint8Array(32);

    await randomFill(a);
    await randomFill(b);

    let different = false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) {
        different = true;
        break;
      }
    }
    expect(different).toBe(true);
  });

  test('handles empty array', async () => {
    const bytes = new Uint8Array(0);
    await randomFill(bytes);
    expect(bytes.length).toBe(0);
  });
});

describe('randomBytes', () => {
  test('returns array of requested length', async () => {
    const bytes = await randomBytes(32);
    expect(bytes.length).toBe(32);
  });

  test('produces different values on each call', async () => {
    const a = await randomBytes(32);
    const b = await randomBytes(32);

    let different = false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) {
        different = true;
        break;
      }
    }
    expect(different).toBe(true);
  });

  test('handles zero length', async () => {
    const bytes = await randomBytes(0);
    expect(bytes.length).toBe(0);
  });

  test('handles large length', async () => {
    const bytes = await randomBytes(10000);
    expect(bytes.length).toBe(10000);
  });
});

describe('withSecureBuffer', () => {
  test('provides buffer of requested size', async () => {
    let capturedBuffer: Uint8Array | null = null;

    await withSecureBuffer(32, (buffer) => {
      capturedBuffer = new Uint8Array(buffer);
      buffer.fill(0xff);
      return buffer.length;
    });

    expect(capturedBuffer!.length).toBe(32);
  });

  test('zeros buffer after callback completes', async () => {
    let capturedBuffer: Uint8Array | null = null;

    await withSecureBuffer(32, (buffer) => {
      capturedBuffer = buffer;
      buffer.fill(0xff);
    });

    expect(capturedBuffer!.every((b) => b === 0)).toBe(true);
  });

  test('returns callback result', async () => {
    const result = await withSecureBuffer(32, (buffer) => {
      return buffer.length * 2;
    });

    expect(result).toBe(64);
  });

  test('handles async callback', async () => {
    const result = await withSecureBuffer(32, async (buffer) => {
      await new Promise((resolve) => resolve(undefined));
      return buffer.length;
    });

    expect(result).toBe(32);
  });

  test('zeros buffer even on throw', async () => {
    let capturedBuffer: Uint8Array | null = null;

    try {
      await withSecureBuffer(32, (buffer) => {
        capturedBuffer = buffer;
        buffer.fill(0xff);
        throw new Error('test error');
      });
    } catch {
      // Expected
    }

    expect(capturedBuffer!.every((b) => b === 0)).toBe(true);
  });

  test('rethrows callback error', async () => {
    const testError = new Error('test error');

    await expect(
      withSecureBuffer(32, () => {
        throw testError;
      })
    ).rejects.toThrow('test error');
  });
});
