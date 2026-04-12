import {
  concatBytes,
  constantTimeEqual,
  decodeUtf8,
  encodeUtf8,
  fromBase64,
  fromHex,
  randomBytes,
  toBase64,
  toHex,
} from '../utils';

describe('Crypto Utils', () => {
  describe('constantTimeEqual', () => {
    test('returns true for equal arrays', () => {
      const a = new Uint8Array([1, 2, 3, 4]);
      const b = new Uint8Array([1, 2, 3, 4]);
      expect(constantTimeEqual(a, b)).toBe(true);
    });

    test('returns false for different arrays', () => {
      const a = new Uint8Array([1, 2, 3, 4]);
      const b = new Uint8Array([1, 2, 3, 5]);
      expect(constantTimeEqual(a, b)).toBe(false);
    });

    test('returns false for different lengths', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3, 4]);
      expect(constantTimeEqual(a, b)).toBe(false);
    });
  });

  describe('randomBytes', () => {
    test('returns correct length', () => {
      expect(randomBytes(32).length).toBe(32);
      expect(randomBytes(16).length).toBe(16);
    });
  });

  describe('hex encoding', () => {
    test('roundtrip', () => {
      const original = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      expect(toHex(original)).toBe('deadbeef');
      expect(fromHex('deadbeef')).toEqual(original);
    });

    test('rejects odd-length hex', () => {
      expect(() => fromHex('abc')).toThrow();
    });
  });

  describe('base64 encoding', () => {
    test('roundtrip', () => {
      const original = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const encoded = toBase64(original);
      expect(fromBase64(encoded)).toEqual(original);
    });
  });

  describe('UTF-8 encoding', () => {
    test('roundtrip', () => {
      const text = 'Hello, 世界!';
      expect(decodeUtf8(encodeUtf8(text))).toBe(text);
    });
  });

  describe('concatBytes', () => {
    test('concatenates arrays', () => {
      const a = new Uint8Array([1, 2]);
      const b = new Uint8Array([3, 4]);
      const c = new Uint8Array([5]);
      expect(concatBytes(a, b, c)).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
    });

    test('handles empty arrays', () => {
      const a = new Uint8Array([1, 2]);
      expect(concatBytes(a, new Uint8Array(0))).toEqual(a);
    });
  });
});
