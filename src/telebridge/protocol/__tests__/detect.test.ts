import { getPayloadBase64, isTelebridgeMessage, parseHeader } from '../detect';

describe('Protocol Detection', () => {
  describe('isTelebridgeMessage', () => {
    test('returns true for tb1.s prefix', () => {
      expect(isTelebridgeMessage('tb1.s.AAAA')).toBe(true);
    });

    test('returns true for tb1.a prefix', () => {
      expect(isTelebridgeMessage('tb1.a.BBBB')).toBe(true);
    });

    test('returns true for tb1.kx prefix', () => {
      expect(isTelebridgeMessage('tb1.kx.CCCC')).toBe(true);
    });

    test('returns true for tb1.pk prefix', () => {
      expect(isTelebridgeMessage('tb1.pk.DDDD')).toBe(true);
    });

    test('returns true for higher version numbers', () => {
      expect(isTelebridgeMessage('tb2.s.AAAA')).toBe(true);
      expect(isTelebridgeMessage('tb9.s.AAAA')).toBe(true);
    });

    test('returns false for v1 format (b. prefix)', () => {
      expect(isTelebridgeMessage('b.xyz')).toBe(false);
    });

    test('returns false for regular text', () => {
      expect(isTelebridgeMessage('Hello world')).toBe(false);
    });

    test('returns false for "tb" without a digit', () => {
      expect(isTelebridgeMessage('tb')).toBe(false);
      expect(isTelebridgeMessage('tbx.s.data')).toBe(false);
    });

    test('returns false for empty string', () => {
      expect(isTelebridgeMessage('')).toBe(false);
    });

    test('returns false for short strings', () => {
      expect(isTelebridgeMessage('t')).toBe(false);
      expect(isTelebridgeMessage('tb')).toBe(false);
    });

    test('returns false for "tb" followed by non-digit', () => {
      expect(isTelebridgeMessage('tba.s.data')).toBe(false);
    });
  });

  describe('parseHeader', () => {
    test('parses tb1.s header', () => {
      const header = parseHeader('tb1.s.payload');
      expect(header).toEqual({ version: 1, mode: 's' });
    });

    test('parses tb1.a header', () => {
      const header = parseHeader('tb1.a.payload');
      expect(header).toEqual({ version: 1, mode: 'a' });
    });

    test('parses tb1.kx header', () => {
      const header = parseHeader('tb1.kx.payload');
      expect(header).toEqual({ version: 1, mode: 'kx' });
    });

    test('parses tb1.pk header', () => {
      const header = parseHeader('tb1.pk.payload');
      expect(header).toEqual({ version: 1, mode: 'pk' });
    });

    test('returns undefined for invalid header', () => {
      expect(parseHeader('Hello world')).toBeUndefined();
    });

    test('returns undefined for v1 format', () => {
      expect(parseHeader('b.xyz')).toBeUndefined();
    });

    test('returns undefined for unknown mode', () => {
      expect(parseHeader('tb1.zz.payload')).toBeUndefined();
    });

    test('returns undefined for empty string', () => {
      expect(parseHeader('')).toBeUndefined();
    });

    test('returns undefined for header without trailing dot', () => {
      expect(parseHeader('tb1s')).toBeUndefined();
    });
  });

  describe('getPayloadBase64', () => {
    test('extracts payload from symmetric message', () => {
      expect(getPayloadBase64('tb1.s.AAAA==')).toBe('AAAA==');
    });

    test('extracts payload from kx message', () => {
      expect(getPayloadBase64('tb1.kx.dGVzdA==')).toBe('dGVzdA==');
    });

    test('returns undefined for invalid header', () => {
      expect(getPayloadBase64('b.xyz')).toBeUndefined();
    });

    test('returns undefined for empty payload after header', () => {
      expect(getPayloadBase64('tb1.s.')).toBeUndefined();
    });

    test('returns undefined for unknown mode', () => {
      expect(getPayloadBase64('tb1.zz.data')).toBeUndefined();
    });
  });
});
