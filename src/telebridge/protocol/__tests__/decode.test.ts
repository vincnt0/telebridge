import { randomBytes, toBase64 } from '../../crypto/utils';
import { FIELD_SIZES, MIN_PAYLOAD_SIZES } from '../constants';
import {
  decodeKeyExchange,
  decodeMessage,
  decodePrekeyPublication,
  decodeSecuredMessage,
  decodeSymmetricMessage,
} from '../decode';

describe('Protocol Decoding', () => {
  describe('decodeSymmetricMessage', () => {
    test('throws on invalid header', () => {
      expect(() => decodeSymmetricMessage('Hello world')).toThrow('unrecognized header');
    });

    test('throws on wrong mode', () => {
      const fakePayload = toBase64(randomBytes(200));
      expect(() => decodeSymmetricMessage(`tb1.a.${fakePayload}`)).toThrow('Mode mismatch');
    });

    test('throws on empty payload', () => {
      expect(() => decodeSymmetricMessage('tb1.s.')).toThrow('empty payload');
    });

    test('throws on payload too short for fixed fields', () => {
      const shortPayload = toBase64(randomBytes(MIN_PAYLOAD_SIZES.SYMMETRIC - 1));
      expect(() => decodeSymmetricMessage(`tb1.s.${shortPayload}`)).toThrow('too short');
    });

    test('throws on payload with exactly fixed fields but no ciphertext', () => {
      const exactPayload = toBase64(randomBytes(MIN_PAYLOAD_SIZES.SYMMETRIC));
      expect(() => decodeSymmetricMessage(`tb1.s.${exactPayload}`)).toThrow('empty ciphertext');
    });

    test('throws on invalid base64', () => {
      expect(() => decodeSymmetricMessage('tb1.s.!!!invalid!!!')).toThrow('not valid base64');
    });

    test('throws on unsupported version', () => {
      const payload = toBase64(randomBytes(200));
      expect(() => decodeSymmetricMessage(`tb9.s.${payload}`)).toThrow('Unsupported protocol version');
    });
  });

  describe('decodeSecuredMessage', () => {
    test('throws on payload too short', () => {
      const shortPayload = toBase64(randomBytes(MIN_PAYLOAD_SIZES.ASYMMETRIC - 1));
      expect(() => decodeSecuredMessage(`tb1.a.${shortPayload}`)).toThrow('too short');
    });

    test('throws on empty ciphertext', () => {
      const exactPayload = toBase64(randomBytes(MIN_PAYLOAD_SIZES.ASYMMETRIC));
      expect(() => decodeSecuredMessage(`tb1.a.${exactPayload}`)).toThrow('empty ciphertext');
    });
  });

  describe('decodeKeyExchange', () => {
    test('throws on payload too short', () => {
      const shortPayload = toBase64(randomBytes(MIN_PAYLOAD_SIZES.KEY_EXCHANGE - 1));
      expect(() => decodeKeyExchange(`tb1.kx.${shortPayload}`)).toThrow('too short');
    });

    test('accepts payload with exactly fixed fields (empty encryptedChatKey)', () => {
      const exactPayload = toBase64(randomBytes(MIN_PAYLOAD_SIZES.KEY_EXCHANGE));
      const result = decodeKeyExchange(`tb1.kx.${exactPayload}`);
      expect(result.encryptedChatKey.length).toBe(0);
      expect(result.senderIdKey.length).toBe(FIELD_SIZES.ED25519_PUBLIC_KEY);
      expect(result.ephemeralX25519.length).toBe(FIELD_SIZES.X25519_PUBLIC_KEY);
      expect(result.signature.length).toBe(FIELD_SIZES.ED25519_SIGNATURE);
    });
  });

  describe('decodePrekeyPublication', () => {
    test('throws on wrong size', () => {
      const wrongPayload = toBase64(randomBytes(MIN_PAYLOAD_SIZES.PREKEY + 1));
      expect(() => decodePrekeyPublication(`tb1.pk.${wrongPayload}`)).toThrow('invalid size');
    });

    test('throws on too short', () => {
      const shortPayload = toBase64(randomBytes(MIN_PAYLOAD_SIZES.PREKEY - 1));
      expect(() => decodePrekeyPublication(`tb1.pk.${shortPayload}`)).toThrow('invalid size');
    });
  });

  describe('decodeMessage dispatcher', () => {
    test('throws on invalid header', () => {
      expect(() => decodeMessage('not a telebridge message')).toThrow('unrecognized header');
    });

    test('throws on unsupported version', () => {
      const payload = toBase64(randomBytes(200));
      expect(() => decodeMessage(`tb5.s.${payload}`)).toThrow('Unsupported protocol version');
    });

    test('throws on unknown mode', () => {
      // This should not happen because parseHeader rejects unknown modes,
      // but verify the error propagates
      expect(() => decodeMessage('tb1.zz.data')).toThrow('unrecognized header');
    });
  });
});
