import { randomBytes } from '../../crypto/utils';
import { FIELD_SIZES, MODES } from '../constants';
import {
  encodeKeyExchange,
  encodeMessage,
  encodePrekeyPublication,
  encodeSecuredMessage,
  encodeSymmetricMessage,
} from '../encode';

describe('Protocol Encoding', () => {
  describe('encodeSymmetricMessage', () => {
    test('produces wire format with tb1.s prefix', () => {
      const wire = encodeSymmetricMessage({
        keyId: randomBytes(FIELD_SIZES.KEY_ID),
        nonce: randomBytes(FIELD_SIZES.NONCE),
        ciphertext: randomBytes(100),
        authTag: randomBytes(FIELD_SIZES.AUTH_TAG),
        signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
      });

      expect(wire).toMatch(/^tb1\.s\./);
    });

    test('payload is valid base64', () => {
      const wire = encodeSymmetricMessage({
        keyId: randomBytes(FIELD_SIZES.KEY_ID),
        nonce: randomBytes(FIELD_SIZES.NONCE),
        ciphertext: randomBytes(50),
        authTag: randomBytes(FIELD_SIZES.AUTH_TAG),
        signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
      });

      const payload = wire.slice('tb1.s.'.length);
      expect(() => atob(payload)).not.toThrow();
    });
  });

  describe('encodeSecuredMessage', () => {
    test('produces wire format with tb1.a prefix', () => {
      const wire = encodeSecuredMessage({
        ephemeralX25519: randomBytes(FIELD_SIZES.X25519_PUBLIC_KEY),
        nonce: randomBytes(FIELD_SIZES.NONCE),
        ciphertext: randomBytes(100),
        authTag: randomBytes(FIELD_SIZES.AUTH_TAG),
        signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
      });

      expect(wire).toMatch(/^tb1\.a\./);
    });
  });

  describe('encodeKeyExchange', () => {
    test('produces wire format with tb1.kx prefix', () => {
      const wire = encodeKeyExchange({
        senderIdKey: randomBytes(FIELD_SIZES.ED25519_PUBLIC_KEY),
        ephemeralX25519: randomBytes(FIELD_SIZES.X25519_PUBLIC_KEY),
        encryptedChatKey: randomBytes(48),
        signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
      });

      expect(wire).toMatch(/^tb1\.kx\./);
    });

    test('works with empty encryptedChatKey', () => {
      const wire = encodeKeyExchange({
        senderIdKey: randomBytes(FIELD_SIZES.ED25519_PUBLIC_KEY),
        ephemeralX25519: randomBytes(FIELD_SIZES.X25519_PUBLIC_KEY),
        encryptedChatKey: new Uint8Array(0),
        signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
      });

      expect(wire).toMatch(/^tb1\.kx\./);
    });
  });

  describe('encodePrekeyPublication', () => {
    test('produces wire format with tb1.pk prefix', () => {
      const wire = encodePrekeyPublication({
        ed25519PublicKey: randomBytes(FIELD_SIZES.ED25519_PUBLIC_KEY),
        x25519PublicKey: randomBytes(FIELD_SIZES.X25519_PUBLIC_KEY),
        signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
      });

      expect(wire).toMatch(/^tb1\.pk\./);
    });
  });

  describe('encodeMessage dispatcher', () => {
    test('dispatches symmetric messages correctly', () => {
      const wire = encodeMessage({
        version: 1,
        mode: MODES.SYMMETRIC,
        payload: {
          keyId: randomBytes(FIELD_SIZES.KEY_ID),
          nonce: randomBytes(FIELD_SIZES.NONCE),
          ciphertext: randomBytes(50),
          authTag: randomBytes(FIELD_SIZES.AUTH_TAG),
          signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
        },
      });

      expect(wire).toMatch(/^tb1\.s\./);
    });

    test('dispatches asymmetric messages correctly', () => {
      const wire = encodeMessage({
        version: 1,
        mode: MODES.ASYMMETRIC,
        payload: {
          ephemeralX25519: randomBytes(FIELD_SIZES.X25519_PUBLIC_KEY),
          nonce: randomBytes(FIELD_SIZES.NONCE),
          ciphertext: randomBytes(50),
          authTag: randomBytes(FIELD_SIZES.AUTH_TAG),
          signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
        },
      });

      expect(wire).toMatch(/^tb1\.a\./);
    });

    test('dispatches kx messages correctly', () => {
      const wire = encodeMessage({
        version: 1,
        mode: MODES.KEY_EXCHANGE,
        payload: {
          senderIdKey: randomBytes(FIELD_SIZES.ED25519_PUBLIC_KEY),
          ephemeralX25519: randomBytes(FIELD_SIZES.X25519_PUBLIC_KEY),
          encryptedChatKey: randomBytes(48),
          signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
        },
      });

      expect(wire).toMatch(/^tb1\.kx\./);
    });

    test('dispatches pk messages correctly', () => {
      const wire = encodeMessage({
        version: 1,
        mode: MODES.PREKEY,
        payload: {
          ed25519PublicKey: randomBytes(FIELD_SIZES.ED25519_PUBLIC_KEY),
          x25519PublicKey: randomBytes(FIELD_SIZES.X25519_PUBLIC_KEY),
          signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
        },
      });

      expect(wire).toMatch(/^tb1\.pk\./);
    });
  });
});
