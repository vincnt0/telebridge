import { constantTimeEqual, randomBytes } from '../../crypto/utils';
import { FIELD_SIZES, MODES } from '../constants';
import {
  decodeKeyExchange,
  decodeMessage,
  decodePrekeyPublication,
  decodeSecuredMessage,
  decodeSymmetricMessage,
} from '../decode';
import { isTelebridgeMessage, parseHeader } from '../detect';
import {
  encodeKeyExchange,
  encodeMessage,
  encodePrekeyPublication,
  encodeSecuredMessage,
  encodeSymmetricMessage,
} from '../encode';
import type {
  KeyExchangePayload,
  PrekeyPublicationPayload,
  SecuredMessagePayload,
  SymmetricMessagePayload,
} from '../types';

/** Assert two Uint8Arrays are byte-for-byte identical */
function expectBytesEqual(actual: Uint8Array, expected: Uint8Array): void {
  expect(actual.length).toBe(expected.length);
  expect(constantTimeEqual(actual, expected)).toBe(true);
}

describe('Encode → Decode Roundtrip', () => {
  describe('Symmetric messages (tb1.s)', () => {
    const makePayload = (ciphertextSize = 100): SymmetricMessagePayload => ({
      keyId: randomBytes(FIELD_SIZES.KEY_ID),
      nonce: randomBytes(FIELD_SIZES.NONCE),
      ciphertext: randomBytes(ciphertextSize),
      authTag: randomBytes(FIELD_SIZES.AUTH_TAG),
      signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
    });

    test('preserves all fields byte-for-byte', () => {
      const original = makePayload();
      const wire = encodeSymmetricMessage(original);
      const decoded = decodeSymmetricMessage(wire);

      expectBytesEqual(decoded.keyId, original.keyId);
      expectBytesEqual(decoded.nonce, original.nonce);
      expectBytesEqual(decoded.ciphertext, original.ciphertext);
      expectBytesEqual(decoded.authTag, original.authTag);
      expectBytesEqual(decoded.signature, original.signature);
    });

    test('detection identifies the wire format', () => {
      const wire = encodeSymmetricMessage(makePayload());
      expect(isTelebridgeMessage(wire)).toBe(true);

      const header = parseHeader(wire);
      expect(header).toEqual({ version: 1, mode: 's' });
    });

    test('works with small ciphertext (1 byte)', () => {
      const original = makePayload(1);
      const wire = encodeSymmetricMessage(original);
      const decoded = decodeSymmetricMessage(wire);
      expectBytesEqual(decoded.ciphertext, original.ciphertext);
    });

    test('signature integrity — last 64 bytes survive roundtrip', () => {
      const sig = randomBytes(FIELD_SIZES.ED25519_SIGNATURE);
      const original = { ...makePayload(), signature: sig };
      const wire = encodeSymmetricMessage(original);
      const decoded = decodeSymmetricMessage(wire);
      expectBytesEqual(decoded.signature, sig);
    });

    test('encodeMessage dispatcher roundtrip', () => {
      const original = makePayload();
      const wire = encodeMessage({
        version: 1,
        mode: MODES.SYMMETRIC,
        payload: original,
      });
      const decoded = decodeMessage(wire);
      expect(decoded.mode).toBe(MODES.SYMMETRIC);
      expect(decoded.version).toBe(1);
      if (decoded.mode === MODES.SYMMETRIC) {
        expectBytesEqual(decoded.payload.ciphertext, original.ciphertext);
        expectBytesEqual(decoded.payload.signature, original.signature);
      }
    });
  });

  describe('Secured messages (tb1.a)', () => {
    const makePayload = (ciphertextSize = 100): SecuredMessagePayload => ({
      ephemeralX25519: randomBytes(FIELD_SIZES.X25519_PUBLIC_KEY),
      nonce: randomBytes(FIELD_SIZES.NONCE),
      ciphertext: randomBytes(ciphertextSize),
      authTag: randomBytes(FIELD_SIZES.AUTH_TAG),
      signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
    });

    test('preserves all fields byte-for-byte', () => {
      const original = makePayload();
      const wire = encodeSecuredMessage(original);
      const decoded = decodeSecuredMessage(wire);

      expectBytesEqual(decoded.ephemeralX25519, original.ephemeralX25519);
      expectBytesEqual(decoded.nonce, original.nonce);
      expectBytesEqual(decoded.ciphertext, original.ciphertext);
      expectBytesEqual(decoded.authTag, original.authTag);
      expectBytesEqual(decoded.signature, original.signature);
    });

    test('detection identifies the wire format', () => {
      const wire = encodeSecuredMessage(makePayload());
      expect(isTelebridgeMessage(wire)).toBe(true);

      const header = parseHeader(wire);
      expect(header).toEqual({ version: 1, mode: 'a' });
    });

    test('signature integrity — position-sensitive last 64 bytes', () => {
      const sig = randomBytes(FIELD_SIZES.ED25519_SIGNATURE);
      const original = { ...makePayload(), signature: sig };
      const wire = encodeSecuredMessage(original);
      const decoded = decodeSecuredMessage(wire);
      expectBytesEqual(decoded.signature, sig);
    });
  });

  describe('Key exchange messages (tb1.kx)', () => {
    const makePayload = (chatKeySize = 48): KeyExchangePayload => ({
      senderIdKey: randomBytes(FIELD_SIZES.ED25519_PUBLIC_KEY),
      ephemeralX25519: randomBytes(FIELD_SIZES.X25519_PUBLIC_KEY),
      encryptedChatKey: randomBytes(chatKeySize),
      signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
    });

    test('preserves all fields byte-for-byte', () => {
      const original = makePayload();
      const wire = encodeKeyExchange(original);
      const decoded = decodeKeyExchange(wire);

      expectBytesEqual(decoded.senderIdKey, original.senderIdKey);
      expectBytesEqual(decoded.ephemeralX25519, original.ephemeralX25519);
      expectBytesEqual(decoded.encryptedChatKey, original.encryptedChatKey);
      expectBytesEqual(decoded.signature, original.signature);
    });

    test('detection identifies the wire format', () => {
      const wire = encodeKeyExchange(makePayload());
      expect(isTelebridgeMessage(wire)).toBe(true);

      const header = parseHeader(wire);
      expect(header).toEqual({ version: 1, mode: 'kx' });
    });

    test('roundtrip with empty encryptedChatKey', () => {
      const original = makePayload(0);
      const wire = encodeKeyExchange(original);
      const decoded = decodeKeyExchange(wire);

      expect(decoded.encryptedChatKey.length).toBe(0);
      expectBytesEqual(decoded.senderIdKey, original.senderIdKey);
      expectBytesEqual(decoded.ephemeralX25519, original.ephemeralX25519);
      expectBytesEqual(decoded.signature, original.signature);
    });
  });

  describe('Prekey publication messages (tb1.pk)', () => {
    const makePayload = (): PrekeyPublicationPayload => ({
      ed25519PublicKey: randomBytes(FIELD_SIZES.ED25519_PUBLIC_KEY),
      x25519PublicKey: randomBytes(FIELD_SIZES.X25519_PUBLIC_KEY),
      signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
    });

    test('preserves all fields byte-for-byte', () => {
      const original = makePayload();
      const wire = encodePrekeyPublication(original);
      const decoded = decodePrekeyPublication(wire);

      expectBytesEqual(decoded.ed25519PublicKey, original.ed25519PublicKey);
      expectBytesEqual(decoded.x25519PublicKey, original.x25519PublicKey);
      expectBytesEqual(decoded.signature, original.signature);
    });

    test('detection identifies the wire format', () => {
      const wire = encodePrekeyPublication(makePayload());
      expect(isTelebridgeMessage(wire)).toBe(true);

      const header = parseHeader(wire);
      expect(header).toEqual({ version: 1, mode: 'pk' });
    });
  });

  describe('Edge cases', () => {
    test('large ciphertext near Telegram 4096-char limit', () => {
      // 4096 chars - ~7 header chars = ~4089 base64 chars
      // ~4089 base64 chars = ~3066 raw bytes
      // Subtract fixed fields (96B for symmetric) = ~2970 bytes ciphertext
      const original: SymmetricMessagePayload = {
        keyId: randomBytes(FIELD_SIZES.KEY_ID),
        nonce: randomBytes(FIELD_SIZES.NONCE),
        ciphertext: randomBytes(2900),
        authTag: randomBytes(FIELD_SIZES.AUTH_TAG),
        signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
      };
      const wire = encodeSymmetricMessage(original);
      const decoded = decodeSymmetricMessage(wire);

      expectBytesEqual(decoded.ciphertext, original.ciphertext);
      // Verify wire format fits within Telegram limit
      expect(wire.length).toBeLessThanOrEqual(4096);
    });

    test('binary data with all byte values (0x00-0xFF) survives base64 roundtrip', () => {
      const allBytes = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        allBytes[i] = i;
      }

      const original: SymmetricMessagePayload = {
        keyId: randomBytes(FIELD_SIZES.KEY_ID),
        nonce: randomBytes(FIELD_SIZES.NONCE),
        ciphertext: allBytes,
        authTag: randomBytes(FIELD_SIZES.AUTH_TAG),
        signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
      };
      const wire = encodeSymmetricMessage(original);
      const decoded = decodeSymmetricMessage(wire);

      expectBytesEqual(decoded.ciphertext, allBytes);
    });

    test('decodeMessage correctly round-trips all 4 types', () => {
      const types = [
        {
          mode: MODES.SYMMETRIC,
          payload: {
            keyId: randomBytes(FIELD_SIZES.KEY_ID),
            nonce: randomBytes(FIELD_SIZES.NONCE),
            ciphertext: randomBytes(50),
            authTag: randomBytes(FIELD_SIZES.AUTH_TAG),
            signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
          },
        },
        {
          mode: MODES.ASYMMETRIC,
          payload: {
            ephemeralX25519: randomBytes(FIELD_SIZES.X25519_PUBLIC_KEY),
            nonce: randomBytes(FIELD_SIZES.NONCE),
            ciphertext: randomBytes(50),
            authTag: randomBytes(FIELD_SIZES.AUTH_TAG),
            signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
          },
        },
        {
          mode: MODES.KEY_EXCHANGE,
          payload: {
            senderIdKey: randomBytes(FIELD_SIZES.ED25519_PUBLIC_KEY),
            ephemeralX25519: randomBytes(FIELD_SIZES.X25519_PUBLIC_KEY),
            encryptedChatKey: randomBytes(48),
            signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
          },
        },
        {
          mode: MODES.PREKEY,
          payload: {
            ed25519PublicKey: randomBytes(FIELD_SIZES.ED25519_PUBLIC_KEY),
            x25519PublicKey: randomBytes(FIELD_SIZES.X25519_PUBLIC_KEY),
            signature: randomBytes(FIELD_SIZES.ED25519_SIGNATURE),
          },
        },
      ] as const;

      for (const msg of types) {
        const wire = encodeMessage({ version: 1, ...msg } as any);
        const decoded = decodeMessage(wire);
        expect(decoded.mode).toBe(msg.mode);
        expect(decoded.version).toBe(1);
      }
    });
  });
});
