import { Crypto } from '@peculiar/webcrypto';

// Polyfill Web Crypto for Node/jsdom test environment
Object.defineProperty(globalThis, 'crypto', { value: new Crypto() });

import { generateSigningKeyPair } from '../../crypto';
import type { DecryptedIdentity } from '../../state/types';

import {
  BUNDLE_PREFIX,
  BUNDLE_TOTAL_LEN,
  decodeIdentityBundle,
  encodeIdentityBundle,
  InvalidBundleError,
  InvalidSignatureError,
  verifyIdentityBundle,
} from '../bundle';

/** Derive X25519 keypair from Ed25519 seed (matching TelebridgeState convention) */
function deriveX25519(ed25519Seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const { x25519 } = require('@noble/curves/ed25519.js');
  const privateKey = ed25519Seed.slice();
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

function makeIdentity(): DecryptedIdentity {
  const ed25519 = generateSigningKeyPair();
  const x25519kp = deriveX25519(ed25519.privateKey);
  return {
    ed25519PublicKey: ed25519.publicKey,
    ed25519PrivateKey: ed25519.privateKey,
    x25519PublicKey: x25519kp.publicKey,
    x25519PrivateKey: x25519kp.privateKey,
  };
}

// base64url encode helper (URL-safe, no padding) — mirrors the codec's internal transform.
function b64url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

describe('identity bundle codec', () => {
  test('round-trip: encode → decode → verify', () => {
    const identity = makeIdentity();
    const text = encodeIdentityBundle(identity);

    expect(text.startsWith(BUNDLE_PREFIX)).toBe(true);

    const decoded = decodeIdentityBundle(text);
    expect(decoded.version).toBe(0x01);
    expect(decoded.raw.length).toBe(BUNDLE_TOTAL_LEN);
    expect(decoded.ed25519PublicKey).toEqual(identity.ed25519PublicKey);
    expect(decoded.x25519PublicKey).toEqual(identity.x25519PublicKey);
    expect(decoded.signature.length).toBe(64);

    // Signable is magic(2) + ver(1) + ed25519Pub(32) + x25519Pub(32) = 67 bytes.
    expect(decoded.signable.length).toBe(67);
    expect(decoded.signable[0]).toBe(0x74);
    expect(decoded.signable[1]).toBe(0x62);
    expect(decoded.signable[2]).toBe(0x01);

    // Should not throw.
    verifyIdentityBundle(decoded);
  });

  test('truncated payload throws InvalidBundleError', () => {
    const identity = makeIdentity();
    const text = encodeIdentityBundle(identity);
    // Chop the last ~20 base64url chars — payload will decode to < 131 bytes.
    const truncated = text.slice(0, text.length - 20);

    expect(() => decodeIdentityBundle(truncated)).toThrow(InvalidBundleError);
  });

  test('wrong magic bytes throw InvalidBundleError', () => {
    const identity = makeIdentity();
    const text = encodeIdentityBundle(identity);
    const decoded = decodeIdentityBundle(text);

    // Flip the first magic byte from 0x74 ('t') to 0x00 and re-encode as a bundle string.
    const tampered = new Uint8Array(decoded.raw);
    tampered[0] = 0x00;
    const badText = BUNDLE_PREFIX + b64url(tampered);

    expect(() => decodeIdentityBundle(badText)).toThrow(InvalidBundleError);
  });

  test('wrong version byte throws InvalidBundleError', () => {
    const identity = makeIdentity();
    const text = encodeIdentityBundle(identity);
    const decoded = decodeIdentityBundle(text);

    // Bump version from 0x01 to 0x02 (reserved for future PQ bundle).
    const tampered = new Uint8Array(decoded.raw);
    tampered[2] = 0x02;
    const badText = BUNDLE_PREFIX + b64url(tampered);

    expect(() => decodeIdentityBundle(badText)).toThrow(InvalidBundleError);
  });

  test('tampered signature throws InvalidSignatureError', () => {
    const identity = makeIdentity();
    const text = encodeIdentityBundle(identity);
    const decoded = decodeIdentityBundle(text);

    // Flip one bit inside the 64-byte signature region (offset 67..131).
    const tampered = new Uint8Array(decoded.raw);
    tampered[tampered.length - 1] ^= 0x01;
    const badText = BUNDLE_PREFIX + b64url(tampered);

    // Decode should still succeed (prefix/magic/version/length all valid).
    const reDecoded = decodeIdentityBundle(badText);
    expect(() => verifyIdentityBundle(reDecoded)).toThrow(InvalidSignatureError);
  });

  test('non-tb1 prefix throws InvalidBundleError', () => {
    const identity = makeIdentity();
    const text = encodeIdentityBundle(identity);
    // Replace the prefix with something else, same payload bytes.
    const wrongPrefix = `https://example.com/${text.slice(BUNDLE_PREFIX.length)}`;

    expect(() => decodeIdentityBundle(wrongPrefix)).toThrow(InvalidBundleError);
  });
});
