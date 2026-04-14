/**
 * Layer 4 — Send Secured round-trip + failure-mode coverage.
 *
 * Verifies:
 *  - encryptForRecipient → decryptEnvelope round-trip for the intended peer.
 *  - "not for me" envelopes (encrypt-to-self sibling) surface `notForMe`.
 *  - Tampered signatures surface `invalidSignature` (GCM still passes).
 *  - wire-format round-trip via encodeSecuredMessage + decodeSecuredMessage.
 */
import { Crypto } from '@peculiar/webcrypto';

// Polyfill Web Crypto for the jest/Node environment. Must run before the
// aes.ts module touches `crypto.subtle` on first import.
Object.defineProperty(globalThis, 'crypto', { value: new Crypto() });

import {
  decryptEnvelope,
  encryptForRecipient,
} from '../asymmetric';
import { generateKeyExchangeKeyPair } from '../keyexchange';
import { generateSigningKeyPair } from '../signing';
import { encodeUtf8, decodeUtf8 } from '../utils';
import { x25519 } from '@noble/curves/ed25519.js';
import { decodeSecuredMessage } from '../../protocol/decode';
import { encodeSecuredMessage } from '../../protocol/encode';

function deriveX25519ForEd25519(seed: Uint8Array) {
  const priv = seed.slice();
  return { privateKey: priv, publicKey: x25519.getPublicKey(priv) };
}

describe('Layer 4 asymmetric envelope', () => {
  test('round-trips plaintext for the intended recipient', async () => {
    const senderEd = generateSigningKeyPair();
    const recipient = generateKeyExchangeKeyPair();

    const msg = encodeUtf8('hello secured world');
    const payload = await encryptForRecipient(msg, recipient.publicKey, senderEd.privateKey);

    const result = await decryptEnvelope(payload, recipient.privateKey, senderEd.publicKey);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(decodeUtf8(result.plaintext)).toBe('hello secured world');
    }
  });

  test('wrong recipient (encrypt-to-self sibling) returns notForMe', async () => {
    const senderEd = generateSigningKeyPair();
    const senderX = deriveX25519ForEd25519(senderEd.privateKey);
    const recipient = generateKeyExchangeKeyPair();

    // Sender fan-out: envelope to recipient AND envelope to self.
    const plaintext = encodeUtf8('cross-device readable');
    const envelopeToRecipient = await encryptForRecipient(
      plaintext, recipient.publicKey, senderEd.privateKey,
    );
    const envelopeToSelf = await encryptForRecipient(
      plaintext, senderX.publicKey, senderEd.privateKey,
    );

    // Recipient opens their envelope — fine.
    const good = await decryptEnvelope(envelopeToRecipient, recipient.privateKey, senderEd.publicKey);
    expect(good.ok).toBe(true);

    // Recipient tries to open the sender's encrypt-to-self sibling — GCM fails.
    const sibling = await decryptEnvelope(envelopeToSelf, recipient.privateKey, senderEd.publicKey);
    expect(sibling.ok).toBe(false);
    if (!sibling.ok) expect(sibling.reason).toBe('notForMe');
  });

  test('tampered signature after valid GCM returns invalidSignature', async () => {
    const senderEd = generateSigningKeyPair();
    const recipient = generateKeyExchangeKeyPair();

    const payload = await encryptForRecipient(
      encodeUtf8('authentic payload'),
      recipient.publicKey,
      senderEd.privateKey,
    );

    // Flip a bit in the signature — GCM still verifies, only Ed25519 fails.
    payload.signature[0] ^= 0x01;

    const result = await decryptEnvelope(payload, recipient.privateKey, senderEd.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('invalidSignature');
  });

  test('round-trips through tb1.a wire format', async () => {
    const senderEd = generateSigningKeyPair();
    const recipient = generateKeyExchangeKeyPair();

    const payload = await encryptForRecipient(
      encodeUtf8('over the wire'),
      recipient.publicKey,
      senderEd.privateKey,
    );

    const wire = encodeSecuredMessage(payload);
    expect(wire.startsWith('tb1.a.')).toBe(true);

    const decoded = decodeSecuredMessage(wire);
    const result = await decryptEnvelope(decoded, recipient.privateKey, senderEd.publicKey);

    expect(result.ok).toBe(true);
    if (result.ok) expect(decodeUtf8(result.plaintext)).toBe('over the wire');
  });
});
