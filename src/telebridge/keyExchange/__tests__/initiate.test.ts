import { Crypto } from '@peculiar/webcrypto';

// Polyfill Web Crypto for Node/jsdom test environment
Object.defineProperty(globalThis, 'crypto', { value: new Crypto() });

import { generateKeyExchangeKeyPair, generateSigningKeyPair } from '../../crypto';
import { decodeKeyExchange } from '../../protocol/decode';
import { isTelebridgeMessage, parseHeader } from '../../protocol/detect';
import type { DecryptedIdentity } from '../../state/types';

import { initiateKeyExchange } from '../initiate';

/** Build a minimal DecryptedIdentity from Ed25519 seed + X25519 keypair */
function makeIdentity(): DecryptedIdentity {
  const ed25519 = generateSigningKeyPair();
  const x25519kp = generateKeyExchangeKeyPair();
  return {
    ed25519PublicKey: ed25519.publicKey,
    ed25519PrivateKey: ed25519.privateKey,
    x25519PublicKey: x25519kp.publicKey,
    x25519PrivateKey: x25519kp.privateKey,
  };
}

describe('initiateKeyExchange', () => {
  test('produces a valid tb1.kx wire message', async () => {
    const alice = makeIdentity();
    const bob = generateKeyExchangeKeyPair();

    const result = await initiateKeyExchange(alice, bob.publicKey);

    expect(result.wireMessage).toBeDefined();
    expect(result.wireMessage.startsWith('tb1.kx.')).toBe(true);
    expect(isTelebridgeMessage(result.wireMessage)).toBe(true);

    const header = parseHeader(result.wireMessage);
    expect(header).toBeDefined();
    expect(header!.version).toBe(1);
    expect(header!.mode).toBe('kx');
  });

  test('generates a 32-byte AES-256 chat key', async () => {
    const alice = makeIdentity();
    const bob = generateKeyExchangeKeyPair();

    const result = await initiateKeyExchange(alice, bob.publicKey);

    expect(result.chatKey).toBeInstanceOf(Uint8Array);
    expect(result.chatKey.length).toBe(32);
  });

  test('generates a hex key ID string', async () => {
    const alice = makeIdentity();
    const bob = generateKeyExchangeKeyPair();

    const result = await initiateKeyExchange(alice, bob.publicKey);

    expect(typeof result.keyId).toBe('string');
    expect(result.keyId.length).toBe(8); // 4 bytes = 8 hex chars
    expect(/^[0-9a-f]{8}$/.test(result.keyId)).toBe(true);
  });

  test('wire message can be decoded by decodeKeyExchange', async () => {
    const alice = makeIdentity();
    const bob = generateKeyExchangeKeyPair();

    const result = await initiateKeyExchange(alice, bob.publicKey);
    const payload = decodeKeyExchange(result.wireMessage);

    expect(payload.senderIdKey).toEqual(alice.ed25519PublicKey);
    expect(payload.ephemeralX25519.length).toBe(32);
    expect(payload.encryptedChatKey.length).toBeGreaterThan(0);
    expect(payload.signature.length).toBe(64);
  });

  test('signature is valid over the correct fields', async () => {
    const { verify } = await import('../../crypto');
    const { concatBytes } = await import('../../crypto/utils');

    const alice = makeIdentity();
    const bob = generateKeyExchangeKeyPair();

    const result = await initiateKeyExchange(alice, bob.publicKey);
    const payload = decodeKeyExchange(result.wireMessage);

    const signablePayload = concatBytes(
      payload.senderIdKey,
      payload.ephemeralX25519,
      payload.encryptedChatKey,
    );

    expect(verify(signablePayload, payload.signature, alice.ed25519PublicKey)).toBe(true);
  });

  test('each invocation produces unique keys and ephemeral keypairs', async () => {
    const alice = makeIdentity();
    const bob = generateKeyExchangeKeyPair();

    const result1 = await initiateKeyExchange(alice, bob.publicKey);
    const result2 = await initiateKeyExchange(alice, bob.publicKey);

    expect(result1.chatKey).not.toEqual(result2.chatKey);
    expect(result1.keyId).not.toEqual(result2.keyId);
    expect(result1.wireMessage).not.toEqual(result2.wireMessage);
  });

  test('encrypted chat key is non-empty in decoded payload', async () => {
    const alice = makeIdentity();
    const bob = generateKeyExchangeKeyPair();

    const result = await initiateKeyExchange(alice, bob.publicKey);
    const payload = decodeKeyExchange(result.wireMessage);

    // 12B IV + 36B ciphertext (4B keyId + 32B chatKey) + 16B authTag = 64B minimum
    expect(payload.encryptedChatKey.length).toBeGreaterThanOrEqual(64);
  });
});
