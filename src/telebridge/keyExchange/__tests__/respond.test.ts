import { Crypto } from '@peculiar/webcrypto';

// Polyfill Web Crypto for Node/jsdom test environment
Object.defineProperty(globalThis, 'crypto', { value: new Crypto() });

import {
  concatBytes,
  generateKeyExchangeKeyPair,
  generateSigningKeyPair,
  sign,
} from '../../crypto';
import { encodeKeyExchange } from '../../protocol/encode';
import type { DecryptedIdentity } from '../../state/types';
import { TelebridgeState } from '../../state/TelebridgeState';

import { initiateKeyExchange } from '../initiate';
import { respondToKeyExchange } from '../respond';

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

async function makeUnlockedState(): Promise<TelebridgeState> {
  const state = new TelebridgeState();
  const json = await state.initialize('test-password-123');
  // State is already unlocked after initialize
  return state;
}

describe('respondToKeyExchange', () => {
  test('successfully unwraps chat key from valid KX message', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const initiation = await initiateKeyExchange(alice, bob.x25519PublicKey);
    const state = await makeUnlockedState();

    const response = await respondToKeyExchange(
      initiation.wireMessage,
      bob,
      state,
      'alice-user-id',
    );

    expect(response.chatKey).toBeInstanceOf(Uint8Array);
    expect(response.chatKey.length).toBe(32);
  });

  test('unwrapped chat key matches initiator chat key', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const initiation = await initiateKeyExchange(alice, bob.x25519PublicKey);
    const state = await makeUnlockedState();

    const response = await respondToKeyExchange(
      initiation.wireMessage,
      bob,
      state,
      'alice-user-id',
    );

    const { constantTimeEqual } = await import('../../crypto/utils');
    expect(constantTimeEqual(initiation.chatKey, response.chatKey)).toBe(true);
  });

  test('unwrapped keyId matches initiator keyId', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const initiation = await initiateKeyExchange(alice, bob.x25519PublicKey);
    const state = await makeUnlockedState();

    const response = await respondToKeyExchange(
      initiation.wireMessage,
      bob,
      state,
      'alice-user-id',
    );

    expect(response.keyId).toBe(initiation.keyId);
  });

  test('rejects tampered signature', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const initiation = await initiateKeyExchange(alice, bob.x25519PublicKey);

    // Tamper: flip a byte in the wire message's base64 payload
    const parts = initiation.wireMessage.split('.');
    const payloadChars = parts[2].split('');
    // Flip a character near the end (within the signature region)
    const idx = payloadChars.length - 5;
    payloadChars[idx] = payloadChars[idx] === 'A' ? 'B' : 'A';
    const tampered = `${parts[0]}.${parts[1]}.${payloadChars.join('')}`;

    const state = await makeUnlockedState();

    await expect(
      respondToKeyExchange(tampered, bob, state, 'alice-user-id'),
    ).rejects.toThrow(/signature verification failed/);
  });

  test('rejects message signed by wrong identity', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const mallory = makeIdentity();

    // Alice initiates but we re-sign with Mallory's key (won't match senderIdKey)
    const initiation = await initiateKeyExchange(alice, bob.x25519PublicKey);

    // The senderIdKey in the payload is Alice's, but signature was made by Alice.
    // If we decode, change the signature to Mallory's, re-encode — verify should fail.
    const { decodeKeyExchange } = await import('../../protocol/decode');
    const payload = decodeKeyExchange(initiation.wireMessage);

    const signablePayload = concatBytes(
      payload.senderIdKey,
      payload.ephemeralX25519,
      payload.encryptedChatKey,
    );

    // Sign with Mallory's key (but senderIdKey still says Alice)
    const mallorySig = sign(signablePayload, mallory.ed25519PrivateKey);
    const tamperedWire = encodeKeyExchange({
      senderIdKey: payload.senderIdKey,
      ephemeralX25519: payload.ephemeralX25519,
      encryptedChatKey: payload.encryptedChatKey,
      signature: mallorySig,
    });

    const state = await makeUnlockedState();

    await expect(
      respondToKeyExchange(tamperedWire, bob, state, 'alice-user-id'),
    ).rejects.toThrow(/signature verification failed/);
  });

  test('TOFU: first key exchange stores contact as new', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const initiation = await initiateKeyExchange(alice, bob.x25519PublicKey);
    const state = await makeUnlockedState();

    const response = await respondToKeyExchange(
      initiation.wireMessage,
      bob,
      state,
      'alice-user-id',
    );

    expect(response.tofuStatus).toBe('new');
    expect(response.senderPublicKey).toEqual(alice.ed25519PublicKey);
  });

  test('TOFU: second exchange with same key is unchanged', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const state = await makeUnlockedState();

    // First exchange
    const init1 = await initiateKeyExchange(alice, bob.x25519PublicKey);
    const resp1 = await respondToKeyExchange(init1.wireMessage, bob, state, 'alice-user-id');
    expect(resp1.tofuStatus).toBe('new');

    // Second exchange with same identity
    const init2 = await initiateKeyExchange(alice, bob.x25519PublicKey);
    const resp2 = await respondToKeyExchange(init2.wireMessage, bob, state, 'alice-user-id');
    expect(resp2.tofuStatus).toBe('unchanged');
  });

  test('TOFU: exchange with different key triggers changed status', async () => {
    const alice1 = makeIdentity();
    const alice2 = makeIdentity(); // Different identity
    const bob = makeIdentity();

    const state = await makeUnlockedState();

    // First exchange with alice1's identity
    const init1 = await initiateKeyExchange(alice1, bob.x25519PublicKey);
    await respondToKeyExchange(init1.wireMessage, bob, state, 'alice-user-id');

    // Second exchange with alice2's identity (different ed25519 key)
    const init2 = await initiateKeyExchange(alice2, bob.x25519PublicKey);
    const resp2 = await respondToKeyExchange(init2.wireMessage, bob, state, 'alice-user-id');
    expect(resp2.tofuStatus).toBe('changed');
  });

  test('wrong recipient cannot decrypt', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const charlie = makeIdentity();

    // Alice initiates for Bob
    const initiation = await initiateKeyExchange(alice, bob.x25519PublicKey);
    const state = await makeUnlockedState();

    // Charlie tries to respond (wrong x25519 private key)
    // The ECDH will produce a different shared secret → decryption will fail
    await expect(
      respondToKeyExchange(initiation.wireMessage, charlie, state, 'alice-user-id'),
    ).rejects.toThrow();
  });
});
