import { Crypto } from '@peculiar/webcrypto';

// Polyfill Web Crypto for Node/jsdom test environment
Object.defineProperty(globalThis, 'crypto', { value: new Crypto() });

import {
  constantTimeEqual,
  generateKeyExchangeKeyPair,
  generateSigningKeyPair,
} from '../../crypto';
import type { DecryptedIdentity } from '../../state/types';
import { TelebridgeState } from '../../state/TelebridgeState';

import { initiateKeyExchange } from '../initiate';
import { respondToKeyExchange } from '../respond';

/** Derive X25519 keypair from Ed25519 seed */
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
  await state.initialize('test-password-roundtrip');
  return state;
}

/** Wraps respondToKeyExchange + asserts the 'ok' branch so test bodies can read .chatKey etc. */
async function respondOk(
  wire: string,
  recipient: DecryptedIdentity,
  state: TelebridgeState,
  senderId: string,
  pinnedSenderIdKey: Uint8Array,
) {
  const r = await respondToKeyExchange(wire, recipient, state, senderId, pinnedSenderIdKey);
  if (r.status !== 'ok') {
    throw new Error(`Expected ok, got ${r.status}`);
  }
  return r;
}

describe('Key Exchange Roundtrip', () => {
  test('Alice initiates → Bob responds → both derive identical chat key', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    // Alice initiates key exchange targeting Bob's X25519 public key
    const initiation = await initiateKeyExchange(alice, bob.x25519PublicKey);

    // Bob receives the wire message and responds
    const state = await makeUnlockedState();
    const response = await respondOk(
      initiation.wireMessage,
      bob,
      state,
      'alice-user-id',
      alice.ed25519PublicKey,
    );

    // Both sides should have byte-identical chat keys
    expect(constantTimeEqual(initiation.chatKey, response.chatKey)).toBe(true);
    expect(initiation.chatKey.length).toBe(32);
    expect(response.chatKey.length).toBe(32);
  });

  test('keyId is identical on both sides', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const initiation = await initiateKeyExchange(alice, bob.x25519PublicKey);
    const state = await makeUnlockedState();

    const response = await respondOk(
      initiation.wireMessage,
      bob,
      state,
      'alice-user-id',
      alice.ed25519PublicKey,
    );

    expect(response.keyId).toBe(initiation.keyId);
  });

  test('multiple sequential exchanges produce unique keys', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const state = await makeUnlockedState();

    const keys: Uint8Array[] = [];

    for (let i = 0; i < 3; i++) {
      const initiation = await initiateKeyExchange(alice, bob.x25519PublicKey);
      const response = await respondOk(
        initiation.wireMessage,
        bob,
        state,
        'alice-user-id',
        alice.ed25519PublicKey,
      );

      expect(constantTimeEqual(initiation.chatKey, response.chatKey)).toBe(true);
      keys.push(response.chatKey);
    }

    // All three keys should be different
    expect(constantTimeEqual(keys[0], keys[1])).toBe(false);
    expect(constantTimeEqual(keys[1], keys[2])).toBe(false);
    expect(constantTimeEqual(keys[0], keys[2])).toBe(false);
  });

  test('bidirectional exchange: Alice→Bob and Bob→Alice both work', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    // Alice → Bob
    const aliceInit = await initiateKeyExchange(alice, bob.x25519PublicKey);
    const bobState = await makeUnlockedState();
    const bobResponse = await respondOk(
      aliceInit.wireMessage,
      bob,
      bobState,
      'alice-user-id',
      alice.ed25519PublicKey,
    );
    expect(constantTimeEqual(aliceInit.chatKey, bobResponse.chatKey)).toBe(true);

    // Bob → Alice
    const bobInit = await initiateKeyExchange(bob, alice.x25519PublicKey);
    const aliceState = await makeUnlockedState();
    const aliceResponse = await respondOk(
      bobInit.wireMessage,
      alice,
      aliceState,
      'bob-user-id',
      bob.ed25519PublicKey,
    );
    expect(constantTimeEqual(bobInit.chatKey, aliceResponse.chatKey)).toBe(true);

    // The two exchanges should produce different keys
    expect(constantTimeEqual(aliceInit.chatKey, bobInit.chatKey)).toBe(false);
  });

  test('sender identity is correctly propagated', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const initiation = await initiateKeyExchange(alice, bob.x25519PublicKey);
    const state = await makeUnlockedState();

    const response = await respondOk(
      initiation.wireMessage,
      bob,
      state,
      'alice-user-id',
      alice.ed25519PublicKey,
    );

    expect(response.senderPublicKey).toEqual(alice.ed25519PublicKey);
  });

  test('chat key can be used for AES-256-GCM encryption/decryption', async () => {
    const { encrypt, decrypt, encodeUtf8, decodeUtf8 } = await import('../../crypto');

    const alice = makeIdentity();
    const bob = makeIdentity();

    const initiation = await initiateKeyExchange(alice, bob.x25519PublicKey);
    const state = await makeUnlockedState();

    const response = await respondOk(
      initiation.wireMessage,
      bob,
      state,
      'alice-user-id',
      alice.ed25519PublicKey,
    );

    // Alice encrypts a message with the shared chat key
    const plaintext = encodeUtf8('Hello, Bob! This is a secret message.');
    const encrypted = await encrypt(plaintext, initiation.chatKey);

    // Bob decrypts with his copy of the chat key
    const decrypted = await decrypt(encrypted, response.chatKey);
    expect(decodeUtf8(decrypted)).toBe('Hello, Bob! This is a secret message.');
  });
});
