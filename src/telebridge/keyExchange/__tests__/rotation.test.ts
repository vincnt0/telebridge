import { Crypto } from '@peculiar/webcrypto';

// Polyfill Web Crypto for Node/jsdom test environment
Object.defineProperty(globalThis, 'crypto', { value: new Crypto() });

import {
  generateKeyExchangeKeyPair,
  generateSigningKeyPair,
} from '../../crypto';
import type { DecryptedIdentity } from '../../state/types';
import { TelebridgeState } from '../../state/TelebridgeState';

import { shouldRotate, performRotation } from '../rotation';
import type { RotationConfig } from '../types';

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
  await state.initialize('test-password-rotation');
  return state;
}

describe('shouldRotate', () => {
  test('returns false when no key exists for chat', async () => {
    const state = await makeUnlockedState();

    const result = shouldRotate('nonexistent-chat', state);
    expect(result.shouldRotate).toBe(false);
    expect(result.reason).toBeUndefined();
  });

  test('returns false when under both thresholds', async () => {
    const state = await makeUnlockedState();
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    await state.storeChatKey('chat-1', key, 'abcd1234');

    const result = shouldRotate('chat-1', state);
    expect(result.shouldRotate).toBe(false);
  });

  test('returns true with reason message_count when count exceeds threshold', async () => {
    const state = await makeUnlockedState();
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    await state.storeChatKey('chat-1', key, 'abcd1234');

    // Simulate reaching the threshold
    const config: RotationConfig = { maxMessages: 5, maxDays: 365 };

    for (let i = 0; i < 5; i++) {
      state.incrementMessageCount('chat-1');
    }

    const result = shouldRotate('chat-1', state, config);
    expect(result.shouldRotate).toBe(true);
    expect(result.reason).toBe('message_count');
  });

  test('returns true with reason time_elapsed when time exceeds threshold', async () => {
    const state = await makeUnlockedState();
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    await state.storeChatKey('chat-1', key, 'abcd1234');

    // Use a very short time threshold (0 days = immediate)
    const config: RotationConfig = { maxMessages: 999, maxDays: 0 };

    const result = shouldRotate('chat-1', state, config);
    expect(result.shouldRotate).toBe(true);
    expect(result.reason).toBe('time_elapsed');
  });

  test('message count threshold is checked before time threshold', async () => {
    const state = await makeUnlockedState();
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    await state.storeChatKey('chat-1', key, 'abcd1234');

    // Both conditions met: low thresholds
    const config: RotationConfig = { maxMessages: 1, maxDays: 0 };
    state.incrementMessageCount('chat-1');

    const result = shouldRotate('chat-1', state, config);
    expect(result.shouldRotate).toBe(true);
    expect(result.reason).toBe('message_count'); // Count checked first
  });
});

describe('performRotation', () => {
  test('generates a new key and wire message', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const state = await makeUnlockedState();

    // First, store an initial key
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    await state.storeChatKey('chat-1', key, 'abcd1234');

    // Perform rotation
    const result = await performRotation('chat-1', alice, bob.x25519PublicKey, state);

    expect(result.wireMessage).toBeDefined();
    expect(result.wireMessage.startsWith('tb1.kx.')).toBe(true);
    expect(result.newKey).toBeInstanceOf(Uint8Array);
    expect(result.newKey.length).toBe(32);
    expect(typeof result.newKeyId).toBe('string');
  });

  test('preserves previous key after rotation', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const state = await makeUnlockedState();

    const originalKey = new Uint8Array(32);
    crypto.getRandomValues(originalKey);
    await state.storeChatKey('chat-1', originalKey, 'abcd1234');

    await performRotation('chat-1', alice, bob.x25519PublicKey, state);

    const info = state.getRotationInfo('chat-1');
    expect(info).toBeDefined();
    expect(info!.hasPreviousKey).toBe(true);
    expect(info!.previousKeyId).toBe('abcd1234');
    expect(info!.rotationVersion).toBe(1);
  });

  test('new key differs from original key', async () => {
    const { constantTimeEqual } = await import('../../crypto/utils');
    const alice = makeIdentity();
    const bob = makeIdentity();
    const state = await makeUnlockedState();

    const originalKey = new Uint8Array(32);
    crypto.getRandomValues(originalKey);
    await state.storeChatKey('chat-1', originalKey, 'abcd1234');

    const result = await performRotation('chat-1', alice, bob.x25519PublicKey, state);

    expect(constantTimeEqual(originalKey, result.newKey)).toBe(false);
  });

  test('rotation resets message count to zero', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const state = await makeUnlockedState();

    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    await state.storeChatKey('chat-1', key, 'abcd1234');

    // Increment message count
    for (let i = 0; i < 50; i++) {
      state.incrementMessageCount('chat-1');
    }

    const beforeRecord = state.getDecryptedChatKeyRecord('chat-1');
    expect(beforeRecord!.messageCount).toBe(50);

    await performRotation('chat-1', alice, bob.x25519PublicKey, state);

    const afterRecord = state.getDecryptedChatKeyRecord('chat-1');
    expect(afterRecord!.messageCount).toBe(0);
  });

  test('throws when no existing key to rotate', async () => {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const state = await makeUnlockedState();

    await expect(
      performRotation('no-such-chat', alice, bob.x25519PublicKey, state),
    ).rejects.toThrow(/No existing key/);
  });
});
