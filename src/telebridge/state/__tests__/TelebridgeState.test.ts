/**
 * Telebridge v2 — TelebridgeState Unit Tests
 *
 * Comprehensive tests for the state management lifecycle:
 * - Lock/unlock roundtrip
 * - Wrong password rejection
 * - Password change re-encryption
 * - No plaintext in persisted state
 * - Identity keypair encrypt/decrypt
 * - Chat key storage
 * - Contact TOFU tracking
 * - Contact verification
 * - Key rotation tracking
 * - Edge cases
 */

import { Crypto } from '@peculiar/webcrypto';

// Polyfill Web Crypto for Node/jsdom test environment
Object.defineProperty(globalThis, 'crypto', { value: new Crypto() });

import { TelebridgeState } from '../TelebridgeState';
import { assertNoPlaintextSecrets } from '../validation';
import { deserialize } from '../serialization';
import { ContactTrustLevel, PLAINTEXT_FIELD_NAMES } from '../types';
import {
  randomBytes,
  ed25519Sign,
  ed25519Verify,
  toBase64,
} from '../../crypto';

const TEST_PASSWORD = 'test-bridge-password-2026';
const WRONG_PASSWORD = 'wrong-password-definitely';
const NEW_PASSWORD = 'new-bridge-password-2026';

describe('TelebridgeState', () => {
  // ---------------------------------------------------------------------------
  // Initialization
  // ---------------------------------------------------------------------------

  describe('initialize()', () => {
    it('should create a new state with identity keypair and encrypted persistence', async () => {
      const state = new TelebridgeState();
      const serialized = await state.initialize(TEST_PASSWORD);

      expect(state.isInitialized()).toBe(true);
      expect(state.isLocked()).toBe(false);

      // Persisted state should be valid JSON
      const persisted = deserialize(serialized);
      expect(persisted.formatVersion).toBe(2);
      expect(persisted.passwordSalt).toBeTruthy();
      expect(persisted.passwordVerifier).toBeTruthy();
      expect(persisted.identity).toBeDefined();
      expect(persisted.identity!.ed25519PublicKey).toBeTruthy();
      expect(persisted.identity!.x25519PublicKey).toBeTruthy();
      expect(persisted.identity!.encryptedEd25519PrivateKey).toBeTruthy();
      expect(persisted.identity!.encryptedX25519PrivateKey).toBeTruthy();
    });

    it('should throw if called twice', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);
      await expect(state.initialize(TEST_PASSWORD)).rejects.toThrow('already initialized');
    });
  });

  // ---------------------------------------------------------------------------
  // Lock / Unlock Roundtrip
  // ---------------------------------------------------------------------------

  describe('lock/unlock roundtrip', () => {
    it('should lock and unlock with correct password', async () => {
      const state = new TelebridgeState();
      const serialized = await state.initialize(TEST_PASSWORD);

      // Get identity before lock
      const identityBefore = state.getIdentityKeyPair();
      const ed25519PubBefore = identityBefore.ed25519PublicKey.slice();
      const ed25519PrivBefore = identityBefore.ed25519PrivateKey.slice();

      // Lock
      state.lock();
      expect(state.isLocked()).toBe(true);

      // Operations should throw while locked
      expect(() => state.getIdentityKeyPair()).toThrow('locked');

      // Unlock with correct password
      await state.unlock(TEST_PASSWORD);
      expect(state.isLocked()).toBe(false);

      // Identity should match what we had before
      const identityAfter = state.getIdentityKeyPair();
      expect(toBase64(identityAfter.ed25519PublicKey)).toBe(toBase64(ed25519PubBefore));
      expect(toBase64(identityAfter.ed25519PrivateKey)).toBe(toBase64(ed25519PrivBefore));
    });

    it('should restore state from serialized form', async () => {
      const state1 = new TelebridgeState();
      const serialized = await state1.initialize(TEST_PASSWORD);
      const pubKeyBefore = toBase64(state1.getIdentityKeyPair().ed25519PublicKey);
      state1.lock();

      // Load into a new state instance
      const state2 = new TelebridgeState();
      state2.load(serialized);
      expect(state2.isInitialized()).toBe(true);
      expect(state2.isLocked()).toBe(true);

      await state2.unlock(TEST_PASSWORD);
      const pubKeyAfter = toBase64(state2.getIdentityKeyPair().ed25519PublicKey);
      expect(pubKeyAfter).toBe(pubKeyBefore);
    });
  });

  // ---------------------------------------------------------------------------
  // Wrong Password Rejection
  // ---------------------------------------------------------------------------

  describe('wrong password rejection', () => {
    it('should reject wrong password without corrupting state', async () => {
      const state = new TelebridgeState();
      const serialized = await state.initialize(TEST_PASSWORD);
      state.lock();

      // Try wrong password
      await expect(state.unlock(WRONG_PASSWORD)).rejects.toThrow('Incorrect password');

      // State should still be locked
      expect(state.isLocked()).toBe(true);

      // Correct password should still work
      await state.unlock(TEST_PASSWORD);
      expect(state.isLocked()).toBe(false);
      expect(state.getIdentityKeyPair()).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Password Change
  // ---------------------------------------------------------------------------

  describe('changePassword()', () => {
    it('should re-encrypt all secrets under new password', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      // Store a chat key first
      const chatKey = randomBytes(32);
      await state.storeChatKey('chat-123', chatKey);

      const pubKeyBefore = toBase64(state.getIdentityKeyPair().ed25519PublicKey);
      const chatKeyBefore = toBase64(state.getChatKey('chat-123')!);

      // Change password
      const newSerialized = await state.changePassword(TEST_PASSWORD, NEW_PASSWORD);

      // Lock and unlock with new password
      state.lock();
      await state.unlock(NEW_PASSWORD);

      // All keys should still be accessible
      const pubKeyAfter = toBase64(state.getIdentityKeyPair().ed25519PublicKey);
      expect(pubKeyAfter).toBe(pubKeyBefore);

      const chatKeyAfter = toBase64(state.getChatKey('chat-123')!);
      expect(chatKeyAfter).toBe(chatKeyBefore);
    });

    it('should reject old password after change', async () => {
      const state = new TelebridgeState();
      const serialized = await state.initialize(TEST_PASSWORD);
      await state.changePassword(TEST_PASSWORD, NEW_PASSWORD);

      state.lock();
      await expect(state.unlock(TEST_PASSWORD)).rejects.toThrow('Incorrect password');
    });

    it('should reject wrong current password', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);
      await expect(state.changePassword(WRONG_PASSWORD, NEW_PASSWORD)).rejects.toThrow('incorrect');
    });
  });

  // ---------------------------------------------------------------------------
  // No Plaintext in Persisted State
  // ---------------------------------------------------------------------------

  describe('no plaintext secrets in persisted state', () => {
    it('should never contain plaintext secret field names', async () => {
      const state = new TelebridgeState();
      const serialized = await state.initialize(TEST_PASSWORD);

      // Parse and scan
      const parsed = JSON.parse(serialized);
      expect(() => assertNoPlaintextSecrets(parsed)).not.toThrow();

      // Deep scan for any field matching forbidden names
      const allKeys = getAllKeys(parsed);
      for (const forbidden of PLAINTEXT_FIELD_NAMES) {
        expect(allKeys).not.toContain(forbidden);
      }
    });

    it('should pass validation after password change', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);
      await state.storeChatKey('chat-1', randomBytes(32));
      const serialized = await state.changePassword(TEST_PASSWORD, NEW_PASSWORD);

      const parsed = JSON.parse(serialized);
      expect(() => assertNoPlaintextSecrets(parsed)).not.toThrow();
    });

    it('should pass validation after key rotation', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);
      await state.storeChatKey('chat-1', randomBytes(32));
      const serialized = await state.rotateKey('chat-1', randomBytes(32));

      const parsed = JSON.parse(serialized);
      expect(() => assertNoPlaintextSecrets(parsed)).not.toThrow();
    });
  });

  // ---------------------------------------------------------------------------
  // Identity Keypair
  // ---------------------------------------------------------------------------

  describe('identity keypair', () => {
    it('should generate valid Ed25519 keypair that can sign and verify', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      const identity = state.getIdentityKeyPair();
      const message = new Uint8Array([1, 2, 3, 4, 5]);

      // Sign with private key
      const signature = ed25519Sign(message, identity.ed25519PrivateKey);

      // Verify with public key
      const valid = ed25519Verify(message, signature, identity.ed25519PublicKey);
      expect(valid).toBe(true);

      // Verify fails with wrong message
      const wrongMessage = new Uint8Array([5, 4, 3, 2, 1]);
      const invalid = ed25519Verify(wrongMessage, signature, identity.ed25519PublicKey);
      expect(invalid).toBe(false);
    });

    it('should survive lock/unlock cycle', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      const message = new Uint8Array([10, 20, 30]);
      const identity = state.getIdentityKeyPair();
      const signature = ed25519Sign(message, identity.ed25519PrivateKey);

      state.lock();
      await state.unlock(TEST_PASSWORD);

      const restored = state.getIdentityKeyPair();
      const valid = ed25519Verify(message, signature, restored.ed25519PublicKey);
      expect(valid).toBe(true);
    });

    it('should provide public keys even when locked', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      const pubKeys = state.getPublicKeys();
      expect(pubKeys).toBeDefined();
      expect(pubKeys!.ed25519PublicKey.length).toBe(32);
      expect(pubKeys!.x25519PublicKey.length).toBe(32);

      state.lock();

      // Public keys still accessible when locked
      const pubKeysLocked = state.getPublicKeys();
      expect(pubKeysLocked).toBeDefined();
      expect(toBase64(pubKeysLocked!.ed25519PublicKey)).toBe(toBase64(pubKeys!.ed25519PublicKey));
    });
  });

  // ---------------------------------------------------------------------------
  // Chat Key Storage
  // ---------------------------------------------------------------------------

  describe('chat key storage', () => {
    it('should store and retrieve chat keys', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      const key = randomBytes(32);
      await state.storeChatKey('chat-456', key);

      const retrieved = state.getChatKey('chat-456');
      expect(retrieved).toBeDefined();
      expect(toBase64(retrieved!)).toBe(toBase64(key));
    });

    it('should survive lock/unlock cycle', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      const key = randomBytes(32);
      await state.storeChatKey('chat-789', key);

      state.lock();
      expect(() => state.getChatKey('chat-789')).toThrow('locked');

      await state.unlock(TEST_PASSWORD);
      const retrieved = state.getChatKey('chat-789');
      expect(toBase64(retrieved!)).toBe(toBase64(key));
    });

    it('should return undefined for non-existent chat key', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      const result = state.getChatKey('nonexistent');
      expect(result).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Contact TOFU
  // ---------------------------------------------------------------------------

  describe('contact TOFU tracking', () => {
    it('should accept first-seen key as initial trust', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      const contactPub = randomBytes(32);
      const contactX25519 = randomBytes(32);
      const result = state.storeContactKey('user-1', contactPub, contactX25519);

      expect(result.status).toBe('new');

      const contact = state.getContactKey('user-1');
      expect(contact).toBeDefined();
      expect(contact!.trustLevel).toBe(ContactTrustLevel.Initial);
    });

    it('should flag key change and archive the new key (no overwrite of active)', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      const firstKey = randomBytes(32);
      const firstX25519 = randomBytes(32);
      state.storeContactKey('user-2', firstKey, firstX25519);

      // Change key — the new shape appends-as-inactive rather than overwriting.
      const secondKey = randomBytes(32);
      const secondX25519 = randomBytes(32);
      const result = state.storeContactKey('user-2', secondKey, secondX25519);

      expect(result.status).toBe('changed');

      const contact = state.getContactKey('user-2');
      expect(contact!.trustLevel).toBe(ContactTrustLevel.Changed);
      // Active key remains the original; new key appended as archived.
      expect(contact!.ed25519PublicKey).toBe(toBase64(firstKey));
      expect(contact!.keys.length).toBe(2);
      const archived = contact!.keys.find((k) => k.keyId !== contact!.activeKeyId);
      expect(archived).toBeDefined();
      expect(archived!.ed25519PublicKey).toBe(toBase64(secondKey));
      expect(archived!.archivedAt).toBeDefined();
    });

    it('should return unchanged for same key', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      const key = randomBytes(32);
      const x25519 = randomBytes(32);
      state.storeContactKey('user-3', key, x25519);

      const result = state.storeContactKey('user-3', key, x25519);
      expect(result.status).toBe('unchanged');
    });

    it('should return undefined for unknown contact', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      expect(state.getContactKey('unknown')).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Contact Verification
  // ---------------------------------------------------------------------------

  describe('contact verification', () => {
    it('should mark contact as verified', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      state.storeContactKey('user-v', randomBytes(32), randomBytes(32));
      state.verifyContact('user-v');

      const contact = state.getContactKey('user-v');
      expect(contact!.trustLevel).toBe(ContactTrustLevel.Verified);
      expect(contact!.verifiedAt).toBeDefined();
    });

    it('should persist verified status through lock/unlock', async () => {
      const state = new TelebridgeState();
      const serialized = await state.initialize(TEST_PASSWORD);

      state.storeContactKey('user-vp', randomBytes(32), randomBytes(32));
      state.verifyContact('user-vp');

      // Persist and reload
      const persisted = state.toPersistable();
      const state2 = new TelebridgeState();
      state2.load(persisted);
      await state2.unlock(TEST_PASSWORD);

      const contact = state2.getContactKey('user-vp');
      expect(contact!.trustLevel).toBe(ContactTrustLevel.Verified);
      expect(contact!.verifiedAt).toBeDefined();
    });

    it('should throw for unknown contact', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      expect(() => state.verifyContact('unknown')).toThrow('Unknown contact');
    });

    it('should reset verification on key change', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      state.storeContactKey('user-vr', randomBytes(32), randomBytes(32));
      state.verifyContact('user-vr');
      expect(state.getContactKey('user-vr')!.trustLevel).toBe(ContactTrustLevel.Verified);

      // Key change should reset to Changed
      state.storeContactKey('user-vr', randomBytes(32), randomBytes(32));
      expect(state.getContactKey('user-vr')!.trustLevel).toBe(ContactTrustLevel.Changed);
      expect(state.getContactKey('user-vr')!.verifiedAt).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Key Rotation Tracking
  // ---------------------------------------------------------------------------

  describe('key rotation', () => {
    it('should increment version and track previous key', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      const originalKey = randomBytes(32);
      await state.storeChatKey('chat-rot', originalKey);

      const newKey = randomBytes(32);
      await state.rotateKey('chat-rot', newKey);

      // Current key should be the new one
      const currentKey = state.getChatKey('chat-rot');
      expect(toBase64(currentKey!)).toBe(toBase64(newKey));

      // Previous key should be the original
      const previousKey = state.getPreviousChatKey('chat-rot');
      expect(previousKey).toBeDefined();
      expect(toBase64(previousKey!)).toBe(toBase64(originalKey));

      // Rotation info should show version 1
      const info = state.getRotationInfo('chat-rot');
      expect(info).toBeDefined();
      expect(info!.rotationVersion).toBe(1);
      expect(info!.hasPreviousKey).toBe(true);
      expect(info!.lastRotatedAt).toBeGreaterThan(0);
    });

    it('should survive lock/unlock after rotation', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      const originalKey = randomBytes(32);
      await state.storeChatKey('chat-rot2', originalKey);

      const newKey = randomBytes(32);
      await state.rotateKey('chat-rot2', newKey);

      state.lock();
      await state.unlock(TEST_PASSWORD);

      expect(toBase64(state.getChatKey('chat-rot2')!)).toBe(toBase64(newKey));
      expect(toBase64(state.getPreviousChatKey('chat-rot2')!)).toBe(toBase64(originalKey));
      expect(state.getRotationInfo('chat-rot2')!.rotationVersion).toBe(1);
    });

    it('should throw if no existing key to rotate', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      await expect(state.rotateKey('nonexistent', randomBytes(32))).rejects.toThrow('No existing key');
    });

    it('should handle multiple rotations', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      const key1 = randomBytes(32);
      await state.storeChatKey('chat-multi', key1);

      const key2 = randomBytes(32);
      await state.rotateKey('chat-multi', key2);

      const key3 = randomBytes(32);
      await state.rotateKey('chat-multi', key3);

      expect(toBase64(state.getChatKey('chat-multi')!)).toBe(toBase64(key3));
      // Previous should be key2 (only one previous preserved)
      expect(toBase64(state.getPreviousChatKey('chat-multi')!)).toBe(toBase64(key2));
      expect(state.getRotationInfo('chat-multi')!.rotationVersion).toBe(2);
    });
  });

  // ---------------------------------------------------------------------------
  // Edge Cases
  // ---------------------------------------------------------------------------

  describe('edge cases', () => {
    it('double-lock should be a no-op', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      state.lock();
      expect(state.isLocked()).toBe(true);

      // Second lock should not throw
      state.lock();
      expect(state.isLocked()).toBe(true);
    });

    it('unlock when already unlocked should be a no-op', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);

      expect(state.isLocked()).toBe(false);

      // Double unlock should not throw
      await state.unlock(TEST_PASSWORD);
      expect(state.isLocked()).toBe(false);
    });

    it('operations while locked should throw', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);
      state.lock();

      expect(() => state.getIdentityKeyPair()).toThrow('locked');
      expect(() => state.getChatKey('any')).toThrow('locked');
      await expect(state.storeChatKey('any', randomBytes(32))).rejects.toThrow('locked');
      await expect(state.rotateKey('any', randomBytes(32))).rejects.toThrow('locked');
      await expect(state.changePassword('a', 'b')).rejects.toThrow('locked');
    });

    it('unlock without initialization should throw', async () => {
      const state = new TelebridgeState();
      await expect(state.unlock(TEST_PASSWORD)).rejects.toThrow('not initialized');
    });

    it('getRotationInfo should work when locked', async () => {
      const state = new TelebridgeState();
      await state.initialize(TEST_PASSWORD);
      await state.storeChatKey('chat-info', randomBytes(32));
      await state.rotateKey('chat-info', randomBytes(32));

      state.lock();

      const info = state.getRotationInfo('chat-info');
      expect(info).toBeDefined();
      expect(info!.rotationVersion).toBe(1);
    });
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Recursively collect all keys from an object */
function getAllKeys(obj: unknown, prefix = ''): string[] {
  if (typeof obj !== 'object' || obj === null) return [];
  const keys: string[] = [];
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    keys.push(key);
    if (typeof value === 'object' && value !== null) {
      keys.push(...getAllKeys(value, `${prefix}${key}.`));
    }
  }
  return keys;
}
