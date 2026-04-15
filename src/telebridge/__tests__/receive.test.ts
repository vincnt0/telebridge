/**
 * Telebridge v3 — Receive-Pipeline Self-Sender Coverage.
 *
 * Guards the bug where a user's own outgoing encrypted message (both tb1.s
 * plain composer and tb1.a Send Secured) would be left as raw ciphertext on
 * the sender's own screen with the MessageMeta red warn glyph — because
 * `vault.getContactKey(self)` is always undefined (self is not a contact).
 *
 * Repro preconditions:
 *  - vault unlocked
 *  - chat key installed via the same path `bridgeSetManualChatKey` uses
 *    (`vault.storeChatKey(chatId, key, undefined, '__manual__')`)
 *  - `global.currentUserId` equals the senderId of the outgoing envelope
 *
 * Verifies, end-to-end through the receive functions:
 *  1. `ensureDecryptedText` (symmetric tb1.s) populates
 *     `global.bridge.decryptedByKey[messageKey]` for self-sender messages.
 *  2. `ensureAsymmetricProcessed` (tb1.a) handles the encrypt-to-self
 *     sibling on the sender's own screen: plaintext cached + marked decrypted;
 *     the encrypt-to-recipient sibling is marked filtered (GCM notForMe).
 */

import { Crypto } from '@peculiar/webcrypto';

// Polyfill Web Crypto for the jest/Node environment. Must run before any
// aes/asymmetric/decrypt module touches `crypto.subtle` on first import.
Object.defineProperty(globalThis, 'crypto', { value: new Crypto() });

// Stub out the global/index module so receive.ts can dispatch actions into
// our captured fakes without pulling in the full action handler graph.
// Map shape mirrors `global.bridge.decryptedByKey` + the two asymmetric
// markers; `currentUserId` drives the self-sender branch in
// ensureAsymmetricProcessed. Names must be prefixed with `mock` to satisfy
// jest's factory out-of-scope-variable guard.
type MockGlobalShape = {
  currentUserId?: string;
  bridge: {
    decryptedByKey: Record<string, string>;
    filteredAsymmetricMessageIds: Record<string, true>;
    asymmetricDecryptedMessageIds: Record<string, true>;
  };
};

const mockGlobal: MockGlobalShape = {
  currentUserId: undefined,
  bridge: {
    decryptedByKey: {},
    filteredAsymmetricMessageIds: {},
    asymmetricDecryptedMessageIds: {},
  },
};

const mockActions = {
  bridgeSetDecryptedText: jest.fn(({ messageKey, text }: { messageKey: string; text: string }) => {
    mockGlobal.bridge.decryptedByKey[messageKey] = text;
  }),
  bridgeMarkAsymmetricFiltered: jest.fn(({ messageKey }: { messageKey: string }) => {
    mockGlobal.bridge.filteredAsymmetricMessageIds[messageKey] = true;
  }),
  bridgeMarkAsymmetricDecrypted: jest.fn(({ messageKey }: { messageKey: string }) => {
    mockGlobal.bridge.asymmetricDecryptedMessageIds[messageKey] = true;
  }),
};

jest.mock('../../global/index', () => ({
  getGlobal: () => mockGlobal,
  getActions: () => mockActions,
}));

import { encryptForRecipient } from '../crypto/asymmetric';
import { encodeUtf8 } from '../crypto/utils';
import { encodeSecuredMessage } from '../protocol/encode';
import {
  ensureAsymmetricProcessed,
  ensureDecryptedText,
  resetAsymmetricReceive,
} from '../receive';
import { encryptOutgoingText, setTelebridgeVault } from '../send';
import { TelebridgeState } from '../state';

const TEST_PASSWORD = 'test-bridge-password-2026';
const SELF_USER_ID = '1000000001';
const CHAT_ID = '1000000001'; // 1:1 chat: chatId === peer user id, but for
// self-sender tests we just need a valid string.

// Shared helper: swap in a fresh vault with a known 32-byte chat key and
// reset per-test receive-side state (inflight/processed caches, fake global
// buffers, action spies). Returns the vault for follow-up reads (identity
// keys, etc.).
async function buildFreshVault(chatKey: Uint8Array): Promise<TelebridgeState> {
  const vault = new TelebridgeState();
  await vault.initialize(TEST_PASSWORD);
  // Mirror the `bridgeSetManualChatKey` path — `'__manual__'` sentinel so
  // the chat-key entry is tagged the same way the debug-only UI tags it.
  await vault.storeChatKey(CHAT_ID, chatKey, undefined, '__manual__');
  setTelebridgeVault(vault);
  return vault;
}

function resetMockState(currentUserId: string) {
  mockGlobal.currentUserId = currentUserId;
  mockGlobal.bridge.decryptedByKey = {};
  mockGlobal.bridge.filteredAsymmetricMessageIds = {};
  mockGlobal.bridge.asymmetricDecryptedMessageIds = {};
  mockActions.bridgeSetDecryptedText.mockClear();
  mockActions.bridgeMarkAsymmetricFiltered.mockClear();
  mockActions.bridgeMarkAsymmetricDecrypted.mockClear();
  resetAsymmetricReceive();
}

// Wait for the fire-and-forget decrypt promise chain to drain. The receive
// functions return synchronously and kick off `void (async () => ...)`; the
// async body awaits Web Crypto (which in the @peculiar/webcrypto polyfill
// may queue macrotasks), so a plain microtask flush isn't enough.
// `setTimeout(0)` lets the macrotask queue run — we loop to cover nested
// awaits.
async function flushAsync() {
  for (let i = 0; i < 20; i++) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

describe('Telebridge receive — self-sender plaintext cache', () => {
  describe('ensureDecryptedText (tb1.s symmetric)', () => {
    it('caches plaintext for the user\'s own outgoing symmetric message', async () => {
      const chatKey = new Uint8Array(32);
      chatKey.fill(0xAB);
      await buildFreshVault(chatKey);
      resetMockState(SELF_USER_ID);

      const plaintext = 'Hello from self via tb1.s';
      const wire = await encryptOutgoingText(plaintext, CHAT_ID);
      expect(wire.startsWith('tb1.s.')).toBe(true);

      const messageKey = `${CHAT_ID}-self-sym-1`;
      // senderId === currentUserId — the exact case the bug report describes.
      ensureDecryptedText(CHAT_ID, messageKey, wire, SELF_USER_ID);
      await flushAsync();

      expect(mockGlobal.bridge.decryptedByKey[messageKey]).toBe(plaintext);
      expect(mockActions.bridgeSetDecryptedText).toHaveBeenCalledWith({
        messageKey, text: plaintext,
      });
    });
  });

  describe('ensureAsymmetricProcessed (tb1.a Send Secured)', () => {
    it('caches plaintext for the user\'s own encrypt-to-self sibling envelope', async () => {
      const chatKey = new Uint8Array(32);
      chatKey.fill(0xCD);
      const vault = await buildFreshVault(chatKey);
      resetMockState(SELF_USER_ID);

      const identity = vault.getIdentityKeyPair();
      const plaintext = 'Hello from self via tb1.a (encrypt-to-self sibling)';

      // Reproduce the send-secured fan-out for the encrypt-to-self envelope.
      // `bridgeSendSecured` generates both envelopes and sends them in sequence;
      // here we just need the sibling that our own X25519 key can open.
      const payload = await encryptForRecipient(
        encodeUtf8(plaintext),
        identity.x25519PublicKey,
        identity.ed25519PrivateKey,
      );
      const wire = encodeSecuredMessage(payload);
      expect(wire.startsWith('tb1.a.')).toBe(true);

      const messageKey = `${CHAT_ID}-self-asym-self-1`;
      ensureAsymmetricProcessed(CHAT_ID, messageKey, wire, SELF_USER_ID);
      await flushAsync();

      expect(mockGlobal.bridge.decryptedByKey[messageKey]).toBe(plaintext);
      expect(mockGlobal.bridge.asymmetricDecryptedMessageIds[messageKey]).toBe(true);
      expect(mockGlobal.bridge.filteredAsymmetricMessageIds[messageKey]).toBeUndefined();
    });

    it('filters the user\'s own encrypt-to-recipient sibling envelope (GCM notForMe)', async () => {
      const chatKey = new Uint8Array(32);
      chatKey.fill(0xEF);
      const vault = await buildFreshVault(chatKey);
      resetMockState(SELF_USER_ID);

      const identity = vault.getIdentityKeyPair();

      // Build a recipient X25519 pub that is NOT ours. Simplest construction:
      // spin up another state to borrow a fresh identity's X25519 pub.
      const peerVault = new TelebridgeState();
      await peerVault.initialize(TEST_PASSWORD);
      const peerIdentity = peerVault.getIdentityKeyPair();

      const plaintext = 'Hello — this sibling is NOT for me';
      const payload = await encryptForRecipient(
        encodeUtf8(plaintext),
        peerIdentity.x25519PublicKey,
        identity.ed25519PrivateKey,
      );
      const wire = encodeSecuredMessage(payload);

      const messageKey = `${CHAT_ID}-self-asym-recipient-1`;
      ensureAsymmetricProcessed(CHAT_ID, messageKey, wire, SELF_USER_ID);
      await flushAsync();

      // GCM fails against our X25519 key → flagged for render filter,
      // plaintext cache untouched (no warning glyph, no leaked ciphertext).
      expect(mockGlobal.bridge.filteredAsymmetricMessageIds[messageKey]).toBe(true);
      expect(mockGlobal.bridge.decryptedByKey[messageKey]).toBeUndefined();
      expect(mockGlobal.bridge.asymmetricDecryptedMessageIds[messageKey]).toBeUndefined();
    });
  });
});
