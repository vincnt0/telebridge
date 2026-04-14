/**
 * Telebridge bridge actions.
 *
 * Vault lifecycle (first-run setup, unlock, lock, password change, chat-key
 * storage) plus the runtime decrypted-plaintext cache used by the render
 * path. All vault work goes through the singleton in `src/telebridge/send.ts`
 * (`getTelebridgeVault()`); this module mirrors its state into `global.bridge`
 * so components can react without touching the vault directly.
 *
 * Error handling: async actions that can fail (`bridgeUnlock`,
 * `bridgeChangePassword`) trap the error, write a short message to
 * `global.bridge.lastError`, and clear `isBusy`. Components display the
 * string; `bridgeClearError` wipes it on next attempt. Passwords themselves
 * are never written to global state — only the derived/encrypted outputs
 * handled by TelebridgeState.
 */

import type { ActionReturnType, GlobalState } from '../../types';

import { concatBytes, ed25519Sign } from '../../../telebridge/crypto';
import { initiateKeyExchange, respondToKeyExchange } from '../../../telebridge/keyExchange';
import { ContactTrustLevel } from '../../../telebridge/state/types';
import { decodePrekeyPublication } from '../../../telebridge/protocol/decode';
import { encodePrekeyPublication } from '../../../telebridge/protocol/encode';
import { InvalidSignatureError, verifyPrekeyBundle } from '../../../telebridge/protocol/verify';
import { backfillDecryptsForAllChats } from '../../../telebridge/receive';
import { getTelebridgeVault } from '../../../telebridge/send';
import { isUserId } from '../../../util/entities/ids';
import { getCurrentTabId } from '../../../util/establishMultitabRole';
import { pause, rafPromise } from '../../../util/schedulers';
import { addActionHandler, getActions, getGlobal, setGlobal } from '../../index';
import { selectChat } from '../../selectors';

/**
 * In-memory queue of `tb1.kx` messages that arrived before the sender's
 * identity was pinned. Keyed by senderId; replayed by
 * `bridgeStoreContactPrekey` once the pinning message (tb1.pk or in-person
 * bundle scan) lands. Not persisted — kx is short-lived on the wire and a
 * re-publish is cheap. Cleared on `bridgeLock`.
 */
const pendingKxBySenderId = new Map<string, { chatId: string; wireText: string }>();

addActionHandler('bridgeSetDecryptedText', (global, actions, payload): ActionReturnType => {
  const { messageKey, text } = payload;
  // Skip writes if the cached entry already matches — spare a needless re-render.
  if (global.bridge.decryptedByKey[messageKey] === text) {
    return undefined;
  }
  return {
    ...global,
    bridge: {
      ...global.bridge,
      decryptedByKey: {
        ...global.bridge.decryptedByKey,
        [messageKey]: text,
      },
    },
  };
});

addActionHandler('bridgeClearDecryptedCache', (global): ActionReturnType => {
  return {
    ...global,
    bridge: {
      ...global.bridge,
      decryptedByKey: {},
    },
  };
});

addActionHandler('bridgeClearError', (global): ActionReturnType => {
  if (!global.bridge.lastError) return undefined;
  return {
    ...global,
    bridge: { ...global.bridge, lastError: undefined },
  };
});

// ---------------------------------------------------------------------------
// Vault lifecycle
// ---------------------------------------------------------------------------

addActionHandler('bridgeSetPassword', async (global, actions, payload): Promise<void> => {
  const { password } = payload;

  setGlobal(setBusy(global, true));
  // rAF fires at the start of the next frame (before paint); a following macrotask
  // yield lets the spinner actually paint before Argon2id blocks the main thread.
  await rafPromise();
  await pause(0);

  try {
    const vault = getTelebridgeVault();
    const persistedJson = await vault.initialize(password);

    global = getGlobal();
    setGlobal({
      ...global,
      bridge: {
        ...global.bridge,
        isInitialized: true,
        isUnlocked: true,
        persistedJson,
        chatKeyIds: {},
        decryptedByKey: {},
        isBusy: false,
        lastError: undefined,
      },
    });
  } catch (err) {
    setGlobal(setError(getGlobal(), err));
  }
});

addActionHandler('bridgeUnlock', async (global, actions, payload): Promise<void> => {
  const { password } = payload;

  setGlobal(setBusy(global, true));
  // rAF fires at the start of the next frame (before paint); a following macrotask
  // yield lets the spinner actually paint before Argon2id blocks the main thread.
  await rafPromise();
  await pause(0);

  try {
    const vault = getTelebridgeVault();
    await vault.unlock(password);

    // Rebuild chatKeyIds from persisted state — keys are already decrypted
    // in memory, but we only surface the set of chatIds, never the bytes.
    const persisted = vault.getPersistedState();
    const chatKeyIds: Record<string, true> = {};
    for (const chatId of Object.keys(persisted.chatKeys)) {
      chatKeyIds[chatId] = true;
    }

    // Rehydrate contact pinning + trust state from the vault. Without this,
    // verified contacts surface as "Not verified" until a fresh tb1.pk arrives.
    const contactKeyIds: Record<string, true> = {};
    const contactTofuStatusByContactId: Record<string, 'new' | 'changed' | 'unchanged' | 'verified'> = {};
    for (const [contactId, record] of Object.entries(persisted.contacts)) {
      contactKeyIds[contactId] = true;
      contactTofuStatusByContactId[contactId] = record.trustLevel === ContactTrustLevel.Verified
        ? 'verified'
        : record.trustLevel === ContactTrustLevel.Changed
          ? 'changed'
          : 'unchanged';
    }

    global = getGlobal();
    setGlobal({
      ...global,
      bridge: {
        ...global.bridge,
        isUnlocked: true,
        chatKeyIds,
        contactKeyIds,
        contactTofuStatusByContactId,
        decryptedByKey: {},
        isBusy: false,
        lastError: undefined,
      },
    });

    // Fire-and-forget: walk loaded messages and kick off decrypts so
    // components that already rendered during lock get their plaintext
    // without user scroll.
    backfillDecryptsForAllChats();
  } catch (err) {
    setGlobal(setError(getGlobal(), err));
  }
});

addActionHandler('bridgeLock', async (global): Promise<void> => {
  // Flip busy first so the button renders a spinner, then yield a frame before
  // the cache-clear triggers a re-render storm across chat list + messages.
  setGlobal(setBusy(global, true));
  await rafPromise();

  getTelebridgeVault().lock();

  // Queued kx pointers are only meaningful while unlocked — drop them so a
  // subsequent unlock starts from a clean slate.
  pendingKxBySenderId.clear();

  global = getGlobal();
  setGlobal({
    ...global,
    bridge: {
      ...global.bridge,
      isUnlocked: false,
      chatKeyIds: {},
      decryptedByKey: {},
      isBusy: false,
      lastError: undefined,
    },
  });
});

addActionHandler('bridgeChangePassword', async (global, actions, payload): Promise<void> => {
  const { currentPassword, newPassword } = payload;

  setGlobal(setBusy(global, true));
  // rAF fires at the start of the next frame (before paint); a following macrotask
  // yield lets the spinner actually paint before Argon2id blocks the main thread.
  await rafPromise();
  await pause(0);

  try {
    const vault = getTelebridgeVault();
    const persistedJson = await vault.changePassword(currentPassword, newPassword);

    global = getGlobal();
    setGlobal({
      ...global,
      bridge: {
        ...global.bridge,
        persistedJson,
        isBusy: false,
        lastError: undefined,
      },
    });
  } catch (err) {
    setGlobal(setError(getGlobal(), err));
  }
});

addActionHandler('bridgeStoreChatKey', async (global, actions, payload): Promise<void> => {
  const { chatId, key, keyId } = payload;

  try {
    const vault = getTelebridgeVault();
    const persistedJson = await vault.storeChatKey(chatId, key, keyId);

    global = getGlobal();
    setGlobal({
      ...global,
      bridge: {
        ...global.bridge,
        persistedJson,
        chatKeyIds: {
          ...global.bridge.chatKeyIds,
          [chatId]: true,
        },
      },
    });
  } catch (err) {
    setGlobal(setError(getGlobal(), err));
  }
});

// ---------------------------------------------------------------------------
// Layer-2 key exchange (prekey publication + handshake)
// ---------------------------------------------------------------------------

addActionHandler('bridgePublishPrekey', async (global, actions, payload): Promise<void> => {
  const { chatId } = payload;

  try {
    const vault = getTelebridgeVault();
    if (!vault.isInitialized() || vault.isLocked()) {
      throw new Error('Bridge is locked');
    }
    if (!isUserId(chatId)) {
      throw new Error('Prekey publication only supported for 1:1 chats');
    }
    if (global.bridge.prekeyPublishedChatIds[chatId]) {
      return;
    }

    const chat = selectChat(global, chatId);
    if (!chat) {
      throw new Error(`Chat ${chatId} not found`);
    }

    const wireText = await buildPrekeyWireMessage();

    getActions().sendMessage({ chat, text: wireText, tabId: getCurrentTabId() });

    global = getGlobal();
    setGlobal({
      ...global,
      bridge: {
        ...global.bridge,
        prekeyPublishedChatIds: {
          ...global.bridge.prekeyPublishedChatIds,
          [chatId]: true,
        },
      },
    });
  } catch (err) {
    setGlobal(setError(getGlobal(), err));
  }
});

addActionHandler('bridgeStoreContactPrekey', async (global, actions, payload): Promise<void> => {
  const { senderId, wireText } = payload;

  try {
    const vault = getTelebridgeVault();
    if (!vault.isInitialized() || vault.isLocked()) {
      throw new Error('Bridge is locked');
    }

    const decoded = decodePrekeyPublication(wireText);

    // Verify the self-signature before pinning. Proves the publisher holds
    // the private key for the declared Ed25519 public key; it does NOT bind
    // that key to the Telegram user id (that remains TOFU, per ARCHITECTURE
    // Layer 1). Drop silently on failure so a malformed/forged tb1.pk in a
    // high-volume receive cycle never banners the user or breaks the router.
    const signable = concatBytes(decoded.ed25519PublicKey, decoded.x25519PublicKey);
    try {
      verifyPrekeyBundle(signable, decoded.signature, decoded.ed25519PublicKey);
    } catch (verifyErr) {
      if (verifyErr instanceof InvalidSignatureError) {
        return;
      }
      throw verifyErr;
    }

    const result = vault.storeContactKey(senderId, decoded.ed25519PublicKey, decoded.x25519PublicKey);
    const persistedJson = vault.toPersistable();

    global = getGlobal();
    setGlobal({
      ...global,
      bridge: {
        ...global.bridge,
        persistedJson,
        contactKeyIds: {
          ...global.bridge.contactKeyIds,
          [senderId]: true,
        },
        contactTofuStatusByContactId: {
          ...global.bridge.contactTofuStatusByContactId,
          [senderId]: result.status,
        },
      },
    });

    // Replay any kx we parked while this sender was unpinned. Now that the
    // pk has landed and the identity is on record, the responder can run
    // the strict-equality gate and derive the chat key.
    const pending = pendingKxBySenderId.get(senderId);
    if (pending) {
      pendingKxBySenderId.delete(senderId);
      getActions().bridgeReceiveChatKey({
        chatId: pending.chatId,
        senderId,
        wireText: pending.wireText,
      });
    }
  } catch (err) {
    setGlobal(setError(getGlobal(), err));
  }
});

addActionHandler('bridgeStartKeyExchange', async (global, actions, payload): Promise<void> => {
  const { chatId } = payload;

  try {
    const vault = getTelebridgeVault();
    if (!vault.isInitialized() || vault.isLocked()) {
      throw new Error('Bridge is locked');
    }
    if (!isUserId(chatId)) {
      throw new Error('Key exchange only supported for 1:1 chats');
    }

    // 1:1 chats: peer user ID === chat ID
    const peerId = chatId;

    const chat = selectChat(global, chatId);
    if (!chat) {
      throw new Error(`Chat ${chatId} not found`);
    }

    // Step b — make sure our prekey is out there.
    if (!global.bridge.prekeyPublishedChatIds[chatId]) {
      const wireText = await buildPrekeyWireMessage();
      getActions().sendMessage({ chat, text: wireText, tabId: getCurrentTabId() });

      global = getGlobal();
      global = {
        ...global,
        bridge: {
          ...global.bridge,
          prekeyPublishedChatIds: {
            ...global.bridge.prekeyPublishedChatIds,
            [chatId]: true,
          },
        },
      };
      setGlobal(global);
    }

    // Step c — do we have the contact's prekey?
    const contact = vault.getContactKey(peerId);
    if (!contact) {
      global = getGlobal();
      setGlobal({
        ...global,
        bridge: {
          ...global.bridge,
          lastError: 'BridgeWaitingForContactPrekey',
          kxInProgressChatIds: {
            ...global.bridge.kxInProgressChatIds,
            [chatId]: true,
          },
        },
      });
      return;
    }

    // Step d — initiate handshake.
    const myIdentity = vault.getIdentityKeyPair();
    const contactX25519 = vault.getContactX25519PublicKey(peerId);
    if (!contactX25519) {
      throw new Error('Contact X25519 key not available');
    }

    const initiation = await initiateKeyExchange(myIdentity, contactX25519);

    getActions().sendMessage({ chat, text: initiation.wireMessage, tabId: getCurrentTabId() });

    const persistedJson = await vault.storeChatKey(chatId, initiation.chatKey, initiation.keyId);

    global = getGlobal();
    const nextKxInProgress = { ...global.bridge.kxInProgressChatIds };
    delete nextKxInProgress[chatId];
    setGlobal({
      ...global,
      bridge: {
        ...global.bridge,
        persistedJson,
        chatKeyIds: {
          ...global.bridge.chatKeyIds,
          [chatId]: true,
        },
        kxInProgressChatIds: nextKxInProgress,
      },
    });
  } catch (err) {
    setGlobal(setError(getGlobal(), err));
  }
});

addActionHandler('bridgeReceiveChatKey', async (global, actions, payload): Promise<void> => {
  const { chatId, senderId, wireText } = payload;

  try {
    const vault = getTelebridgeVault();
    if (!vault.isInitialized() || vault.isLocked()) {
      throw new Error('Bridge is locked');
    }

    const pinnedSenderIdKey = vault.getContactKey(senderId)?.publicKey;
    const myIdentity = vault.getIdentityKeyPair();
    const result = await respondToKeyExchange(
      wireText,
      myIdentity,
      vault,
      senderId,
      pinnedSenderIdKey,
    );

    if (result.status === 'needsPrekey') {
      // Park the kx until a tb1.pk (or in-person bundle) pins this sender's
      // identity. Newest wins: if a prior kx is still queued we replace it
      // (the sender just re-issued). Cleared on bridgeLock.
      pendingKxBySenderId.set(senderId, { chatId, wireText });
      return;
    }

    if (result.status === 'identityMismatch') {
      global = getGlobal();
      setGlobal({
        ...global,
        bridge: {
          ...global.bridge,
          lastError: 'BridgeIdentityMismatch',
        },
      });
      return;
    }

    const persistedJson = await vault.storeChatKey(chatId, result.chatKey, result.keyId);

    global = getGlobal();
    const nextKxInProgress = { ...global.bridge.kxInProgressChatIds };
    delete nextKxInProgress[chatId];
    setGlobal({
      ...global,
      bridge: {
        ...global.bridge,
        persistedJson,
        chatKeyIds: {
          ...global.bridge.chatKeyIds,
          [chatId]: true,
        },
        kxInProgressChatIds: nextKxInProgress,
        contactTofuStatusByContactId: {
          ...global.bridge.contactTofuStatusByContactId,
          [senderId]: result.tofuStatus,
        },
      },
    });
  } catch (err) {
    setGlobal(setError(getGlobal(), err));
  }
});

addActionHandler('bridgeRemoveChatKey', async (global, actions, payload): Promise<void> => {
  const { chatId } = payload;

  try {
    const vault = getTelebridgeVault();
    if (!vault.isInitialized() || vault.isLocked()) {
      throw new Error('Bridge is locked');
    }

    const persistedJson = await vault.removeChatKey(chatId);

    global = getGlobal();
    const nextChatKeyIds = { ...global.bridge.chatKeyIds };
    delete nextChatKeyIds[chatId];
    setGlobal({
      ...global,
      bridge: {
        ...global.bridge,
        persistedJson,
        chatKeyIds: nextChatKeyIds,
      },
    });
  } catch (err) {
    setGlobal(setError(getGlobal(), err));
  }
});

addActionHandler('bridgeVerifyContact', (global, actions, payload): ActionReturnType => {
  const { contactId } = payload;

  try {
    const vault = getTelebridgeVault();
    if (!vault.isInitialized() || vault.isLocked()) {
      throw new Error('Bridge is locked');
    }

    vault.verifyContact(contactId);
    const persistedJson = vault.toPersistable();

    return {
      ...global,
      bridge: {
        ...global.bridge,
        persistedJson,
        contactTofuStatusByContactId: {
          ...global.bridge.contactTofuStatusByContactId,
          [contactId]: 'verified',
        },
      },
    };
  } catch (err) {
    return setError(global, err);
  }
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a signed `tb1.pk` wire message advertising our identity public keys.
 * Caller must ensure the vault is unlocked.
 */
async function buildPrekeyWireMessage(): Promise<string> {
  const vault = getTelebridgeVault();
  const identity = vault.getIdentityKeyPair();

  const signable = concatBytes(identity.ed25519PublicKey, identity.x25519PublicKey);
  const signature = ed25519Sign(signable, identity.ed25519PrivateKey);

  return encodePrekeyPublication({
    ed25519PublicKey: identity.ed25519PublicKey,
    x25519PublicKey: identity.x25519PublicKey,
    signature,
  });
}

function setBusy(global: GlobalState, isBusy: boolean): GlobalState {
  return {
    ...global,
    bridge: { ...global.bridge, isBusy, lastError: undefined },
  };
}

function setError(global: GlobalState, err: unknown): GlobalState {
  const message = err instanceof Error ? err.message : 'Bridge operation failed';
  return {
    ...global,
    bridge: { ...global.bridge, isBusy: false, lastError: message },
  };
}

