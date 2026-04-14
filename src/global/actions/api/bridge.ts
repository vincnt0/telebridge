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

import {
  concatBytes,
  ed25519Sign,
  encodeUtf8,
  encryptForRecipient,
  fromBase64,
  fromHex,
} from '../../../telebridge/crypto';
import {
  decodeIdentityBundle,
  InvalidBundleError,
  InvalidSignatureError as InvalidBundleSignatureError,
  verifyIdentityBundle,
} from '../../../telebridge/inPerson/bundle';
import { initiateKeyExchange, respondToKeyExchange } from '../../../telebridge/keyExchange';
import { ContactTrustLevel } from '../../../telebridge/state/types';
import { decodePrekeyPublication } from '../../../telebridge/protocol/decode';
import { encodePrekeyPublication, encodeSecuredMessage } from '../../../telebridge/protocol/encode';
import { InvalidSignatureError, verifyPrekeyBundle } from '../../../telebridge/protocol/verify';
import { backfillDecryptsForAllChats, resetAsymmetricReceive } from '../../../telebridge/receive';
import { getTelebridgeVault } from '../../../telebridge/send';
import { MAIN_THREAD_ID } from '../../../api/types/messages';
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

  // Queued kx pointers + asymmetric-triage cache are only meaningful while
  // unlocked — drop them so a subsequent unlock starts from a clean slate.
  pendingKxBySenderId.clear();
  resetAsymmetricReceive();

  global = getGlobal();
  setGlobal({
    ...global,
    bridge: {
      ...global.bridge,
      isUnlocked: false,
      chatKeyIds: {},
      decryptedByKey: {},
      // Layer-4 tracking maps reference messages whose plaintext lived in
      // `decryptedByKey`; drop them together so the render side doesn't apply
      // `is-bridge-secured` styling to a bubble that can no longer be decoded.
      asymmetricDecryptedMessageIds: {},
      filteredAsymmetricMessageIds: {},
      isBusy: false,
      lastError: undefined,
      bridgeMismatchPending: undefined,
      bridgeLastExport: undefined,
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

    getActions().sendMessage({
      messageList: { chatId, threadId: MAIN_THREAD_ID, type: 'thread' },
      text: wireText,
      tabId: getCurrentTabId(),
    });

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

    // Step b — (re)publish our prekey. Cheap + idempotent on the receiver
    // side; re-publishing on every Start-click lets the user recover from a
    // prior send that silently failed (offline / flood-wait / missing
    // messageList payload).
    const wireText = await buildPrekeyWireMessage();
    getActions().sendMessage({
      messageList: { chatId, threadId: MAIN_THREAD_ID, type: 'thread' },
      text: wireText,
      tabId: getCurrentTabId(),
    });

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

    getActions().sendMessage({
      messageList: { chatId, threadId: MAIN_THREAD_ID, type: 'thread' },
      text: initiation.wireMessage,
      tabId: getCurrentTabId(),
    });

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

/**
 * Debug-only: install a manually-entered 32-byte key as the active chat key
 * for `chatId`. Gated on `global.bridge.isDebugMode`. Exists to sidestep
 * Layer-2 KX when testing two-account scenarios on a single device (pin the
 * same symmetric key on both accounts so `tb1.s` round-trips without a real
 * handshake). Refuses to overwrite an existing chat key — the user must
 * remove the KX-derived key first. Stamps `derivedFromKeyId = '__manual__'`
 * so downstream code can tell manual keys apart from KX-derived ones.
 */
addActionHandler('bridgeSetManualChatKey', async (global, actions, payload): Promise<void> => {
  const { chatId, keyText, tabId = getCurrentTabId() } = payload;

  if (!global.bridge.isDebugMode) {
    setGlobal({
      ...global,
      bridge: { ...global.bridge, lastError: 'BridgeKeysTabDevToolsErrorUnavailable' },
    });
    return;
  }

  if (!global.bridge.isUnlocked) {
    setGlobal({
      ...global,
      bridge: { ...global.bridge, lastError: 'BridgeKeysTabDevToolsErrorUnavailable' },
    });
    return;
  }

  if (!global.bridge.contactKeyIds[chatId]) {
    setGlobal({
      ...global,
      bridge: { ...global.bridge, lastError: 'BridgeKeysTabDevToolsErrorUnavailable' },
    });
    return;
  }

  if (global.bridge.chatKeyIds[chatId]) {
    setGlobal({
      ...global,
      bridge: { ...global.bridge, lastError: 'BridgeKeysTabDevToolsErrorExists' },
    });
    return;
  }

  // Parse the textual key. Hex first (64 chars, strict regex), base64 second
  // (decode + length === 32). Anything else is rejected — no URL-safe base64,
  // no whitespace tolerance, no heuristics. Keeps parsing boring.
  const keyBytes = parseManualChatKey(keyText);
  if (!keyBytes) {
    setGlobal({
      ...global,
      bridge: { ...global.bridge, lastError: 'BridgeKeysTabDevToolsErrorInvalid' },
    });
    return;
  }

  try {
    const vault = getTelebridgeVault();
    const persistedJson = await vault.storeChatKey(chatId, keyBytes, undefined, '__manual__');

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
        lastError: undefined,
      },
    });

    actions.showNotification({ message: { key: 'BridgeKeysTabDevToolsKeySet' }, tabId });
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
// In-person scan + contact-key archive management (§6.1.5)
// ---------------------------------------------------------------------------

addActionHandler('bridgeApplyInPersonScan', async (global, actions, payload): Promise<void> => {
  const { peerUserId, bundleText } = payload;

  try {
    const vault = getTelebridgeVault();
    if (!vault.isInitialized() || vault.isLocked()) {
      throw new Error('Bridge is locked');
    }

    let decoded;
    try {
      decoded = decodeIdentityBundle(bundleText);
      verifyIdentityBundle(decoded);
    } catch (err) {
      if (err instanceof InvalidBundleError || err instanceof InvalidBundleSignatureError) {
        global = getGlobal();
        setGlobal({
          ...global,
          bridge: { ...global.bridge, lastError: 'BridgeInvalidScanBundle' },
        });
        return;
      }
      throw err;
    }

    const result = vault.storeContactKeyFromScan(
      peerUserId,
      decoded.ed25519PublicKey,
      decoded.x25519PublicKey,
      decoded.signature,
    );
    const persistedJson = vault.toPersistable();

    global = getGlobal();
    const nextContactTofu = { ...global.bridge.contactTofuStatusByContactId };
    if (result.kind === 'fresh' || result.kind === 'matchedActive') {
      nextContactTofu[peerUserId] = 'verified';
    }

    setGlobal({
      ...global,
      bridge: {
        ...global.bridge,
        persistedJson,
        contactKeyIds: {
          ...global.bridge.contactKeyIds,
          [peerUserId]: true,
        },
        contactTofuStatusByContactId: nextContactTofu,
        bridgeMismatchPending: result.needsUserConfirmation
          ? { peerUserId, scannedKeyId: result.keyId, kind: result.kind }
          : global.bridge.bridgeMismatchPending,
        lastError: undefined,
      },
    });
  } catch (err) {
    setGlobal(setError(getGlobal(), err));
  }
});

addActionHandler('bridgeSetActiveContactKey', (global, actions, payload): ActionReturnType => {
  const { peerUserId, keyId } = payload;
  try {
    const vault = getTelebridgeVault();
    if (!vault.isInitialized() || vault.isLocked()) {
      throw new Error('Bridge is locked');
    }

    vault.setActiveKey(peerUserId, keyId);
    const persistedJson = vault.toPersistable();
    const record = vault.getContactKey(peerUserId);
    const tofuStatus = record?.trustLevel === ContactTrustLevel.Verified
      ? 'verified'
      : record?.trustLevel === ContactTrustLevel.Changed
        ? 'changed'
        : 'unchanged';

    return {
      ...global,
      bridge: {
        ...global.bridge,
        persistedJson,
        contactTofuStatusByContactId: {
          ...global.bridge.contactTofuStatusByContactId,
          [peerUserId]: tofuStatus,
        },
      },
    };
  } catch (err) {
    return setError(global, err);
  }
});

addActionHandler('bridgeArchiveContactKey', (global, actions, payload): ActionReturnType => {
  const { peerUserId, keyId } = payload;
  try {
    const vault = getTelebridgeVault();
    if (!vault.isInitialized() || vault.isLocked()) {
      throw new Error('Bridge is locked');
    }
    vault.archiveKey(peerUserId, keyId);
    const persistedJson = vault.toPersistable();
    return {
      ...global,
      bridge: { ...global.bridge, persistedJson },
    };
  } catch (err) {
    return setError(global, err);
  }
});

addActionHandler('bridgeDeleteContactKey', (global, actions, payload): ActionReturnType => {
  const { peerUserId, keyId } = payload;
  try {
    const vault = getTelebridgeVault();
    if (!vault.isInitialized() || vault.isLocked()) {
      throw new Error('Bridge is locked');
    }
    const result = vault.deleteKey(peerUserId, keyId);
    const persistedJson = vault.toPersistable();

    const nextContactKeyIds = { ...global.bridge.contactKeyIds };
    const nextTofu = { ...global.bridge.contactTofuStatusByContactId };
    if (result.contactRemoved) {
      delete nextContactKeyIds[peerUserId];
      delete nextTofu[peerUserId];
    } else {
      const record = getTelebridgeVault().getContactKey(peerUserId);
      if (record) {
        nextTofu[peerUserId] = record.trustLevel === ContactTrustLevel.Verified
          ? 'verified'
          : record.trustLevel === ContactTrustLevel.Changed
            ? 'changed'
            : 'unchanged';
      }
    }

    // Cascade: any chat session that was negotiated against a dropped key
    // must have its runtime pointers cleared so the UI doesn't keep showing
    // an encrypted badge for a chat whose key is gone.
    const nextChatKeyIds = { ...global.bridge.chatKeyIds };
    const nextPrekeyPublished = { ...global.bridge.prekeyPublishedChatIds };
    for (const chatId of result.droppedChatIds) {
      delete nextChatKeyIds[chatId];
      delete nextPrekeyPublished[chatId];
    }

    return {
      ...global,
      bridge: {
        ...global.bridge,
        persistedJson,
        contactKeyIds: nextContactKeyIds,
        contactTofuStatusByContactId: nextTofu,
        chatKeyIds: nextChatKeyIds,
        prekeyPublishedChatIds: nextPrekeyPublished,
      },
    };
  } catch (err) {
    return setError(global, err);
  }
});

addActionHandler('bridgeExportContactKey', (global, actions, payload): ActionReturnType => {
  const { peerUserId, keyId } = payload;
  try {
    const vault = getTelebridgeVault();
    if (!vault.isInitialized() || vault.isLocked()) {
      throw new Error('Bridge is locked');
    }
    const { json, qrText } = vault.exportKey(peerUserId, keyId);
    return {
      ...global,
      bridge: {
        ...global.bridge,
        bridgeLastExport: { peerUserId, keyId, json, qrText },
      },
    };
  } catch (err) {
    return setError(global, err);
  }
});

addActionHandler('bridgeImportContactKey', async (global, actions, payload): Promise<void> => {
  const { peerUserId, payload: blob } = payload;
  try {
    const vault = getTelebridgeVault();
    if (!vault.isInitialized() || vault.isLocked()) {
      throw new Error('Bridge is locked');
    }
    const result = vault.importKey(peerUserId, blob);
    const persistedJson = vault.toPersistable();

    global = getGlobal();
    setGlobal({
      ...global,
      bridge: {
        ...global.bridge,
        persistedJson,
        lastError: result.kind === 'duplicate' ? 'BridgeImportDuplicate' : undefined,
      },
    });
  } catch (err) {
    const message = err instanceof Error && err.message === 'Import signature invalid'
      ? 'BridgeImportInvalid'
      : err instanceof Error ? err.message : 'Bridge operation failed';
    global = getGlobal();
    setGlobal({
      ...global,
      bridge: { ...global.bridge, isBusy: false, lastError: message },
    });
  }
});

addActionHandler('bridgeRevokeContactKey', async (global, actions, payload): Promise<void> => {
  const { peerUserId } = payload;
  try {
    const vault = getTelebridgeVault();
    if (!vault.isInitialized() || vault.isLocked()) {
      throw new Error('Bridge is locked');
    }
    const { droppedChatIds } = vault.revokeContactKey(peerUserId);
    const persistedJson = vault.toPersistable();

    global = getGlobal();
    const nextChatKeyIds = { ...global.bridge.chatKeyIds };
    const nextPrekeyPublished = { ...global.bridge.prekeyPublishedChatIds };
    for (const chatId of droppedChatIds) {
      delete nextChatKeyIds[chatId];
      delete nextPrekeyPublished[chatId];
    }
    const nextContactKeyIds = { ...global.bridge.contactKeyIds };
    delete nextContactKeyIds[peerUserId];
    const nextTofu = { ...global.bridge.contactTofuStatusByContactId };
    delete nextTofu[peerUserId];

    setGlobal({
      ...global,
      bridge: {
        ...global.bridge,
        persistedJson,
        chatKeyIds: nextChatKeyIds,
        prekeyPublishedChatIds: nextPrekeyPublished,
        contactKeyIds: nextContactKeyIds,
        contactTofuStatusByContactId: nextTofu,
      },
    });
  } catch (err) {
    setGlobal(setError(getGlobal(), err));
  }
});

addActionHandler('bridgeClearMismatchPending', (global): ActionReturnType => {
  if (!global.bridge.bridgeMismatchPending) return undefined;
  return {
    ...global,
    bridge: { ...global.bridge, bridgeMismatchPending: undefined },
  };
});

addActionHandler('bridgeClearLastExport', (global): ActionReturnType => {
  if (!global.bridge.bridgeLastExport) return undefined;
  return {
    ...global,
    bridge: { ...global.bridge, bridgeLastExport: undefined },
  };
});

// ---------------------------------------------------------------------------
// Layer 4 — Send Secured (per-message asymmetric fan-out)
// ---------------------------------------------------------------------------

addActionHandler('bridgeSendSecured', async (global, actions, payload): Promise<void> => {
  const { chatId, text, tabId = getCurrentTabId() } = payload;

  try {
    const vault = getTelebridgeVault();
    if (!vault.isInitialized() || vault.isLocked()) {
      throw new Error('Bridge is locked');
    }
    if (!isUserId(chatId)) {
      // Group Secured Messaging is deferred per ARCHITECTURE.md Layer 4.
      // Composer gates this out pre-dispatch, so this is belt-and-braces;
      // surfaces a distinct error code for parity with the no-peer-key path.
      global = getGlobal();
      setGlobal({
        ...global,
        bridge: { ...global.bridge, lastError: 'BridgeSendSecuredNotDm' },
      });
      return;
    }

    // 1:1 chats: recipient user id === chat id.
    const recipientId = chatId;
    const recipientContact = vault.getContactKey(recipientId);
    if (!recipientContact) {
      global = getGlobal();
      setGlobal({
        ...global,
        bridge: { ...global.bridge, lastError: 'BridgeSendSecuredNoPeerKey' },
      });
      return;
    }

    // Success path from here on — clear any stale error from a prior failed
    // dispatch so the composer doesn't re-emit it after the next mount.
    if (global.bridge.lastError) {
      global = getGlobal();
      setGlobal({
        ...global,
        bridge: { ...global.bridge, lastError: undefined },
      });
    }

    const recipientX25519 = fromBase64(recipientContact.x25519PublicKey);
    const myIdentity = vault.getIdentityKeyPair();
    const plaintextBytes = encodeUtf8(text);

    // Envelope A: encrypt-to-recipient. Envelope B: encrypt-to-self so our
    // other devices can read our own outgoing copy (§ARCHITECTURE Layer 4).
    // Each call burns its own ephemeral X25519 keypair; no reuse.
    const envelopeToRecipient = await encryptForRecipient(
      plaintextBytes,
      recipientX25519,
      myIdentity.ed25519PrivateKey,
    );
    const envelopeToSelf = await encryptForRecipient(
      plaintextBytes,
      myIdentity.x25519PublicKey,
      myIdentity.ed25519PrivateKey,
    );

    const wireToRecipient = encodeSecuredMessage(envelopeToRecipient);
    const wireToSelf = encodeSecuredMessage(envelopeToSelf);

    // Both sends use the canonical `messageList` shape — the 72763106b
    // silent-drop regression was exactly a missing messageList field.
    const sendActions = getActions();
    sendActions.sendMessage({
      messageList: { chatId, threadId: MAIN_THREAD_ID, type: 'thread' },
      text: wireToRecipient,
      tabId,
    });
    sendActions.sendMessage({
      messageList: { chatId, threadId: MAIN_THREAD_ID, type: 'thread' },
      text: wireToSelf,
      tabId,
    });
  } catch (err) {
    setGlobal(setError(getGlobal(), err));
  }
});

addActionHandler('bridgeMarkAsymmetricFiltered', (global, actions, payload): ActionReturnType => {
  const { messageKey } = payload;
  if (global.bridge.filteredAsymmetricMessageIds[messageKey]) return undefined;
  return {
    ...global,
    bridge: {
      ...global.bridge,
      filteredAsymmetricMessageIds: {
        ...global.bridge.filteredAsymmetricMessageIds,
        [messageKey]: true,
      },
    },
  };
});

addActionHandler('bridgeMarkAsymmetricDecrypted', (global, actions, payload): ActionReturnType => {
  const { messageKey } = payload;
  if (global.bridge.asymmetricDecryptedMessageIds[messageKey]) return undefined;
  return {
    ...global,
    bridge: {
      ...global.bridge,
      asymmetricDecryptedMessageIds: {
        ...global.bridge.asymmetricDecryptedMessageIds,
        [messageKey]: true,
      },
    },
  };
});

addActionHandler('bridgeToggleSecuredMode', (global, actions, payload): ActionReturnType => {
  const { chatId } = payload;
  // Belt-and-braces: composer should hide the toggle when the vault is locked
  // or no peer key is pinned, but ignore stray dispatches anyway so the UI
  // can't put state into a "secured-on without key" state.
  if (!global.bridge.isUnlocked) return undefined;
  if (!global.bridge.contactKeyIds[chatId]) {
    return {
      ...global,
      bridge: { ...global.bridge, lastError: 'BridgeSendSecuredNoPeerKey' },
    };
  }

  if (global.bridge.securedModeByChatId[chatId]) {
    const { [chatId]: _removed, ...rest } = global.bridge.securedModeByChatId;
    return {
      ...global,
      bridge: { ...global.bridge, securedModeByChatId: rest },
    };
  }

  return {
    ...global,
    bridge: {
      ...global.bridge,
      securedModeByChatId: {
        ...global.bridge.securedModeByChatId,
        [chatId]: true,
      },
    },
  };
});

addActionHandler('bridgeToggleDebugMode', (global): ActionReturnType => {
  return {
    ...global,
    bridge: { ...global.bridge, isDebugMode: !global.bridge.isDebugMode },
  };
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

/**
 * Parse a debug-only manual chat key. Accepts strict 64-char hex first, then
 * standard base64 (no URL-safe variant, no whitespace tolerance). Returns the
 * decoded bytes iff they decode to exactly 32 bytes; otherwise `undefined`.
 */
function parseManualChatKey(keyText: string): Uint8Array | undefined {
  if (/^[0-9a-fA-F]{64}$/.test(keyText)) {
    try {
      const bytes = fromHex(keyText);
      if (bytes.length === 32) return bytes;
    } catch {
      // Fall through to base64
    }
  }

  try {
    const bytes = fromBase64(keyText);
    if (bytes.length === 32) return bytes;
  } catch {
    // Invalid base64 — fall through
  }

  return undefined;
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

