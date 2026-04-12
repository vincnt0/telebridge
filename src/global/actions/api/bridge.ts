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

import { backfillDecryptsForAllChats } from '../../../telebridge/receive';
import { getTelebridgeVault } from '../../../telebridge/send';
import { rafPromise } from '../../../util/schedulers';
import { addActionHandler, getGlobal, setGlobal } from '../../index';

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
  // Yield a frame so the busy spinner paints before Argon2id blocks the main thread.
  await rafPromise();

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
  // Yield a frame so the busy spinner paints before Argon2id blocks the main thread.
  await rafPromise();

  try {
    const vault = getTelebridgeVault();
    await vault.unlock(password);

    // Rebuild chatKeyIds from persisted state — keys are already decrypted
    // in memory, but we only surface the set of chatIds, never the bytes.
    const chatKeyIds: Record<string, true> = {};
    for (const chatId of Object.keys(vault.getPersistedState().chatKeys)) {
      chatKeyIds[chatId] = true;
    }

    global = getGlobal();
    setGlobal({
      ...global,
      bridge: {
        ...global.bridge,
        isUnlocked: true,
        chatKeyIds,
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
  // Yield a frame so the busy spinner paints before Argon2id blocks the main thread.
  await rafPromise();

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
// Helpers
// ---------------------------------------------------------------------------

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

