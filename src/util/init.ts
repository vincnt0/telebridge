import type { GlobalState } from '../global/types';

import { IS_MOCKED_CLIENT } from '../config';
import { loadCache, loadCachedSharedState } from '../global/cache';
import { getAllMessageMediaHashes, getMessageStatefulContent } from '../global/helpers';
import {
  getGlobal, setGlobal,
} from '../global/index';
import { INITIAL_GLOBAL_STATE } from '../global/initialState';
import { updatePasscodeSettings } from '../global/reducers';
import { registerMediaChats } from '../telebridge/mediaRegistry';
import { getTelebridgeVault } from '../telebridge/send';
import { cloneDeep } from './iteratees';
import { clearStoredSession } from './sessions';

export async function initGlobal(force: boolean = false, prevGlobal?: GlobalState) {
  prevGlobal = prevGlobal || getGlobal();
  if (!force && 'byTabId' in prevGlobal) {
    return;
  }

  const initial = cloneDeep(INITIAL_GLOBAL_STATE);
  const cache = await loadCache(initial);
  let global = cache || initial;
  if (IS_MOCKED_CLIENT) global.auth.state = 'authorizationStateReady';

  const { hasPasscode, isScreenLocked } = global.passcode;
  if (hasPasscode && !isScreenLocked) {
    global = updatePasscodeSettings(global, {
      isScreenLocked: true,
    });

    clearStoredSession();
  }

  if (force) {
    global.byTabId = prevGlobal.byTabId;
  }

  if (!cache) { // Try loading shared state separately
    const storedSharedState = await loadCachedSharedState();
    if (storedSharedState) {
      global.sharedState = storedSharedState;
    }
  }

  setGlobal(global);

  // Telebridge: rebuild the media-hash → chatId registry from cache-restored
  // messages. The registry is runtime-only and was empty until this sweep.
  Object.entries(global.messages.byChatId).forEach(([chatId, { byId }]) => {
    Object.values(byId).forEach((message) => {
      const statefulContent = getMessageStatefulContent(global, message);
      const hashes = getAllMessageMediaHashes(message, statefulContent);
      if (hashes.length) registerMediaChats(hashes, chatId);
    });
  });

  // Telebridge: rehydrate the singleton vault from the persisted blob so
  // `isInitialized` on the global slice and the vault agree at boot time.
  // The vault stays locked — unlock() runs from the UI once the user types
  // their password. A corrupt blob is treated as no vault (state remains
  // `isInitialized: false` from the cached slice, which should match).
  if (global.bridge.persistedJson) {
    try {
      getTelebridgeVault().load(global.bridge.persistedJson);
    } catch {
      // Corrupt blob — leave vault uninitialized, the user will have to
      // re-run setup. We deliberately don't surface this: it's a local
      // disk-corruption case that shouldn't happen in normal operation.
    }
  }
}
