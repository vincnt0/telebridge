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

  // Telebridge: rehydrate the singleton vault from the persisted blob BEFORE
  // setGlobal so the reactive bridge slice agrees with runtime vault state on
  // the very first render. Two slices must stay in sync:
  //   - `isInitialized`: the cached flag can get out of step with the vault
  //     (e.g. blob was cleared from disk while the cached flag persisted, or
  //     deserialize throws on a corrupt blob). If the vault can't load, flip
  //     `isInitialized` back to false so the UI shows Setup, not Unlock.
  //   - `hasPassword`: used by the unlock dialog's auto-unlock path. The cached
  //     value can be stale (legacy blobs predate the flag); source of truth is
  //     the vault after load().
  const vault = getTelebridgeVault();
  if (global.bridge.persistedJson) {
    try {
      vault.load(global.bridge.persistedJson);
    } catch {
      // Corrupt blob — leave vault uninitialized and drop the blob from global
      // so the cache reducer doesn't re-persist it next cycle.
    }
  }
  global.bridge = {
    ...global.bridge,
    isInitialized: vault.isInitialized(),
    hasPassword: vault.isInitialized() ? vault.hasPassword() : false,
    // Drop the blob on load failure so a corrupt/stale cache entry doesn't
    // re-persist on the next cache-save cycle. Fresh setup will repopulate it.
    persistedJson: vault.isInitialized() ? global.bridge.persistedJson : undefined,
  };

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
}
