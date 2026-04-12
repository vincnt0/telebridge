/**
 * Telebridge v2 — Receive-Side Plaintext Queue
 *
 * Bridges the asynchronous decrypt pipeline to Web A's synchronous render
 * path. Callers (renderMessageText, message-summary selectors, etc.) probe
 * `getCachedDecryptedText(messageKey)` on every render and fire
 * `ensureDecryptedText(...)` as a fire-and-forget side effect when the
 * cache misses. The decrypt promise lands a plaintext entry into
 * `global.bridge.decryptedByKey` via the `bridgeSetDecryptedText` action,
 * which re-renders any component subscribed to that slice.
 *
 * Inflight dedup lives in this module (not global state) because it's
 * truly transient — on reload everything resets. Storing promise handles
 * in global state would not round-trip through the cache anyway.
 *
 * Runtime-only: decrypted plaintext is never persisted. `reduceBridge()`
 * in cache.ts strips `decryptedByKey` at serialization time.
 */

import { getActions, getGlobal } from '../global/index';

import { decryptSymmetricMessage } from './decrypt';
import { isTelebridgeMessage } from './protocol';
import { getTelebridgeVault } from './send';

/** Keys currently in-flight so we don't stack duplicate decrypts per render. */
const inflight = new Set<string>();

/**
 * Synchronous probe for the render path. Returns the plaintext if the
 * background decrypt has already resolved, otherwise undefined.
 */
export function getCachedDecryptedText(messageKey: string): string | undefined {
  return getGlobal().bridge.decryptedByKey[messageKey];
}

/**
 * Fast gate for the render path. Returns true if the text both looks like
 * a Telebridge wire-format message AND the vault has a usable key for the
 * chat — i.e. decryption has any chance of succeeding right now.
 */
export function canDecryptNow(chatId: string, text: string): boolean {
  if (!isTelebridgeMessage(text)) return false;
  const vault = getTelebridgeVault();
  if (!vault.isInitialized() || vault.isLocked()) return false;
  return vault.getChatKey(chatId) !== undefined;
}

/**
 * Fire-and-forget: kick off a background decrypt for (messageKey, text)
 * if none is already running and no plaintext is cached. On success the
 * plaintext is pushed into `global.bridge.decryptedByKey` via action,
 * which re-renders subscribing components.
 *
 * Safe to call on every render — deduped by `inflight` + cache check.
 */
export function ensureDecryptedText(
  chatId: string,
  messageKey: string,
  encryptedText: string,
): void {
  if (inflight.has(messageKey)) return;
  if (getCachedDecryptedText(messageKey) !== undefined) return;
  if (!canDecryptNow(chatId, encryptedText)) return;

  const vault = getTelebridgeVault();
  const chatKey = vault.getChatKey(chatId);
  if (!chatKey) return;

  inflight.add(messageKey);

  void (async () => {
    try {
      const result = await decryptSymmetricMessage(encryptedText, chatKey);
      if (result.status === 'success' || result.status === 'invalidSignature') {
        if (result.text !== undefined) {
          getActions().bridgeSetDecryptedText({ messageKey, text: result.text });
        }
      }
      // wrongKey / malformed: leave the ciphertext visible — the UI can
      // flag these separately once the lock-state indicator lands.
    } finally {
      inflight.delete(messageKey);
    }
  })();
}
