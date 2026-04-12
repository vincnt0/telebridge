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

import type { ApiMessage } from '../api/types';

import { getActions, getGlobal } from '../global/index';
import { getMessageKey } from '../util/keys/messageKey';

import { decryptSymmetricMessage } from './decrypt';
import {
  decryptAfterDownload,
  getMediaChatKey,
  isEncryptedMedia,
} from './media';
import { getMediaChatId } from './mediaRegistry';
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

/**
 * Gate for one-shot consumers (copy-to-clipboard, share sheets) that snapshot
 * text at invocation time. Returns true when the message is plaintext or has
 * already been decrypted. Returns false on cache miss for a Telebridge
 * message, after kicking off a background decrypt — the caller should show a
 * retry notification and abort the copy so the user doesn't get ciphertext.
 */
export function ensureDecryptedBeforeCopy(message: ApiMessage): boolean {
  const rawText = message.content.text?.text;
  if (!rawText || !isTelebridgeMessage(rawText)) return true;
  const messageKey = getMessageKey(message);
  if (getCachedDecryptedText(messageKey) !== undefined) return true;
  ensureDecryptedText(message.chatId, messageKey, rawText);
  return false;
}

/**
 * Fire a background decrypt for every loaded Telebridge-encrypted message
 * whose chat currently has a usable key. Called from the unlock action so
 * messages that rendered during the locked period get replaced with
 * plaintext without the user needing to scroll past them.
 *
 * Cheap when nothing matches: `canDecryptNow` short-circuits on
 * non-tb1 text and locked-vault / missing-key cases; the per-message
 * `inflight` guard prevents duplicates if the render loop also fired.
 */
export function backfillDecryptsForAllChats(): void {
  const global = getGlobal();
  if (!global.bridge.isUnlocked) return;

  for (const [chatId, chatMessages] of Object.entries(global.messages.byChatId)) {
    for (const message of Object.values(chatMessages.byId)) {
      const text = message.content.text?.text;
      if (!text || !isTelebridgeMessage(text)) continue;
      ensureDecryptedText(chatId, getMessageKey(message), text);
    }
  }
}

// ---------------------------------------------------------------------------
// Media receive path
// ---------------------------------------------------------------------------

/**
 * Decrypt a downloaded media blob if the URL is registered to a Telebridge
 * chat and the vault currently holds a key for it. Returns the original
 * blob untouched when no registration is known, when the vault is locked,
 * or when the buffer doesn't carry the Telebridge file header.
 *
 * The main-thread mediaLoader calls this right after a successful remote
 * fetch (see `fetchFromCacheOrRemote` in src/util/mediaLoader.ts).
 */
export async function decryptMediaBlobIfRegistered(
  url: string,
  blob: Blob,
): Promise<Blob> {
  const chatId = getMediaChatId(url);
  if (!chatId) return blob;

  const chatKey = getMediaChatKey(chatId);
  if (!chatKey) return blob;

  // Fast gate: peek at the prefix to spare the full arrayBuffer() copy
  // for plaintext payloads in mixed chats. `isEncryptedMedia` inspects the
  // leading version byte plus the minimum-size check.
  const prefix = new Uint8Array(await blob.slice(0, 64).arrayBuffer());
  if (!isEncryptedMedia(prefix)) {
    return blob;
  }

  const cipherBuffer = new Uint8Array(await blob.arrayBuffer());
  const plaintext = await decryptAfterDownload(cipherBuffer, chatKey);

  // decryptAfterDownload returns the original buffer on decrypt failure.
  // Wrap in a new blob preserving the original mime type.
  // Slice into a fresh ArrayBuffer so the Blob doesn't reference the
  // Uint8Array's backing store (TS DOM types reject SharedArrayBuffer views).
  const bodyCopy = new ArrayBuffer(plaintext.byteLength);
  new Uint8Array(bodyCopy).set(plaintext);
  return new Blob([bodyCopy], { type: blob.type });
}
