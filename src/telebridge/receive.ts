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

import { decryptEnvelopeToText } from './crypto/asymmetric';
import { fromBase64 } from './crypto/utils';
import { decryptSymmetricMessage } from './decrypt';
import {
  decryptAfterDownload,
  getMediaChatKey,
  isEncryptedMedia,
} from './media';
import { getMediaChatId } from './mediaRegistry';
import { decodeSecuredMessage } from './protocol/decode';
import { isTelebridgeMachineMessage, isTelebridgeMessage } from './protocol';
import { getTelebridgeVault } from './send';

/** Keys currently in-flight so we don't stack duplicate decrypts per render. */
const inflight = new Set<string>();

/** Message keys whose `tb1.pk.…` wire payload has already been dispatched. */
const prekeyProcessed = new Set<string>(); // messageKey
/** Message keys whose `tb1.kx.…` wire payload has already been dispatched. */
const kxProcessed = new Set<string>();     // messageKey
/** Message keys whose `tb1.a.…` envelope we've already triaged. */
const asymmetricProcessed = new Set<string>(); // messageKey

/**
 * Drop the per-session triage caches. Called on `bridgeLock` so a subsequent
 * unlock starts from a clean slate — envelopes whose triage outcome depended
 * on (now-dropped) vault state get a chance to re-run after the user unlocks
 * or pins a new contact key.
 */
export function resetAsymmetricReceive(): void {
  asymmetricProcessed.clear();
}

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
  senderId?: string,
): void {
  // Machine-msg wire formats (prekey publish, key exchange) are handled by
  // their own dispatchers — they're not `tb1.s` ciphertext and would only
  // fail the symmetric decrypt path.
  if (encryptedText.startsWith('tb1.pk.') || encryptedText.startsWith('tb1.kx.')) return;
  if (encryptedText.startsWith('tb1.a.')) {
    ensureAsymmetricProcessed(chatId, messageKey, encryptedText, senderId);
    return;
  }
  if (inflight.has(messageKey)) return;
  if (getCachedDecryptedText(messageKey) !== undefined) return;
  if (!canDecryptNow(chatId, encryptedText)) return;

  const vault = getTelebridgeVault();
  const chatKey = vault.getChatKey(chatId);
  if (!chatKey) return;

  // Per-message sig is defence-in-depth on top of GCM+TOFU'd chat key; if the
  // contact prekey hasn't arrived yet we decrypt without verify rather than reject.
  const senderPublicKey = senderId ? vault.getContactKey(senderId)?.publicKey : undefined;

  inflight.add(messageKey);

  void (async () => {
    try {
      const result = await decryptSymmetricMessage(encryptedText, chatKey, senderPublicKey);
      if (result.status === 'success') {
        // Stamp the contact key's `lastUsed` when we actually verified the
        // sender signature against a known key — the only path where the
        // bump reflects real traffic. Unsigned/unknown-sender decrypts
        // (senderPublicKey === undefined, isSignatureVerified undefined)
        // intentionally don't bump: there's no proof a specific identity
        // sent this message. The bump is in-memory; next vault save flushes.
        if (senderId && result.isSignatureVerified) {
          vault.bumpContactKeyLastUsed(senderId);
        }
        if (result.text !== undefined) {
          getActions().bridgeSetDecryptedText({ messageKey, text: result.text });
        }
      }
      // invalidSignature: known contact key failed to verify — someone with
      // the chat key forged a message. Don't surface the plaintext; leave
      // the ciphertext visible so MessageMeta's `isTelebridgeFailed` warning
      // slot renders (it fires on any tb1 payload without decryptedByKey).
      // wrongKey / malformed: leave the ciphertext visible — the UI can
      // flag these separately once the lock-state indicator lands.
    } finally {
      inflight.delete(messageKey);
    }
  })();
}

/**
 * Gate for one-shot consumers (copy-to-clipboard, share sheets) that snapshot
 * text at invocation time. Returns 'ok' when the message is plaintext or
 * has already been decrypted. Returns 'handshake' for tb1.pk / tb1.kx
 * machine messages — they never decrypt, so emitting their wire bytes to
 * the clipboard would leak handshake base64. Returns 'coldCiphertext' on
 * cache miss for a regular tb1 payload, after kicking off a background
 * decrypt; the caller should abort and show a retry notification.
 */
export type EnsureDecryptedResult = 'ok' | 'handshake' | 'coldCiphertext';

export function ensureDecryptedBeforeCopy(message: ApiMessage): EnsureDecryptedResult {
  const rawText = message.content.text?.text;
  if (!rawText || !isTelebridgeMessage(rawText)) return 'ok';
  // Handshake payloads (tb1.pk / tb1.kx) have no plaintext form — blocking
  // copy here prevents the user ending up with raw base64 handshake bytes.
  if (isTelebridgeMachineMessage(rawText)) return 'handshake';
  const messageKey = getMessageKey(message);
  if (getCachedDecryptedText(messageKey) !== undefined) return 'ok';
  ensureDecryptedText(message.chatId, messageKey, rawText, message.senderId);
  return 'coldCiphertext';
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
      // Prekey first so contact keys land before any kx in the same pass can
      // consume them; kx next so chat keys exist before decrypt attempts.
      ensurePrekeyProcessed(message);
      ensureKxProcessed(message);
      // `ensureDecryptedText` internally routes tb1.a envelopes into
      // `ensureAsymmetricProcessed`, so a single entry point covers both.
      ensureDecryptedText(chatId, getMessageKey(message), text, message.senderId);
    }
  }
}

/**
 * Fire-and-forget dispatcher for inbound `tb1.pk.…` contact-prekey publishes.
 * Safe to call on every render — deduped by `prekeyProcessed` keyed on
 * messageKey. Own outgoing messages are ignored. If the vault is locked we
 * bail without marking the key processed so the backfill on unlock can retry.
 */
export function ensurePrekeyProcessed(message: ApiMessage): void {
  const text = message.content.text?.text;
  if (!text || !text.startsWith('tb1.pk.')) return;
  if (!message.senderId) return;

  const global = getGlobal();
  if (message.senderId === global.currentUserId) return;

  const messageKey = getMessageKey(message);
  if (prekeyProcessed.has(messageKey)) return;

  if (getTelebridgeVault().isLocked()) return;

  prekeyProcessed.add(messageKey);
  getActions().bridgeStoreContactPrekey({ senderId: message.senderId, wireText: text });
}

/**
 * Fire-and-forget dispatcher for inbound `tb1.kx.…` key-exchange messages.
 * Safe to call on every render — deduped by `kxProcessed` keyed on
 * messageKey. Own outgoing messages are ignored. Skips silently when a chat
 * key already exists, so old kx traffic in history isn't re-played. Locked
 * vault leaves the message unmarked so the unlock backfill can retry.
 */
export function ensureKxProcessed(message: ApiMessage): void {
  const text = message.content.text?.text;
  if (!text || !text.startsWith('tb1.kx.')) return;
  if (!message.senderId) return;

  const global = getGlobal();
  if (message.senderId === global.currentUserId) return;
  if (global.bridge.chatKeyIds[message.chatId]) return;

  const messageKey = getMessageKey(message);
  if (kxProcessed.has(messageKey)) return;

  if (getTelebridgeVault().isLocked()) return;

  kxProcessed.add(messageKey);
  getActions().bridgeReceiveChatKey({
    chatId: message.chatId,
    senderId: message.senderId,
    wireText: text,
  });
}

/**
 * Triage an inbound `tb1.a` Secured-Message envelope.
 *
 * Two-message fan-out means every Send Secured produces one envelope for the
 * recipient and one for the sender's other devices. Our job here is to
 * identify which one we can open (GCM auth succeeds against our X25519 key)
 * and — crucially — which one we can't. "Can't open" is not an error: it's
 * the sibling copy meant for someone else's X25519 key. We flag those via
 * `bridgeMarkAsymmetricFiltered` so the MessageList render filter hides them.
 *
 * No pinned contact key → refuse (invalidSignature path). TOFU-accepting
 * per-message traffic from an unknown sender would let anyone on the network
 * sign envelopes under an unverified identity and walk right through the
 * GCM gate. This mirrors finding #2 from the 2026-04-14 code review.
 *
 * Deduped by `asymmetricProcessed`. Locked vault leaves the key unmarked so
 * the unlock backfill retries.
 */
export function ensureAsymmetricProcessed(
  chatId: string,
  messageKey: string,
  encryptedText: string,
  senderId: string | undefined,
): void {
  if (!encryptedText.startsWith('tb1.a.')) return;
  if (asymmetricProcessed.has(messageKey)) return;
  if (getCachedDecryptedText(messageKey) !== undefined) return;
  if (inflight.has(messageKey)) return;

  const vault = getTelebridgeVault();
  if (!vault.isInitialized() || vault.isLocked()) return;
  if (!senderId) return;

  // No pinned contact key → refuse (code-review finding #2: don't TOFU-accept
  // per-message envelopes from unknown senders).
  const contact = vault.getContactKey(senderId);
  if (!contact) {
    asymmetricProcessed.add(messageKey);
    // Surface as invalidSignature via the existing MessageMeta warning slot —
    // the MessageMeta `isTelebridgeFailed` check already fires on any tb1
    // payload without `decryptedByKey`, so leaving the cache empty is enough.
    return;
  }

  let payload;
  try {
    payload = decodeSecuredMessage(encryptedText);
  } catch {
    asymmetricProcessed.add(messageKey);
    return;
  }

  asymmetricProcessed.add(messageKey);
  inflight.add(messageKey);

  void (async () => {
    try {
      const identity = vault.getIdentityKeyPair();
      const senderEd25519 = fromBase64(contact.ed25519PublicKey);
      const result = await decryptEnvelopeToText(
        payload,
        identity.x25519PrivateKey,
        senderEd25519,
      );

      if (!result.ok) {
        if (result.reason === 'notForMe') {
          // Sibling envelope from the encrypt-to-self fan-out. Flag so the
          // render filter hides it from the message list entirely.
          getActions().bridgeMarkAsymmetricFiltered({ messageKey });
        }
        // invalidSignature falls through to the generic "tb1 without cached
        // plaintext" UI — MessageMeta already renders a warning glyph there.
        return;
      }

      // GCM + signature OK. Track separately so Golf can apply
      // Send-Secured-specific styling; also stamp lastUsed since we just
      // verified the sender's signature against the pinned key.
      vault.bumpContactKeyLastUsed(senderId);
      getActions().bridgeSetDecryptedText({ messageKey, text: result.text });
      getActions().bridgeMarkAsymmetricDecrypted({ messageKey });
    } finally {
      inflight.delete(messageKey);
    }
  })();
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
