/**
 * Telebridge v2 — Media Hash → ChatId Registry
 *
 * The mediaLoader identifies downloads by stable media hash (e.g.
 * `photo42/inline`) with no chat context. For Telebridge we need to know
 * which chat a download belongs to so the correct symmetric key can be
 * looked up on the receive side. This module holds a simple in-memory
 * map populated when new messages arrive (apiUpdaters/messages.ts) and
 * consulted by `decryptMediaIfRegistered` from the mediaLoader remote
 * fetch hook.
 *
 * Runtime-only: rebuilt from scratch each session. Messages re-register
 * on reload via the newMessage apiUpdater path, and a batch-register
 * pass on vault-unlock can backfill legacy messages once that lands.
 */

const hashToChatId = new Map<string, string>();

/** Register a single media hash against its owning chat. */
export function registerMediaChat(hash: string, chatId: string): void {
  hashToChatId.set(hash, chatId);
}

/** Register all media hashes on a message in one call. */
export function registerMediaChats(hashes: string[], chatId: string): void {
  for (const hash of hashes) {
    hashToChatId.set(hash, chatId);
  }
}

/** Resolve the owning chatId for a media hash, or undefined if unknown. */
export function getMediaChatId(hash: string): string | undefined {
  return hashToChatId.get(hash);
}

/** Drop all registrations. Useful for tests and full resets. */
export function clearMediaRegistry(): void {
  hashToChatId.clear();
}
