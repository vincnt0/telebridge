/**
 * Telebridge v2 — Media & File Encryption
 *
 * Encrypts ALL media types (photos, videos, voice messages, files) before upload
 * and decrypts after download. No media type is skipped — this explicitly fixes
 * v1's bug where "quick" media (inline photos/videos) were sent unencrypted.
 *
 * ## Binary Wire Format (per ARCHITECTURE.md § Media & File Encryption)
 *
 * ```
 * ┌──────────────┬───────────────┬──────────────────┬──────────────┐
 * │ Version (1B) │ Nonce (12B)   │ Encrypted Data   │ Auth Tag (16B)│
 * └──────────────┴───────────────┴──────────────────┴──────────────┘
 * ```
 *
 * - **Version:** 0x01 for v1.0 (enables future format upgrades)
 * - **Nonce:** 12 random bytes (standard GCM nonce)
 * - **Auth Tag:** GCM authentication tag — MANDATORY (fixes v1's critical auth tag bug)
 * - **Key lookup:** ALWAYS uses message.chatId, never selectCurrentChat() (fixes v1 bug)
 *
 * ## V1 Bugs Fixed
 *
 * 1. Auth tags silently discarded → Auth tags mandatory, always verified
 * 2. `if(quick) key = undefined` skipped photos/videos → ALL media types encrypted
 * 3. Buffer stamp `[0x00, 0x00]` as integrity check → GCM auth tag provides real integrity
 * 4. `selectCurrentChat()` for key lookup → chatId passed explicitly
 * 5. Text vs buffer used different key derivation → Single key path for all data
 * 6. `decipher.final()` commented out → Web Crypto handles finalization properly
 */

import { encrypt, decrypt } from './crypto/aes';
import { SIZES } from './crypto/types';
import type { EncryptedPayload } from './crypto/types';
import { concatBytes, randomBytes } from './crypto/utils';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Current file encryption format version */
export const FILE_FORMAT_VERSION = 0x01;

/** Size of the version prefix in bytes */
const VERSION_SIZE = 1;

/** Minimum encrypted file size: version(1) + nonce(12) + min_ciphertext(1) + auth_tag(16) */
const MIN_ENCRYPTED_SIZE = VERSION_SIZE + SIZES.GCM_NONCE + 1 + SIZES.GCM_TAG;

/** Supported format versions for decryption (current + previous for migration) */
const SUPPORTED_VERSIONS = new Set([0x01]);

/**
 * Coerce a Uint8Array view into a standalone ArrayBuffer.
 * Web Crypto APIs reject ArrayBufferLike (e.g. SharedArrayBuffer) under strict TS.
 */
function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  if (
    data.buffer instanceof ArrayBuffer
    && data.byteOffset === 0
    && data.byteLength === data.buffer.byteLength
  ) {
    return data.buffer;
  }
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

// ---------------------------------------------------------------------------
// Media Type Classification
// ---------------------------------------------------------------------------

/**
 * All media types that MUST be encrypted. No exceptions.
 * This enum exists to make it explicit that every media type is covered —
 * v1 silently skipped "quick" media (photos/videos).
 */
export enum MediaType {
  Photo = 'photo',
  Video = 'video',
  Voice = 'voice',
  Document = 'document',
  Animation = 'animation',
  Sticker = 'sticker', // Note: stickers are NOT encrypted per spec (public assets)
  VideoNote = 'videoNote',
}

/** Media types that should be encrypted (all except stickers per spec) */
const ENCRYPTED_MEDIA_TYPES = new Set<MediaType>([
  MediaType.Photo,
  MediaType.Video,
  MediaType.Voice,
  MediaType.Document,
  MediaType.Animation,
  MediaType.VideoNote,
]);

/**
 * Check whether a media type should be encrypted.
 * Returns true for ALL types except stickers (which are public assets).
 */
export function shouldEncryptMediaType(mediaType: MediaType): boolean {
  return ENCRYPTED_MEDIA_TYPES.has(mediaType);
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/**
 * Encrypt a media file buffer for upload.
 *
 * Produces the binary format:
 * `[version(1B)][nonce(12B)][encrypted_data(var)][auth_tag(16B)]`
 *
 * The entire file is encrypted in memory before upload. Telegram's chunked
 * upload then operates on the ciphertext, which is fine — the recipient
 * downloads all chunks, reassembles, then decrypts.
 *
 * @param plainBuffer - Raw file data (photo, video, voice, document, etc.)
 * @param chatKey - 32-byte AES-256 key for this chat (from TelebridgeState)
 * @returns Encrypted buffer ready for chunked upload to Telegram
 * @throws If chatKey is not 32 bytes
 */
export async function encryptMedia(
  plainBuffer: Uint8Array,
  chatKey: Uint8Array,
): Promise<Uint8Array> {
  if (chatKey.length !== SIZES.AES_KEY) {
    throw new Error(`Chat key must be ${SIZES.AES_KEY} bytes, got ${chatKey.length}`);
  }

  // AES-256-GCM encrypt — returns { iv, ciphertext, authTag }
  const encrypted: EncryptedPayload = await encrypt(plainBuffer, chatKey);

  // Build wire format: version(1) + nonce(12) + encrypted_data(var) + auth_tag(16)
  const version = new Uint8Array([FILE_FORMAT_VERSION]);

  return concatBytes(version, encrypted.iv, encrypted.ciphertext, encrypted.authTag);
}

/**
 * Encrypt a media file with explicit nonce (for testing determinism only).
 * Production code should always use encryptMedia() which generates random nonces.
 *
 * @internal — Exported for testing only
 */
export async function encryptMediaWithNonce(
  plainBuffer: Uint8Array,
  chatKey: Uint8Array,
  nonce: Uint8Array,
): Promise<Uint8Array> {
  if (chatKey.length !== SIZES.AES_KEY) {
    throw new Error(`Chat key must be ${SIZES.AES_KEY} bytes, got ${chatKey.length}`);
  }
  if (nonce.length !== SIZES.GCM_NONCE) {
    throw new Error(`Nonce must be ${SIZES.GCM_NONCE} bytes, got ${nonce.length}`);
  }

  // Use Web Crypto directly for deterministic nonce
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(chatKey),
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  );

  const combined = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(nonce), tagLength: 128 },
      cryptoKey,
      toArrayBuffer(plainBuffer),
    ),
  );

  // Split ciphertext and auth tag
  const ciphertext = combined.slice(0, combined.length - SIZES.GCM_TAG);
  const authTag = combined.slice(combined.length - SIZES.GCM_TAG);
  const version = new Uint8Array([FILE_FORMAT_VERSION]);

  return concatBytes(version, nonce, ciphertext, authTag);
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

/** Result of media decryption attempt */
export interface MediaDecryptionResult {
  /** Whether decryption succeeded */
  success: boolean;
  /** Decrypted file data — only present on success */
  data?: Uint8Array;
  /** Error description for debugging (not shown to users) */
  error?: string;
}

/**
 * Decrypt an encrypted media file buffer after download and reassembly.
 *
 * Parses the binary format:
 * `[version(1B)][nonce(12B)][encrypted_data(var)][auth_tag(16B)]`
 *
 * Verifies the GCM auth tag before returning plaintext.
 * Returns a result object (never throws for expected failures like wrong key).
 *
 * @param encryptedBuffer - Full encrypted file (all chunks reassembled)
 * @param chatKey - 32-byte AES-256 key for this chat
 * @returns MediaDecryptionResult with success status and data
 */
export async function decryptMedia(
  encryptedBuffer: Uint8Array,
  chatKey: Uint8Array,
): Promise<MediaDecryptionResult> {
  // Validate minimum size
  if (encryptedBuffer.length < MIN_ENCRYPTED_SIZE) {
    return {
      success: false,
      error: `Buffer too small: ${encryptedBuffer.length} bytes, minimum ${MIN_ENCRYPTED_SIZE}`,
    };
  }

  // Parse version byte
  const version = encryptedBuffer[0];
  if (!SUPPORTED_VERSIONS.has(version)) {
    return {
      success: false,
      error: `Unsupported file encryption version: 0x${version.toString(16).padStart(2, '0')}`,
    };
  }

  // Validate key size
  if (chatKey.length !== SIZES.AES_KEY) {
    return {
      success: false,
      error: `Chat key must be ${SIZES.AES_KEY} bytes, got ${chatKey.length}`,
    };
  }

  // Parse fields from binary format
  const nonce = encryptedBuffer.slice(VERSION_SIZE, VERSION_SIZE + SIZES.GCM_NONCE);
  const encryptedDataWithTag = encryptedBuffer.slice(VERSION_SIZE + SIZES.GCM_NONCE);

  // Split encrypted data and auth tag
  if (encryptedDataWithTag.length < SIZES.GCM_TAG + 1) {
    return {
      success: false,
      error: 'Encrypted data too short: no ciphertext after nonce and auth tag',
    };
  }

  const ciphertext = encryptedDataWithTag.slice(0, encryptedDataWithTag.length - SIZES.GCM_TAG);
  const authTag = encryptedDataWithTag.slice(encryptedDataWithTag.length - SIZES.GCM_TAG);

  // Build EncryptedPayload for the decrypt function
  const payload: EncryptedPayload = {
    iv: nonce,
    ciphertext,
    authTag,
  };

  // Decrypt and verify auth tag
  try {
    const plaintext = await decrypt(payload, chatKey);
    return {
      success: true,
      data: plaintext,
    };
  } catch {
    return {
      success: false,
      error: 'AES-GCM decryption failed: wrong key or tampered data',
    };
  }
}

// ---------------------------------------------------------------------------
// Upload / Download Pipeline Integration
// ---------------------------------------------------------------------------

/**
 * Encrypt a file buffer for upload if the chat has an active encryption key.
 *
 * This is the single integration point for the upload pipeline.
 * All upload paths (photo, video, voice, document, animation, videoNote)
 * should call this. Stickers pass through unencrypted.
 *
 * @param buffer - Raw file buffer to upload
 * @param chatKey - Chat's AES-256 key, or undefined if chat is not encrypted
 * @param mediaType - Type of media being uploaded
 * @returns Encrypted buffer if key provided and media type should be encrypted,
 *          original buffer otherwise
 */
export async function encryptForUpload(
  buffer: Uint8Array,
  chatKey: Uint8Array | undefined,
  mediaType: MediaType,
): Promise<Uint8Array> {
  // No key = no encryption (chat not set up for Telebridge)
  if (!chatKey) return buffer;

  // Stickers are public assets — never encrypt
  if (!shouldEncryptMediaType(mediaType)) return buffer;

  return encryptMedia(buffer, chatKey);
}

/**
 * Decrypt a file buffer after download if it appears to be Telebridge-encrypted.
 *
 * This is the single integration point for the download pipeline.
 * All download paths should call this after reassembling chunks.
 *
 * Uses message.chatId for key lookup — NEVER selectCurrentChat() (v1 bug fix).
 *
 * If the buffer doesn't have the Telebridge version header, it's returned as-is
 * (graceful fallback for unencrypted files in mixed chats).
 *
 * @param buffer - Downloaded file buffer (all chunks reassembled)
 * @param chatKey - Chat's AES-256 key, or undefined if chat is not encrypted
 * @returns Decrypted buffer on success, original buffer if not encrypted or no key
 */
export async function decryptAfterDownload(
  buffer: Uint8Array,
  chatKey: Uint8Array | undefined,
): Promise<Uint8Array> {
  // No key = can't decrypt, return as-is
  if (!chatKey) return buffer;

  // Check if this looks like a Telebridge-encrypted file
  if (!isEncryptedMedia(buffer)) return buffer;

  const result = await decryptMedia(buffer, chatKey);

  if (result.success && result.data) {
    return result.data;
  }

  // Decryption failed — return original buffer as fallback
  // The UI layer should show a warning indicator
  return buffer;
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/**
 * Quick check: does this buffer start with a known Telebridge file version byte?
 *
 * O(1) — single byte check. Used as a fast gate before attempting decryption.
 *
 * @param buffer - File buffer to check
 * @returns true if the first byte is a supported Telebridge file version
 */
export function isEncryptedMedia(buffer: Uint8Array): boolean {
  if (buffer.length < MIN_ENCRYPTED_SIZE) return false;
  return SUPPORTED_VERSIONS.has(buffer[0]);
}

// ---------------------------------------------------------------------------
// Utility: Get chat key for media operations
// ---------------------------------------------------------------------------

/**
 * Look up the encryption key for a chat from TelebridgeState.
 *
 * ALWAYS uses the message's chatId — never selectCurrentChat().
 * This is a critical v1 bug fix: v1 used selectCurrentChat() which would
 * return the wrong key when downloading media from a different chat than
 * the currently viewed one.
 *
 * @param chatId - The chat ID the media belongs to (from message.chatId)
 * @returns 32-byte AES key or undefined if no key for this chat
 */
export function getMediaChatKey(chatId: string): Uint8Array | undefined {
  // Import here to avoid circular dependency with send.ts singleton
  const { getTelebridgeVault } = require('./send');
  const vault = getTelebridgeVault();

  if (!vault.isInitialized() || vault.isLocked()) {
    return undefined;
  }

  return vault.getChatKey(chatId);
}
