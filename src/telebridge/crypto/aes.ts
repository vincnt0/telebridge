/**
 * Telebridge v2 — AES-256-GCM Symmetric Encryption
 *
 * Uses Web Crypto API for hardware-accelerated AES-256-GCM.
 *
 * V1 BUG AVOIDANCE:
 * - Auth tags are MANDATORY — v1 silently discarded them, making GCM equivalent to CTR.
 * - EncryptedPayload always contains separate iv, ciphertext, and authTag fields.
 * - decipher.final() is never skipped — Web Crypto handles finalization internally.
 * - Fresh random 12-byte IV per encryption — NEVER reused.
 */

import type { EncryptedPayload } from './types';
import { SIZES } from './types';
import { randomBytes } from './utils';

/** GCM tag length in bits (128 bits = 16 bytes) */
const TAG_LENGTH_BITS = 128;

/**
 * Ensure we hand a plain ArrayBuffer to Web Crypto API.
 * Required because TS 5.9+ enforces ArrayBufferView<ArrayBuffer>.
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

/**
 * Encrypt plaintext with AES-256-GCM.
 *
 * Generates a fresh random 12-byte IV per call.
 * Returns separate ciphertext and authTag (split from Web Crypto's combined output).
 *
 * @param plaintext - Data to encrypt
 * @param key - 32-byte AES-256 key (must be derived via HKDF, never raw)
 * @param aad - Optional additional authenticated data
 * @returns EncryptedPayload with iv, ciphertext, and authTag as separate fields
 */
export async function encrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  aad?: Uint8Array,
): Promise<EncryptedPayload> {
  if (key.length !== SIZES.AES_KEY) {
    throw new Error(`AES key must be ${SIZES.AES_KEY} bytes, got ${key.length}`);
  }

  const iv = randomBytes(SIZES.GCM_NONCE);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(key),
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  );

  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: toArrayBuffer(iv),
    tagLength: TAG_LENGTH_BITS,
  };

  if (aad) {
    params.additionalData = toArrayBuffer(aad);
  }

  // Web Crypto appends the 16-byte auth tag to ciphertext
  const combined = new Uint8Array(
    await crypto.subtle.encrypt(params, cryptoKey, toArrayBuffer(plaintext)),
  );

  // Split: ciphertext is everything except the last 16 bytes; auth tag is the last 16
  const ciphertext = combined.slice(0, combined.length - SIZES.GCM_TAG);
  const authTag = combined.slice(combined.length - SIZES.GCM_TAG);

  return { iv, ciphertext, authTag };
}

/**
 * Decrypt AES-256-GCM ciphertext.
 *
 * Verifies the auth tag before returning plaintext.
 * Throws if the key is wrong, ciphertext is tampered, or tag is invalid.
 *
 * @param payload - EncryptedPayload (iv + ciphertext + authTag)
 * @param key - 32-byte AES-256 key
 * @param aad - Optional additional authenticated data (must match encryption)
 * @returns Decrypted plaintext
 * @throws If authentication fails (wrong key, tampered data, or invalid tag)
 */
export async function decrypt(
  payload: EncryptedPayload,
  key: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  if (key.length !== SIZES.AES_KEY) {
    throw new Error(`AES key must be ${SIZES.AES_KEY} bytes, got ${key.length}`);
  }

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(key),
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );

  // Reassemble: Web Crypto expects ciphertext + auth tag concatenated
  const combined = new Uint8Array(payload.ciphertext.length + payload.authTag.length);
  combined.set(payload.ciphertext, 0);
  combined.set(payload.authTag, payload.ciphertext.length);

  const params: AesGcmParams = {
    name: 'AES-GCM',
    iv: toArrayBuffer(payload.iv),
    tagLength: TAG_LENGTH_BITS,
  };

  if (aad) {
    params.additionalData = toArrayBuffer(aad);
  }

  return new Uint8Array(
    await crypto.subtle.decrypt(params, cryptoKey, toArrayBuffer(combined)),
  );
}
