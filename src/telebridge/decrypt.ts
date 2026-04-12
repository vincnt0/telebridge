/**
 * Telebridge v2 — Symmetric Message Decryption
 *
 * Decrypts tb1.s.* wire-format messages using the chat's AES-256-GCM key.
 * Verifies GCM auth tag (mandatory) and Ed25519 sender signature (when possible).
 *
 * Wire format payload: [keyId(4B)][nonce(12B)][ciphertext(var)][authTag(16B)][signature(64B)]
 * Signature covers: keyId ‖ nonce ‖ ciphertext ‖ authTag
 *
 * Security invariants:
 * - GCM auth tag is ALWAYS verified (never skipped)
 * - Signature verification is best-effort (succeeds without sender key, warns on mismatch)
 * - Key lookup uses chatId, NEVER selectCurrentChat() (fixes v1 bug)
 */

import type { EncryptedPayload } from './crypto/types';
import type { DecryptionResult } from './types';

import {
  aesDecrypt,
  concatBytes,
  decodeUtf8,
  ed25519Verify,
} from './crypto';
import { decodeSymmetricMessage } from './protocol/decode';

/**
 * Decrypt a tb1.s.* symmetric message given the chat key and optional sender public key.
 *
 * @param encryptedText — Full wire-format string (e.g. "tb1.s.AAAA...")
 * @param chatKey — 32-byte AES-256 chat key
 * @param senderPublicKey — Optional 32-byte Ed25519 public key for signature verification
 * @returns DecryptionResult with status and (on success) plaintext
 */
export async function decryptSymmetricMessage(
  encryptedText: string,
  chatKey: Uint8Array,
  senderPublicKey?: Uint8Array,
): Promise<DecryptionResult> {
  // 1. Parse the wire format into structured fields
  let payload;
  try {
    payload = decodeSymmetricMessage(encryptedText);
  } catch (err) {
    return {
      status: 'malformed',
      error: err instanceof Error ? err.message : 'Failed to decode message',
    };
  }

  // 2. Build crypto-layer EncryptedPayload (iv/ciphertext/authTag as separate fields)
  const aesPayload: EncryptedPayload = {
    iv: payload.nonce,
    ciphertext: payload.ciphertext,
    authTag: payload.authTag,
  };

  // 3. AES-256-GCM decrypt (auth tag verified internally by Web Crypto)
  let plaintextBytes: Uint8Array;
  try {
    plaintextBytes = await aesDecrypt(aesPayload, chatKey);
  } catch {
    return {
      status: 'wrongKey',
      error: 'AES-GCM decryption failed: wrong key or tampered ciphertext',
    };
  }

  // 4. Decode UTF-8 plaintext
  const text = decodeUtf8(plaintextBytes);

  // 5. Verify Ed25519 sender signature (best-effort)
  let isSignatureVerified: boolean | undefined;

  if (senderPublicKey) {
    // Signature covers: keyId ‖ nonce ‖ ciphertext ‖ authTag
    const signedData = concatBytes(
      payload.keyId,
      payload.nonce,
      payload.ciphertext,
      payload.authTag,
    );

    const isValid = ed25519Verify(signedData, payload.signature, senderPublicKey);

    if (!isValid) {
      // Signature explicitly failed — could be tampered or wrong sender
      return {
        status: 'invalidSignature',
        text, // Still provide decrypted text — GCM already authenticated integrity
        isSignatureVerified: false,
        error: 'Ed25519 signature verification failed',
      };
    }

    isSignatureVerified = true;
  }

  return {
    status: 'success',
    text,
    isSignatureVerified,
  };
}

/**
 * Synchronous check: is this text worth attempting decryption on?
 * Used as a fast gate before the async decrypt path.
 *
 * O(1) — just a char code check, no regex on full text.
 */
export { isTelebridgeMessage } from './protocol';
