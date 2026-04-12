/**
 * Telebridge v2 — HKDF-SHA256 Key Derivation
 *
 * RFC 5869 HKDF (HMAC-based Extract-and-Expand Key Derivation Function).
 *
 * This is the SINGLE consistent key derivation path for the entire system.
 * Every derived key flows through this module:
 *
 *   - AES keys: HKDF(shared_secret | password_hash, salt, info) → 32-byte AES key
 *   - ECDH shared secrets: raw X25519 output → HKDF → usable key material
 *   - Password-derived keys: Argon2id output → HKDF → AES key for encrypting at rest
 *
 * V1 used ad-hoc single/double SHA-256 hashing which caused text and buffer
 * encryption to use different effective keys for the same input. This module
 * eliminates that bug by providing one canonical derivation path.
 */

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { SIZES } from './types';

/**
 * Derive a key using HKDF-SHA256.
 *
 * @param ikm - Input keying material (e.g., ECDH shared secret, Argon2id output)
 * @param salt - Salt value (recommended: random bytes; omit for zero-salt)
 * @param info - Context/application info string (e.g., "Telebridge-v2-chat-key")
 * @param length - Output length in bytes (minimum 32 for AES-256)
 * @returns Derived key as Uint8Array
 * @throws If requested length is less than 32 bytes (AES-256 minimum)
 */
export function deriveKey(
  ikm: Uint8Array,
  salt: Uint8Array = new Uint8Array(0),
  info: Uint8Array = new Uint8Array(0),
  length: number = SIZES.HKDF_DEFAULT_OUTPUT,
): Uint8Array {
  if (length < SIZES.AES_KEY) {
    throw new Error(`Minimum derived key length is ${SIZES.AES_KEY} bytes (AES-256), got ${length}`);
  }

  return hkdf(sha256, ikm, salt, info, length);
}
