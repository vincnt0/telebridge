/**
 * Telebridge v2 — Argon2id Password Hashing
 *
 * Password-based key derivation using Argon2id (RFC 9106).
 * Used for deriving encryption keys from user bridge passwords.
 *
 * Uses @noble/hashes/argon2 — audited, zero-dependency, pure JS.
 *
 * V1 BUG AVOIDANCE:
 * - V1 used bare SHA-256 with no key stretching → we use Argon2id (memory-hard)
 * - V1 stored plaintext password in global state → password discarded after derivation
 */

import { argon2id } from '@noble/hashes/argon2.js';

import type { Argon2Params } from './types';
import { DEFAULT_ARGON2_PARAMS } from './types';

/**
 * Derive a key from a password using Argon2id.
 *
 * Accepts either a string or pre-encoded UTF-8 bytes. Callers are responsible
 * for managing the salt — this function does not generate one.
 *
 * @param password - User password (string or UTF-8 bytes)
 * @param salt - Salt bytes (typically 16–32 bytes of random data)
 * @param params - Optional Argon2id parameters (defaults from DEFAULT_ARGON2_PARAMS)
 * @returns Raw derived key as Uint8Array (length = params.hashLength)
 */
export async function hashPassword(
  password: string | Uint8Array,
  salt: Uint8Array,
  params?: Argon2Params,
): Promise<Uint8Array> {
  const {
    memoryCost,
    timeCost,
    parallelism,
    hashLength,
  } = { ...DEFAULT_ARGON2_PARAMS, ...params };

  const passwordBytes = typeof password === 'string'
    ? new TextEncoder().encode(password)
    : password;

  const hash = argon2id(
    passwordBytes,
    salt,
    {
      t: timeCost,
      m: memoryCost,
      p: parallelism,
      dkLen: hashLength,
    },
  );

  return new Uint8Array(hash);
}
