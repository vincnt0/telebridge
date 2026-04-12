/**
 * Telebridge v2 — X25519 ECDH Key Exchange
 *
 * Diffie-Hellman key exchange using @noble/curves x25519.
 * Used for Layer 2 chat key establishment (ephemeral and static).
 *
 * CRITICAL: The raw shared secret from ECDH MUST be passed through HKDF
 * (via deriveKey() from ./kdf.ts) before use as an encryption key.
 * Never use the raw ECDH output directly — this is enforced by convention
 * and documented here as a hard requirement.
 */

import { x25519 } from '@noble/curves/ed25519.js';

import type { KeyPair } from './types';
import { randomBytes } from './utils';

/**
 * Generate a new X25519 keypair for Diffie-Hellman key exchange.
 *
 * @returns KeyPair with 32-byte public key and 32-byte private key
 */
export function generateKeyExchangeKeyPair(): KeyPair {
  const privateKey = randomBytes(32);
  const publicKey = x25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/**
 * Compute a shared secret via X25519 Diffie-Hellman.
 *
 * WARNING: The returned shared secret is RAW and MUST be passed through
 * HKDF-SHA256 (via deriveKey()) before use as an encryption key.
 * Using raw ECDH output directly as a key is a security vulnerability.
 *
 * @param privateKey - Our 32-byte X25519 private key
 * @param publicKey - Their 32-byte X25519 public key
 * @returns 32-byte raw shared secret (NOT suitable as encryption key without HKDF)
 */
export function computeSharedSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}
