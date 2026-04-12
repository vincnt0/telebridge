/**
 * Telebridge v2 — Ed25519 Digital Signatures
 *
 * Keypair generation, signing, and verification using @noble/curves.
 * Used for identity keys (Layer 1) and per-message authentication.
 *
 * Private keys are never exposed beyond the generateSigningKeyPair() return.
 */

import { ed25519 } from '@noble/curves/ed25519.js';

import type { KeyPair } from './types';
import { randomBytes } from './utils';

/**
 * Generate a new Ed25519 signing keypair.
 *
 * @returns KeyPair with 32-byte public key and 32-byte private key (seed)
 */
export function generateSigningKeyPair(): KeyPair {
  const privateKey = randomBytes(32);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/**
 * Sign a message with an Ed25519 private key.
 *
 * @param message - Message bytes to sign
 * @param privateKey - 32-byte Ed25519 private key (seed)
 * @returns 64-byte Ed25519 signature
 */
export function sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKey);
}

/**
 * Verify an Ed25519 signature.
 *
 * @param message - Original message bytes
 * @param signature - 64-byte Ed25519 signature to verify
 * @param publicKey - 32-byte Ed25519 public key
 * @returns true if signature is valid, false otherwise
 */
export function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
