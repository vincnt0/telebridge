/**
 * Telebridge v3 — Shared prekey-bundle signature verification.
 *
 * A single helper that wire-format (`tb1.pk`) and in-person QR-bundle
 * decoders both call. The caller supplies the exact bytes that were
 * signed (the "signable"); this module stays agnostic about whether
 * those bytes include a magic/version prefix.
 *
 * Wire prekey signable:       ed25519Pub || x25519Pub
 * In-person QR signable:      magic || ver || ed25519Pub || x25519Pub
 *
 * The two shapes are intentionally distinct so a wire bundle cannot be
 * replayed into the QR pipe and vice versa — see plan § 2, byte layout.
 */

import { ed25519Verify } from '../crypto';

/**
 * Thrown when an Ed25519 signature over a prekey bundle fails verification.
 * Callers should treat this as "do not pin this key" — surface to UX on the
 * QR path, drop silently on the wire path (matches existing behavior).
 */
export class InvalidSignatureError extends Error {
  constructor(message = 'Invalid prekey bundle signature') {
    super(message);
    this.name = 'InvalidSignatureError';
  }
}

/**
 * Verify a signed prekey bundle. Throws {@link InvalidSignatureError} on failure.
 *
 * @param signable - The exact bytes covered by the signature.
 * @param sig      - 64-byte Ed25519 signature.
 * @param pub      - 32-byte Ed25519 public key (also the identity key).
 */
export function verifyPrekeyBundle(
  signable: Uint8Array,
  sig: Uint8Array,
  pub: Uint8Array,
): void {
  if (!ed25519Verify(signable, sig, pub)) {
    throw new InvalidSignatureError();
  }
}
