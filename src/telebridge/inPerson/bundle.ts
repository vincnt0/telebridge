/**
 * Telebridge v3 — In-person QR identity-bundle codec.
 *
 * Implements the wire format documented in `docs/plans/in-person-kx.md` § 2:
 *
 *   magic(2B = 0x74 0x62)  "tb"
 *   ver  (1B = 0x01)
 *   Ed25519 public key    (32B)
 *   X25519  public key    (32B)
 *   Ed25519 signature     (64B)   — over magic || ver || ed25519Pub || x25519Pub
 *   ─────────────────────────────
 *   total                 131B
 *
 * The binary blob is base64url-encoded (URL-safe alphabet, no padding) and
 * prefixed with `tb1://pk/` so that non-Telebridge scanners surface an intent
 * handler instead of raw base64.
 *
 * Magic + version are included in the signed bytes so a wire `tb1.pk` bundle
 * cannot be replayed into the QR pipe (and vice versa); see plan § 2.
 */

import { concatBytes, ed25519Sign, fromBase64, toBase64 } from '../crypto';
import { InvalidSignatureError, verifyPrekeyBundle } from '../protocol/verify';

// ---------------------------------------------------------------------------
// Constants — wire format
// ---------------------------------------------------------------------------

export const BUNDLE_PREFIX = 'tb1://pk/';
export const BUNDLE_MAGIC = new Uint8Array([0x74, 0x62]); // "tb"
export const BUNDLE_VERSION = 0x01;

const MAGIC_LEN = 2;
const VERSION_LEN = 1;
const ED25519_PUB_LEN = 32;
const X25519_PUB_LEN = 32;
const SIGNATURE_LEN = 64;
export const BUNDLE_TOTAL_LEN =
  MAGIC_LEN + VERSION_LEN + ED25519_PUB_LEN + X25519_PUB_LEN + SIGNATURE_LEN; // 131

// Byte offsets
const OFFSET_MAGIC = 0;
const OFFSET_VERSION = OFFSET_MAGIC + MAGIC_LEN;
const OFFSET_ED25519_PUB = OFFSET_VERSION + VERSION_LEN;
const OFFSET_X25519_PUB = OFFSET_ED25519_PUB + ED25519_PUB_LEN;
// Signable covers magic || ver || ed25519Pub || x25519Pub — ending where the sig begins.
const OFFSET_SIGNATURE = OFFSET_X25519_PUB + X25519_PUB_LEN;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Thrown when a QR-bundle string cannot be parsed: bad prefix, bad base64,
 * wrong magic, wrong version, or truncated/overlong payload.
 *
 * Signature-check failures are a separate {@link InvalidSignatureError}
 * (re-exported below so callers only import from this module).
 */
export class InvalidBundleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidBundleError';
  }
}

export { InvalidSignatureError };

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Parsed fields of an identity bundle, post-decode, pre-verify. */
export interface DecodedIdentityBundle {
  /** Full raw binary blob, all 131 bytes (useful for re-encoding/display). */
  raw: Uint8Array;
  /** Bytes the signature covers — `magic || ver || ed25519Pub || x25519Pub`. */
  signable: Uint8Array;
  /** Format version byte — currently always 0x01; kept for PQ upgrade (0x02). */
  version: number;
  /** 32-byte Ed25519 identity public key. */
  ed25519PublicKey: Uint8Array;
  /** 32-byte X25519 signed prekey public key. */
  x25519PublicKey: Uint8Array;
  /** 64-byte Ed25519 signature over {@link signable}. */
  signature: Uint8Array;
}

// ---------------------------------------------------------------------------
// base64url helpers (URL-safe alphabet, no padding)
// ---------------------------------------------------------------------------

function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function fromBase64Url(text: string): Uint8Array {
  // Restore standard base64 alphabet and pad to a multiple of 4.
  let normalized = text.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (normalized.length % 4)) % 4;
  normalized += '='.repeat(padLen);
  return fromBase64(normalized);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Sign and encode an identity bundle into its `tb1://pk/<base64url>` form.
 *
 * The caller owns the identity keypair; this function does no key storage.
 */
export function encodeIdentityBundle(identity: {
  ed25519PublicKey: Uint8Array;
  x25519PublicKey: Uint8Array;
  ed25519PrivateKey: Uint8Array;
}): string {
  if (identity.ed25519PublicKey.length !== ED25519_PUB_LEN) {
    throw new Error(`Ed25519 public key must be ${ED25519_PUB_LEN} bytes`);
  }
  if (identity.x25519PublicKey.length !== X25519_PUB_LEN) {
    throw new Error(`X25519 public key must be ${X25519_PUB_LEN} bytes`);
  }

  const versionByte = new Uint8Array([BUNDLE_VERSION]);
  const signable = concatBytes(
    BUNDLE_MAGIC,
    versionByte,
    identity.ed25519PublicKey,
    identity.x25519PublicKey,
  );
  const signature = ed25519Sign(signable, identity.ed25519PrivateKey);
  const raw = concatBytes(signable, signature);
  return BUNDLE_PREFIX + toBase64Url(raw);
}

/**
 * Parse the `tb1://pk/<base64url>` string into its structured parts.
 *
 * Validates: prefix, base64url decodability, total length, magic bytes,
 * version byte. Throws {@link InvalidBundleError} on any failure.
 *
 * Does NOT verify the signature — run {@link verifyIdentityBundle} next.
 */
export function decodeIdentityBundle(text: string): DecodedIdentityBundle {
  if (typeof text !== 'string' || !text.startsWith(BUNDLE_PREFIX)) {
    throw new InvalidBundleError(`Expected ${BUNDLE_PREFIX} prefix`);
  }

  const encoded = text.slice(BUNDLE_PREFIX.length);
  let raw: Uint8Array;
  try {
    raw = fromBase64Url(encoded);
  } catch {
    throw new InvalidBundleError('Payload is not valid base64url');
  }

  if (raw.length !== BUNDLE_TOTAL_LEN) {
    throw new InvalidBundleError(
      `Expected ${BUNDLE_TOTAL_LEN}-byte payload, got ${raw.length}`,
    );
  }

  if (raw[OFFSET_MAGIC] !== BUNDLE_MAGIC[0] || raw[OFFSET_MAGIC + 1] !== BUNDLE_MAGIC[1]) {
    throw new InvalidBundleError('Magic bytes do not match "tb"');
  }

  const version = raw[OFFSET_VERSION];
  if (version !== BUNDLE_VERSION) {
    throw new InvalidBundleError(`Unsupported bundle version 0x${version.toString(16)}`);
  }

  // slice() on Uint8Array returns a copy — safe to hand out to callers.
  const signable = raw.slice(OFFSET_MAGIC, OFFSET_SIGNATURE);
  const ed25519PublicKey = raw.slice(OFFSET_ED25519_PUB, OFFSET_ED25519_PUB + ED25519_PUB_LEN);
  const x25519PublicKey = raw.slice(OFFSET_X25519_PUB, OFFSET_X25519_PUB + X25519_PUB_LEN);
  const signature = raw.slice(OFFSET_SIGNATURE, OFFSET_SIGNATURE + SIGNATURE_LEN);

  return {
    raw,
    signable,
    version,
    ed25519PublicKey,
    x25519PublicKey,
    signature,
  };
}

/**
 * Verify the Ed25519 signature over the decoded bundle's signable bytes.
 * Throws {@link InvalidSignatureError} on failure. Returns normally on success.
 *
 * Delegates to the shared {@link verifyPrekeyBundle} helper so the QR and
 * wire paths share one signature-check implementation.
 */
export function verifyIdentityBundle(decoded: DecodedIdentityBundle): void {
  verifyPrekeyBundle(decoded.signable, decoded.signature, decoded.ed25519PublicKey);
}
