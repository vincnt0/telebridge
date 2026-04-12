/**
 * Telebridge v2 — Protocol Constants
 *
 * Wire format: tb<version>.<mode>.<payload_base64>
 * All field sizes in bytes, matching the architecture spec exactly.
 */

/** Protocol prefix identifying Telebridge messages */
export const TELEBRIDGE_PREFIX = 'tb';

/** Current protocol version */
export const PROTOCOL_VERSION = 1;

/** Message mode identifiers */
export const MODES = {
  SYMMETRIC: 's',
  ASYMMETRIC: 'a',
  KEY_EXCHANGE: 'kx',
  PREKEY: 'pk',
} as const;

/** All valid mode strings for quick lookup */
export const VALID_MODES = new Set<string>(Object.values(MODES));

/** Wire format separator */
export const SEPARATOR = '.';

/** Field sizes in bytes — must match crypto suite and spec diagrams exactly */
export const FIELD_SIZES = {
  /** Key rotation identifier */
  KEY_ID: 4,
  /** AES-256-GCM nonce (standard) */
  NONCE: 12,
  /** AES-256-GCM authentication tag */
  AUTH_TAG: 16,
  /** Ed25519 signature */
  ED25519_SIGNATURE: 64,
  /** X25519 public key */
  X25519_PUBLIC_KEY: 32,
  /** Ed25519 public key */
  ED25519_PUBLIC_KEY: 32,
} as const;

/**
 * Minimum payload sizes for each message type (sum of all fixed-size fields).
 * Variable-length fields (ciphertext, encrypted chat key) are excluded.
 */
export const MIN_PAYLOAD_SIZES = {
  /** keyId(4) + nonce(12) + authTag(16) + sig(64) = 96 */
  SYMMETRIC: FIELD_SIZES.KEY_ID + FIELD_SIZES.NONCE + FIELD_SIZES.AUTH_TAG + FIELD_SIZES.ED25519_SIGNATURE,
  /** ephemeralX25519(32) + nonce(12) + authTag(16) + sig(64) = 124 */
  ASYMMETRIC: FIELD_SIZES.X25519_PUBLIC_KEY + FIELD_SIZES.NONCE + FIELD_SIZES.AUTH_TAG + FIELD_SIZES.ED25519_SIGNATURE,
  /** senderIdKey(32) + ephemeralX25519(32) + sig(64) = 128 */
  KEY_EXCHANGE: FIELD_SIZES.ED25519_PUBLIC_KEY + FIELD_SIZES.X25519_PUBLIC_KEY + FIELD_SIZES.ED25519_SIGNATURE,
  /** ed25519PubKey(32) + x25519PubKey(32) + sig(64) = 128 */
  PREKEY: FIELD_SIZES.ED25519_PUBLIC_KEY + FIELD_SIZES.X25519_PUBLIC_KEY + FIELD_SIZES.ED25519_SIGNATURE,
} as const;

/** Regex pattern matching the Telebridge header: tb<digit>.<mode>. */
export const HEADER_PATTERN = /^tb(\d+)\.([a-z]+)\./;
