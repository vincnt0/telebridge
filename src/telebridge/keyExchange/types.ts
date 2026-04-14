/**
 * Telebridge v2 — Key Exchange Types
 *
 * TypeScript interfaces for the Layer 2 key exchange handshake:
 * initiation results, response results, rotation config, and rotation checks.
 */

/** Result of initiating a key exchange handshake */
export interface KeyExchangeInitiation {
  /** The `tb1.kx` wire-format message to send to the recipient */
  wireMessage: string;
  /** The freshly generated 32-byte AES-256 chat key (for local storage) */
  chatKey: Uint8Array;
  /** 4-byte key identifier as hex string */
  keyId: string;
}

/** Successful result of responding to an incoming key exchange */
export interface KeyExchangeResponseOk {
  status: 'ok';
  /** The unwrapped 32-byte AES-256 chat key */
  chatKey: Uint8Array;
  /** 4-byte key identifier as hex string */
  keyId: string;
  /** Sender's Ed25519 public key (identity) */
  senderPublicKey: Uint8Array;
  /** TOFU status: 'new' = first contact, 'changed' = key changed, 'unchanged' = same key */
  tofuStatus: 'new' | 'changed' | 'unchanged';
}

/**
 * Discriminated result of responding to an incoming key exchange.
 *
 * - `ok`: handshake verified against a pinned identity; chat key derived.
 * - `needsPrekey`: no pinned identity for this sender yet; caller should
 *   queue the raw kx and retry once a `tb1.pk` (or in-person bundle) pins the
 *   sender's Ed25519 key.
 * - `identityMismatch`: wire-embedded sender key differs from the pinned
 *   key — likely race-to-pin MITM; refuse without derivation.
 */
export type KeyExchangeResponse =
  | KeyExchangeResponseOk
  | { status: 'needsPrekey' }
  | { status: 'identityMismatch' };

/** Configuration for automatic key rotation thresholds */
export interface RotationConfig {
  /** Rotate after this many messages (default: 100) */
  maxMessages: number;
  /** Rotate after this many days (default: 7) */
  maxDays: number;
}

/** Result of checking whether rotation is needed */
export interface RotationCheck {
  /** Whether the key should be rotated */
  shouldRotate: boolean;
  /** Reason for rotation (only set when shouldRotate is true) */
  reason?: 'message_count' | 'time_elapsed';
}

/** Default rotation configuration */
export const DEFAULT_ROTATION_CONFIG: RotationConfig = {
  maxMessages: 100,
  maxDays: 7,
};
