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

/** Result of responding to an incoming key exchange */
export interface KeyExchangeResponse {
  /** The unwrapped 32-byte AES-256 chat key */
  chatKey: Uint8Array;
  /** 4-byte key identifier as hex string */
  keyId: string;
  /** Sender's Ed25519 public key (identity) */
  senderPublicKey: Uint8Array;
  /** TOFU status: 'new' = first contact, 'changed' = key changed, 'unchanged' = same key */
  tofuStatus: 'new' | 'changed' | 'unchanged';
}

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
