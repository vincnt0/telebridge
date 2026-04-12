/**
 * Telebridge v2 — Protocol Types
 *
 * TypeScript interfaces for all 4 message payload types and the
 * discriminated union TelebridgeMessage.
 *
 * All binary fields are Uint8Array. No null — undefined only.
 */

import type { MODES } from './constants';

// ---------------------------------------------------------------------------
// Payload types — one per wire format mode
// ---------------------------------------------------------------------------

/**
 * Symmetric encrypted message payload (tb1.s)
 *
 * Binary layout: [keyId(4B)][nonce(12B)][ciphertext(var)][authTag(16B)][signature(64B)]
 * Signature covers: keyId ‖ nonce ‖ ciphertext ‖ authTag
 */
export interface SymmetricMessagePayload {
  /** 4-byte key rotation identifier */
  keyId: Uint8Array;
  /** 12-byte AES-256-GCM nonce */
  nonce: Uint8Array;
  /** Variable-length AES-256-GCM ciphertext */
  ciphertext: Uint8Array;
  /** 16-byte GCM authentication tag */
  authTag: Uint8Array;
  /** 64-byte Ed25519 signature for sender authentication */
  signature: Uint8Array;
}

/**
 * Key exchange handshake payload (tb1.kx)
 *
 * Binary layout: [senderIdKey(32B)][ephemeralX25519(32B)][encryptedChatKey(var)][signature(64B)]
 */
export interface KeyExchangePayload {
  /** 32-byte Ed25519 public key of the sender (identity key) */
  senderIdKey: Uint8Array;
  /** 32-byte ephemeral X25519 public key for DH */
  ephemeralX25519: Uint8Array;
  /** Variable-length AES-256-GCM wrapped chat key */
  encryptedChatKey: Uint8Array;
  /** 64-byte Ed25519 signature over the preceding fields */
  signature: Uint8Array;
}

/**
 * Secured (asymmetric) message payload (tb1.a)
 *
 * Binary layout: [ephemeralX25519(32B)][nonce(12B)][ciphertext(var)][authTag(16B)][signature(64B)]
 */
export interface SecuredMessagePayload {
  /** 32-byte ephemeral X25519 public key */
  ephemeralX25519: Uint8Array;
  /** 12-byte AES-256-GCM nonce */
  nonce: Uint8Array;
  /** Variable-length AES-256-GCM ciphertext */
  ciphertext: Uint8Array;
  /** 16-byte GCM authentication tag */
  authTag: Uint8Array;
  /** 64-byte Ed25519 signature for sender authentication */
  signature: Uint8Array;
}

/**
 * Prekey publication payload (tb1.pk)
 *
 * Binary layout: [ed25519PubKey(32B)][x25519PubKey(32B)][signature(64B)]
 *
 * The signature covers: ed25519PubKey ‖ x25519PubKey
 * This is intentionally minimal — metadata (timestamp, version preferences)
 * can be added in a future protocol version without breaking the binary format
 * (appended before the signature with a length prefix).
 */
export interface PrekeyPublicationPayload {
  /** 32-byte Ed25519 public key (identity) */
  ed25519PublicKey: Uint8Array;
  /** 32-byte X25519 public key (for key exchange) */
  x25519PublicKey: Uint8Array;
  /** 64-byte Ed25519 signature over (ed25519PubKey ‖ x25519PubKey) */
  signature: Uint8Array;
}

// ---------------------------------------------------------------------------
// Header parsing
// ---------------------------------------------------------------------------

/** Parsed protocol header: version + mode */
export interface TelebridgeHeader {
  /** Protocol version number (e.g. 1) */
  version: number;
  /** Message mode string (e.g. 's', 'a', 'kx', 'pk') */
  mode: string;
}

// ---------------------------------------------------------------------------
// Discriminated union — TelebridgeMessage
// ---------------------------------------------------------------------------

export type TelebridgeMode = typeof MODES[keyof typeof MODES];

interface BaseMessage {
  version: number;
}

export interface SymmetricMessage extends BaseMessage {
  mode: typeof MODES.SYMMETRIC;
  payload: SymmetricMessagePayload;
}

export interface SecuredMessage extends BaseMessage {
  mode: typeof MODES.ASYMMETRIC;
  payload: SecuredMessagePayload;
}

export interface KeyExchangeMessage extends BaseMessage {
  mode: typeof MODES.KEY_EXCHANGE;
  payload: KeyExchangePayload;
}

export interface PrekeyMessage extends BaseMessage {
  mode: typeof MODES.PREKEY;
  payload: PrekeyPublicationPayload;
}

/** Discriminated union of all Telebridge message types */
export type TelebridgeMessage =
  | SymmetricMessage
  | SecuredMessage
  | KeyExchangeMessage
  | PrekeyMessage;
