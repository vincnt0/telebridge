/**
 * Telebridge v2 — Message Encoding
 *
 * Serializes structured payload objects into wire-format strings.
 * Format: tb<version>.<mode>.<base64_payload>
 *
 * This is pure serialization — no crypto operations happen here.
 * Binary fields are concatenated in spec-defined order, then base64-encoded.
 */

import { concatBytes, toBase64 } from '../crypto/utils';
import { MODES, PROTOCOL_VERSION, SEPARATOR, TELEBRIDGE_PREFIX } from './constants';
import type {
  KeyExchangePayload,
  PrekeyPublicationPayload,
  SecuredMessagePayload,
  SymmetricMessagePayload,
  TelebridgeMessage,
} from './types';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Build the wire-format header string: "tb1.s." etc. */
function buildHeader(mode: string): string {
  return `${TELEBRIDGE_PREFIX}${PROTOCOL_VERSION}${SEPARATOR}${mode}${SEPARATOR}`;
}

// ---------------------------------------------------------------------------
// Per-type encoders
// ---------------------------------------------------------------------------

/**
 * Encode a symmetric (Layer 3) message payload.
 *
 * Binary layout: [keyId(4B)][nonce(12B)][ciphertext(var)][authTag(16B)][signature(64B)]
 */
export function encodeSymmetricMessage(payload: SymmetricMessagePayload): string {
  const binary = concatBytes(
    payload.keyId,
    payload.nonce,
    payload.ciphertext,
    payload.authTag,
    payload.signature,
  );
  return buildHeader(MODES.SYMMETRIC) + toBase64(binary);
}

/**
 * Encode a secured (Layer 4) asymmetric message payload.
 *
 * Binary layout: [ephemeralX25519(32B)][nonce(12B)][ciphertext(var)][authTag(16B)][signature(64B)]
 */
export function encodeSecuredMessage(payload: SecuredMessagePayload): string {
  const binary = concatBytes(
    payload.ephemeralX25519,
    payload.nonce,
    payload.ciphertext,
    payload.authTag,
    payload.signature,
  );
  return buildHeader(MODES.ASYMMETRIC) + toBase64(binary);
}

/**
 * Encode a key exchange handshake payload.
 *
 * Binary layout: [senderIdKey(32B)][ephemeralX25519(32B)][encryptedChatKey(var)][signature(64B)]
 */
export function encodeKeyExchange(payload: KeyExchangePayload): string {
  const binary = concatBytes(
    payload.senderIdKey,
    payload.ephemeralX25519,
    payload.encryptedChatKey,
    payload.signature,
  );
  return buildHeader(MODES.KEY_EXCHANGE) + toBase64(binary);
}

/**
 * Encode a prekey publication payload.
 *
 * Binary layout: [ed25519PubKey(32B)][x25519PubKey(32B)][signature(64B)]
 */
export function encodePrekeyPublication(payload: PrekeyPublicationPayload): string {
  const binary = concatBytes(
    payload.ed25519PublicKey,
    payload.x25519PublicKey,
    payload.signature,
  );
  return buildHeader(MODES.PREKEY) + toBase64(binary);
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/** Encode any TelebridgeMessage into its wire-format string. */
export function encodeMessage(message: TelebridgeMessage): string {
  switch (message.mode) {
    case MODES.SYMMETRIC:
      return encodeSymmetricMessage(message.payload);
    case MODES.ASYMMETRIC:
      return encodeSecuredMessage(message.payload);
    case MODES.KEY_EXCHANGE:
      return encodeKeyExchange(message.payload);
    case MODES.PREKEY:
      return encodePrekeyPublication(message.payload);
    default:
      throw new Error(`Unknown Telebridge message mode: ${(message as TelebridgeMessage).mode}`);
  }
}
