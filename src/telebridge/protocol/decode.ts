/**
 * Telebridge v2 — Message Decoding
 *
 * Deserializes wire-format strings back into structured payload objects.
 * Validates headers, decodes base64, and splits binary payloads by known field sizes.
 *
 * This is pure deserialization — no crypto operations happen here.
 */

import { fromBase64 } from '../crypto/utils';
import {
  FIELD_SIZES,
  MIN_PAYLOAD_SIZES,
  MODES,
  PROTOCOL_VERSION,
} from './constants';
import { getPayloadBase64, parseHeader } from './detect';
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

/**
 * Validate header and extract raw binary payload from a wire-format string.
 * Throws descriptive errors for each failure mode.
 */
function extractPayload(wire: string, expectedMode: string): Uint8Array {
  const header = parseHeader(wire);
  if (!header) {
    throw new Error('Invalid Telebridge message: unrecognized header format');
  }
  if (header.version !== PROTOCOL_VERSION) {
    throw new Error(`Unsupported protocol version: ${header.version} (expected ${PROTOCOL_VERSION})`);
  }
  if (header.mode !== expectedMode) {
    throw new Error(`Mode mismatch: expected '${expectedMode}', got '${header.mode}'`);
  }

  const base64 = getPayloadBase64(wire);
  if (!base64) {
    throw new Error('Invalid Telebridge message: empty payload');
  }

  let bytes: Uint8Array;
  try {
    bytes = fromBase64(base64);
  } catch {
    throw new Error('Invalid Telebridge message: payload is not valid base64');
  }

  return bytes;
}

// ---------------------------------------------------------------------------
// Per-type decoders
// ---------------------------------------------------------------------------

/**
 * Decode a symmetric (Layer 3) message from wire format.
 *
 * Binary layout: [keyId(4B)][nonce(12B)][ciphertext(var)][authTag(16B)][signature(64B)]
 */
export function decodeSymmetricMessage(wire: string): SymmetricMessagePayload {
  const bytes = extractPayload(wire, MODES.SYMMETRIC);

  if (bytes.length < MIN_PAYLOAD_SIZES.SYMMETRIC) {
    throw new Error(
      `Symmetric message payload too short: ${bytes.length} bytes `
      + `(minimum ${MIN_PAYLOAD_SIZES.SYMMETRIC} for fixed fields)`,
    );
  }

  const ciphertextLength = bytes.length - MIN_PAYLOAD_SIZES.SYMMETRIC;
  if (ciphertextLength === 0) {
    throw new Error('Symmetric message has empty ciphertext');
  }

  let offset = 0;

  const keyId = bytes.slice(offset, offset + FIELD_SIZES.KEY_ID);
  offset += FIELD_SIZES.KEY_ID;

  const nonce = bytes.slice(offset, offset + FIELD_SIZES.NONCE);
  offset += FIELD_SIZES.NONCE;

  const ciphertext = bytes.slice(offset, offset + ciphertextLength);
  offset += ciphertextLength;

  const authTag = bytes.slice(offset, offset + FIELD_SIZES.AUTH_TAG);
  offset += FIELD_SIZES.AUTH_TAG;

  const signature = bytes.slice(offset, offset + FIELD_SIZES.ED25519_SIGNATURE);

  return { keyId, nonce, ciphertext, authTag, signature };
}

/**
 * Decode a secured (Layer 4) asymmetric message from wire format.
 *
 * Binary layout: [ephemeralX25519(32B)][nonce(12B)][ciphertext(var)][authTag(16B)][signature(64B)]
 */
export function decodeSecuredMessage(wire: string): SecuredMessagePayload {
  const bytes = extractPayload(wire, MODES.ASYMMETRIC);

  if (bytes.length < MIN_PAYLOAD_SIZES.ASYMMETRIC) {
    throw new Error(
      `Secured message payload too short: ${bytes.length} bytes `
      + `(minimum ${MIN_PAYLOAD_SIZES.ASYMMETRIC} for fixed fields)`,
    );
  }

  const ciphertextLength = bytes.length - MIN_PAYLOAD_SIZES.ASYMMETRIC;
  if (ciphertextLength === 0) {
    throw new Error('Secured message has empty ciphertext');
  }

  let offset = 0;

  const ephemeralX25519 = bytes.slice(offset, offset + FIELD_SIZES.X25519_PUBLIC_KEY);
  offset += FIELD_SIZES.X25519_PUBLIC_KEY;

  const nonce = bytes.slice(offset, offset + FIELD_SIZES.NONCE);
  offset += FIELD_SIZES.NONCE;

  const ciphertext = bytes.slice(offset, offset + ciphertextLength);
  offset += ciphertextLength;

  const authTag = bytes.slice(offset, offset + FIELD_SIZES.AUTH_TAG);
  offset += FIELD_SIZES.AUTH_TAG;

  const signature = bytes.slice(offset, offset + FIELD_SIZES.ED25519_SIGNATURE);

  return { ephemeralX25519, nonce, ciphertext, authTag, signature };
}

/**
 * Decode a key exchange handshake from wire format.
 *
 * Binary layout: [senderIdKey(32B)][ephemeralX25519(32B)][encryptedChatKey(var)][signature(64B)]
 *
 * Note: encryptedChatKey may be empty (zero bytes) — the spec does not mandate
 * a minimum ciphertext length for kx messages since the handshake structure
 * varies by protocol phase.
 */
export function decodeKeyExchange(wire: string): KeyExchangePayload {
  const bytes = extractPayload(wire, MODES.KEY_EXCHANGE);

  if (bytes.length < MIN_PAYLOAD_SIZES.KEY_EXCHANGE) {
    throw new Error(
      `Key exchange payload too short: ${bytes.length} bytes `
      + `(minimum ${MIN_PAYLOAD_SIZES.KEY_EXCHANGE} for fixed fields)`,
    );
  }

  const encryptedChatKeyLength = bytes.length - MIN_PAYLOAD_SIZES.KEY_EXCHANGE;

  let offset = 0;

  const senderIdKey = bytes.slice(offset, offset + FIELD_SIZES.ED25519_PUBLIC_KEY);
  offset += FIELD_SIZES.ED25519_PUBLIC_KEY;

  const ephemeralX25519 = bytes.slice(offset, offset + FIELD_SIZES.X25519_PUBLIC_KEY);
  offset += FIELD_SIZES.X25519_PUBLIC_KEY;

  const encryptedChatKey = bytes.slice(offset, offset + encryptedChatKeyLength);
  offset += encryptedChatKeyLength;

  const signature = bytes.slice(offset, offset + FIELD_SIZES.ED25519_SIGNATURE);

  return { senderIdKey, ephemeralX25519, encryptedChatKey, signature };
}

/**
 * Decode a prekey publication from wire format.
 *
 * Binary layout: [ed25519PubKey(32B)][x25519PubKey(32B)][signature(64B)]
 *
 * This is a fixed-size payload — exactly 128 bytes.
 */
export function decodePrekeyPublication(wire: string): PrekeyPublicationPayload {
  const bytes = extractPayload(wire, MODES.PREKEY);

  if (bytes.length !== MIN_PAYLOAD_SIZES.PREKEY) {
    throw new Error(
      `Prekey publication payload invalid size: ${bytes.length} bytes `
      + `(expected exactly ${MIN_PAYLOAD_SIZES.PREKEY})`,
    );
  }

  let offset = 0;

  const ed25519PublicKey = bytes.slice(offset, offset + FIELD_SIZES.ED25519_PUBLIC_KEY);
  offset += FIELD_SIZES.ED25519_PUBLIC_KEY;

  const x25519PublicKey = bytes.slice(offset, offset + FIELD_SIZES.X25519_PUBLIC_KEY);
  offset += FIELD_SIZES.X25519_PUBLIC_KEY;

  const signature = bytes.slice(offset, offset + FIELD_SIZES.ED25519_SIGNATURE);

  return { ed25519PublicKey, x25519PublicKey, signature };
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/**
 * Decode any Telebridge wire-format string into its typed message struct.
 * Detects the mode from the header and dispatches to the correct decoder.
 */
export function decodeMessage(wire: string): TelebridgeMessage {
  const header = parseHeader(wire);
  if (!header) {
    throw new Error('Invalid Telebridge message: unrecognized header format');
  }
  if (header.version !== PROTOCOL_VERSION) {
    throw new Error(`Unsupported protocol version: ${header.version} (expected ${PROTOCOL_VERSION})`);
  }

  switch (header.mode) {
    case MODES.SYMMETRIC:
      return {
        version: header.version,
        mode: MODES.SYMMETRIC,
        payload: decodeSymmetricMessage(wire),
      };
    case MODES.ASYMMETRIC:
      return {
        version: header.version,
        mode: MODES.ASYMMETRIC,
        payload: decodeSecuredMessage(wire),
      };
    case MODES.KEY_EXCHANGE:
      return {
        version: header.version,
        mode: MODES.KEY_EXCHANGE,
        payload: decodeKeyExchange(wire),
      };
    case MODES.PREKEY:
      return {
        version: header.version,
        mode: MODES.PREKEY,
        payload: decodePrekeyPublication(wire),
      };
    default:
      throw new Error(`Unknown Telebridge message mode: '${header.mode}'`);
  }
}
