/**
 * Telebridge v2 — Protocol Module Barrel Export
 *
 * Public API for message encoding, decoding, detection, and constants.
 * Import from 'src/telebridge/protocol' only.
 */

// Types
export type {
  KeyExchangeMessage,
  KeyExchangePayload,
  PrekeyMessage,
  PrekeyPublicationPayload,
  SecuredMessage,
  SecuredMessagePayload,
  SymmetricMessage,
  SymmetricMessagePayload,
  TelebridgeHeader,
  TelebridgeMessage,
  TelebridgeMode,
} from './types';

// Detection & parsing
export {
  getPayloadBase64,
  isTelebridgeMachineMessage,
  isTelebridgeMessage,
  parseHeader,
} from './detect';

// Encoding
export {
  encodeKeyExchange,
  encodeMessage,
  encodePrekeyPublication,
  encodeSecuredMessage,
  encodeSymmetricMessage,
} from './encode';

// Decoding
export {
  decodeKeyExchange,
  decodeMessage,
  decodePrekeyPublication,
  decodeSecuredMessage,
  decodeSymmetricMessage,
} from './decode';

// Constants
export {
  FIELD_SIZES,
  HEADER_PATTERN,
  MIN_PAYLOAD_SIZES,
  MODES,
  PROTOCOL_VERSION,
  SEPARATOR,
  TELEBRIDGE_PREFIX,
  VALID_MODES,
} from './constants';
