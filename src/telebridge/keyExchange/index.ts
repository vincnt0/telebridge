/**
 * Telebridge v2 — Key Exchange Module
 *
 * Public API for Layer 2 key exchange protocol:
 * - Initiator flow (generate + wrap + sign → tb1.kx)
 * - Responder flow (decode + verify + unwrap → chat key)
 * - Rotation logic (threshold checks + re-exchange)
 */

export { initiateKeyExchange } from './initiate';
export { respondToKeyExchange } from './respond';
export { performRotation, shouldRotate } from './rotation';
export type {
  KeyExchangeInitiation,
  KeyExchangeResponse,
  RotationCheck,
  RotationConfig,
} from './types';
export { DEFAULT_ROTATION_CONFIG } from './types';
