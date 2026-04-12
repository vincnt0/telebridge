/**
 * Telebridge v2 — Crypto Module Barrel Export
 *
 * Single import point for all cryptographic operations:
 *   import { encrypt, decrypt, sign, verify, ... } from '../crypto';
 */

// AES-256-GCM symmetric encryption
export { decrypt, encrypt } from './aes';
// Aliases used by TelebridgeState and send pipeline
export { encrypt as aesEncrypt, decrypt as aesDecrypt } from './aes';

// Ed25519 signatures
export { generateSigningKeyPair, sign, verify } from './signing';
// Aliases used by TelebridgeState and send pipeline
export { generateSigningKeyPair as generateEd25519Keypair } from './signing';
export { sign as ed25519Sign, verify as ed25519Verify } from './signing';

// X25519 ECDH key exchange
export { computeSharedSecret, generateKeyExchangeKeyPair } from './keyexchange';

// HKDF-SHA256 key derivation
export { deriveKey } from './kdf';

// Argon2id password hashing
export { hashPassword } from './password';

// Types
export type {
  Argon2Params,
  EncryptedPayload,
  KeyPair,
} from './types';
export { DEFAULT_ARGON2_PARAMS, SIZES } from './types';

// Utilities
export {
  concatBytes,
  constantTimeEqual,
  decodeUtf8,
  encodeUtf8,
  fromBase64,
  fromHex,
  randomBytes,
  secureWipe,
  toBase64,
  toHex,
} from './utils';
