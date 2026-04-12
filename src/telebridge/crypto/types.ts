/**
 * Telebridge v2 — Cryptographic Types
 *
 * V1 BUGS TO AVOID (guardrails from V1_SYSTEM_SPEC §2):
 * - GCM auth tags silently discarded → auth tags are MANDATORY in EncryptedPayload
 * - decipher.final() commented out → always finalize GCM (Web Crypto handles this)
 * - Text vs buffer used different key derivation (single vs double SHA-256) → single HKDF path for all
 * - selectCurrentChat() for download key lookup → always use message.chatId
 * - Plaintext keys cached to disk → only encrypted fields persist
 * - No key stretching (bare SHA-256) → Argon2id with proper parameters
 * - Password stored in global state → derived key in memory only, password discarded
 * - var throughout → const/let
 * - Direct global state mutation → immutable updates
 *
 * All binary data is represented as Uint8Array internally.
 * No Buffer, no hex/base64 strings in the crypto API surface.
 */

/** Generic asymmetric key pair */
export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * AES-256-GCM encrypted payload with MANDATORY auth tag.
 *
 * The auth tag is always present and always verified on decrypt.
 * This is non-negotiable — v1 discarded auth tags, effectively
 * downgrading AES-256-GCM to AES-256-CTR with no authentication.
 */
export interface EncryptedPayload {
  /** 12-byte random IV/nonce (standard GCM nonce size) */
  iv: Uint8Array;
  /** Encrypted data (without auth tag) */
  ciphertext: Uint8Array;
  /** 16-byte GCM authentication tag — MANDATORY, never optional */
  authTag: Uint8Array;
}

/** Argon2id parameters */
export interface Argon2Params {
  /** Memory cost in KiB (default: 65536 = 64 MiB) */
  memoryCost?: number;
  /** Time cost / iterations (default: 3) */
  timeCost?: number;
  /** Parallelism (default: 1 for browser compatibility) */
  parallelism?: number;
  /** Output hash length in bytes (default: 32) */
  hashLength?: number;
}

/** Default Argon2id parameters — sensible defaults for browser use */
export const DEFAULT_ARGON2_PARAMS: Required<Argon2Params> = {
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
};

/** Standard key/nonce/tag sizes */
export const SIZES = {
  AES_KEY: 32,
  GCM_NONCE: 12,
  GCM_TAG: 16,
  ED25519_PUBLIC_KEY: 32,
  ED25519_PRIVATE_KEY: 32,
  ED25519_SIGNATURE: 64,
  X25519_PUBLIC_KEY: 32,
  X25519_PRIVATE_KEY: 32,
  X25519_SHARED_SECRET: 32,
  HKDF_DEFAULT_OUTPUT: 32,
  ARGON2_SALT: 16,
} as const;
