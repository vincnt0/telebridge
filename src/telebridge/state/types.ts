/**
 * Telebridge v2 — State Types
 *
 * All TypeScript interfaces for TelebridgeState lifecycle.
 * Binary data is Uint8Array internally; base64 strings for persistence only.
 */

/** Trust level for a known contact's public key */
export enum ContactTrustLevel {
  /** Key accepted on first encounter (TOFU) */
  Initial = 'initial',
  /** Key changed since first seen — needs re-verification */
  Changed = 'changed',
  /** Key manually verified (QR code or safety number) */
  Verified = 'verified',
}

/** Historical record of a contact's key change */
export interface ContactKeyHistoryEntry {
  ed25519PublicKey: string; // base64
  x25519PublicKey: string; // base64
  seenAt: number; // timestamp ms
}

/** Per-contact public key record with TOFU tracking */
export interface ContactRecord {
  ed25519PublicKey: string; // base64
  x25519PublicKey: string; // base64
  trustLevel: ContactTrustLevel;
  firstSeen: number; // timestamp ms
  verifiedAt?: number; // timestamp ms, set when manually verified
  keyHistory: ContactKeyHistoryEntry[];
}

/** Per-chat key metadata */
export interface ChatKeyRecord {
  /** Encrypted chat key (base64 of AES-GCM encrypted payload) */
  encryptedKey: string;
  /** 4-byte key identifier (hex) */
  keyId: string;
  /** Timestamp of key establishment */
  established: number;
  /** Current rotation version (increments on each rotation) */
  rotationVersion: number;
  /** Timestamp of last rotation */
  lastRotatedAt: number;
  /** Previous encrypted key (for migration window) */
  previousEncryptedKey?: string;
  /** Previous key ID */
  previousKeyId?: string;
  /** Number of messages encrypted with this key (for rotation tracking) */
  messageCount: number;
}

/** Identity keypair — public keys always available, private keys only when unlocked */
export interface IdentityKeys {
  /** Ed25519 public key (base64) — always persisted */
  ed25519PublicKey: string;
  /** X25519 public key (base64) — always persisted */
  x25519PublicKey: string;
  /** Encrypted Ed25519 private key (base64 of AES-GCM encrypted payload) */
  encryptedEd25519PrivateKey: string;
  /** Encrypted X25519 private key (base64 of AES-GCM encrypted payload) */
  encryptedX25519PrivateKey: string;
}

/** Argon2id parameters stored alongside the password hash */
export interface StoredArgon2Params {
  memoryCost: number;
  timeCost: number;
  parallelism: number;
  hashLength: number;
}

/** Persisted state format — ONLY encrypted/public data, NEVER plaintext secrets */
export interface PersistedState {
  /** Format version for future migration */
  formatVersion: number;
  /** Argon2id parameters used for key derivation */
  argon2Params: StoredArgon2Params;
  /** Random salt for Argon2id (base64) */
  passwordSalt: string;
  /** Encrypted verifier blob for password validation (base64 of AES-GCM encrypted payload) */
  passwordVerifier: string;
  /** Identity keys (public + encrypted private) */
  identity?: IdentityKeys;
  /** Per-chat encrypted keys */
  chatKeys: Record<string, ChatKeyRecord>;
  /** Known contacts with TOFU tracking */
  contacts: Record<string, ContactRecord>;
  /** Key rotation configuration */
  rotationConfig?: { maxMessages: number; maxDays: number };
  /** Current protocol version */
  protocolVersion: number;
  /** Supported protocol versions */
  supportedVersions: number[];
}

/** Decrypted identity keys held in memory only while unlocked */
export interface DecryptedIdentity {
  ed25519PublicKey: Uint8Array;
  ed25519PrivateKey: Uint8Array;
  x25519PublicKey: Uint8Array;
  x25519PrivateKey: Uint8Array;
}

/** Decrypted chat key held in memory only while unlocked */
export interface DecryptedChatKey {
  key: Uint8Array;
  keyId: string;
  established: number;
  rotationVersion: number;
  lastRotatedAt: number;
  previousKey?: Uint8Array;
  previousKeyId?: string;
  messageCount: number;
}

/** Rotation info returned to consumers */
export interface RotationInfo {
  keyId: string;
  rotationVersion: number;
  lastRotatedAt: number;
  hasPreviousKey: boolean;
  previousKeyId?: string;
}

/** Fields that must NEVER appear in persisted state */
export const PLAINTEXT_FIELD_NAMES = [
  'derivedKey',
  'password',
  'ed25519PrivateKey',
  'x25519PrivateKey',
  'privateKey',
  'decryptedKey',
  'plaintext',
] as const;

/** Current persisted state format version */
export const CURRENT_FORMAT_VERSION = 1;
