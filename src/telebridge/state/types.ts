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

/** Provenance of a contact-key entry */
export type ContactKeyOrigin =
  /** First-seen via Telegram-borne tb1.pk, no explicit verification */
  | 'tofu'
  /** Established via in-person camera QR scan */
  | 'in-person-scan'
  /** Established via pair-fingerprint QR + safety-number compare */
  | 'post-hoc-qr'
  /** User pasted/uploaded a key entry from export */
  | 'imported';

/** A single per-contact key binding in the key archive */
export interface ContactKeyEntry {
  /** First 8 bytes of SHA-256(ed25519PublicKey), hex (16 chars) */
  keyId: string;
  /** Base64, 32 raw bytes */
  ed25519PublicKey: string;
  /** Base64, 32 raw bytes — prekey associated with this identity */
  x25519PublicKey: string;
  /** Provenance of this entry */
  origin: ContactKeyOrigin;
  /** Timestamp ms, when entry was appended */
  firstSeen: number;
  /** Timestamp ms, most recent successful KX or message-sig verify */
  lastUsed?: number;
  /** Timestamp ms, set when entry transitions off activeKeyId */
  archivedAt?: number;
  /** Optional user-supplied note */
  label?: string;
}

/** Per-contact public key record with TOFU tracking and key archive */
export interface ContactRecord {
  /** Telegram user id the archive is scoped to */
  userId: string;
  /** Invariant: keys.length ≥ 1 */
  keys: ContactKeyEntry[];
  /** Invariant: keys.some(k => k.keyId === activeKeyId) */
  activeKeyId: string;
  /** Top-level trust level (mirrors active entry's provenance in the UI) */
  trustLevel: ContactTrustLevel;
  /** Timestamp ms, derived from keys[0].firstSeen at creation */
  firstSeen: number;
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
  /** ContactKeyEntry.keyId this session was negotiated against */
  derivedFromKeyId: string;
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
  /** Known contacts with TOFU tracking and per-contact key archive */
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

/**
 * Current persisted state format version.
 *
 * - v1: single-key ContactRecord with { ed25519PublicKey, x25519PublicKey, keyHistory[] }.
 * - v2: per-contact key archive with { keys: ContactKeyEntry[], activeKeyId }; ChatKeyRecord gains derivedFromKeyId.
 */
export const CURRENT_FORMAT_VERSION = 2;
