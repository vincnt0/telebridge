/**
 * Telebridge v2 — State Serialization
 *
 * Serialize/deserialize TelebridgeState to/from a persistable JSON format.
 * CRITICAL: Only encrypted fields make it to the output.
 * Includes format version for future migration.
 */

import { sha256 } from '@noble/hashes/sha2.js';

import { fromBase64 } from '../crypto';

import type {
  ChatKeyRecord,
  ContactKeyEntry,
  ContactKeyOrigin,
  ContactRecord,
  PersistedState,
} from './types';
import { ContactTrustLevel, CURRENT_FORMAT_VERSION } from './types';
import { assertNoPlaintextSecrets } from './validation';

/**
 * Derive the short content-addressable keyId used by ContactKeyEntry.
 * First 8 bytes of SHA-256(ed25519PublicKey), hex (16 chars).
 */
export function deriveKeyId(ed25519PublicKeyBase64: string): string {
  const pub = fromBase64(ed25519PublicKeyBase64);
  const digest = sha256(pub);
  return Array.from(digest.slice(0, 8))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Legacy (pre-v2) ContactKeyHistoryEntry — read only, for migration. */
interface LegacyContactKeyHistoryEntry {
  ed25519PublicKey: string;
  x25519PublicKey: string;
  seenAt: number;
}

/** Legacy (pre-v2) ContactRecord shape — read only, for migration. */
interface LegacyContactRecord {
  ed25519PublicKey: string;
  x25519PublicKey: string;
  trustLevel: ContactTrustLevel;
  firstSeen: number;
  verifiedAt?: number;
  keyHistory?: LegacyContactKeyHistoryEntry[];
}

/** Legacy (pre-v2) ChatKeyRecord shape — read only, for migration. */
interface LegacyChatKeyRecord {
  encryptedKey: string;
  keyId: string;
  established: number;
  rotationVersion: number;
  lastRotatedAt: number;
  previousEncryptedKey?: string;
  previousKeyId?: string;
  messageCount?: number;
}

/** Map a legacy trustLevel to the origin tag for the migrated active entry. */
function inferOriginFromTrustLevel(trustLevel: ContactTrustLevel): ContactKeyOrigin {
  if (trustLevel === ContactTrustLevel.Verified) return 'post-hoc-qr';
  // Initial and Changed both migrate as TOFU; the scan/import tags didn't
  // exist pre-v2.
  return 'tofu';
}

/** Convert a single legacy ContactRecord into the v2 archive shape. */
export function migrateContactRecord(userId: string, old: LegacyContactRecord): ContactRecord {
  const origin = inferOriginFromTrustLevel(old.trustLevel);
  const keyId = deriveKeyId(old.ed25519PublicKey);
  const entry: ContactKeyEntry = {
    keyId,
    ed25519PublicKey: old.ed25519PublicKey,
    x25519PublicKey: old.x25519PublicKey,
    origin,
    firstSeen: old.firstSeen,
    lastUsed: old.verifiedAt ?? old.firstSeen,
  };
  return {
    userId,
    keys: [entry],
    activeKeyId: keyId,
    trustLevel: old.trustLevel,
    firstSeen: old.firstSeen,
  };
}

/**
 * Stamp a legacy ChatKeyRecord with derivedFromKeyId from the matching
 * contact's active key. Orphan chats (no contact record) get empty string.
 */
export function migrateChatKeyRecord(
  peerUserId: string,
  old: LegacyChatKeyRecord,
  contacts: Record<string, ContactRecord>,
): ChatKeyRecord {
  const contact = contacts[peerUserId];
  return {
    encryptedKey: old.encryptedKey,
    keyId: old.keyId,
    established: old.established,
    rotationVersion: old.rotationVersion,
    lastRotatedAt: old.lastRotatedAt,
    previousEncryptedKey: old.previousEncryptedKey,
    previousKeyId: old.previousKeyId,
    messageCount: old.messageCount ?? 0,
    derivedFromKeyId: contact ? contact.activeKeyId : '',
  };
}

/** Full v1 → v2 migration pass. */
function migrateV1ToV2(state: Record<string, unknown>): void {
  // Contacts: legacy flat record → { keys[], activeKeyId }.
  const migratedContacts: Record<string, ContactRecord> = {};
  const rawContacts = state.contacts as Record<string, LegacyContactRecord> | undefined;
  if (rawContacts) {
    for (const [userId, legacy] of Object.entries(rawContacts)) {
      migratedContacts[userId] = migrateContactRecord(userId, legacy);
    }
  }
  state.contacts = migratedContacts;

  // Chat keys: stamp derivedFromKeyId from the matching contact's active key.
  const migratedChatKeys: Record<string, ChatKeyRecord> = {};
  const rawChatKeys = state.chatKeys as Record<string, LegacyChatKeyRecord> | undefined;
  if (rawChatKeys) {
    for (const [chatId, legacy] of Object.entries(rawChatKeys)) {
      // 1:1 chats: chatId === peer user id. We use the chatId as the lookup
      // key against migratedContacts. Group chats or any chat without a
      // matching contact become orphans (derivedFromKeyId = '').
      migratedChatKeys[chatId] = migrateChatKeyRecord(chatId, legacy, migratedContacts);
    }
  }
  state.chatKeys = migratedChatKeys;

  state.formatVersion = 2;
}

/**
 * Serialize persisted state to a JSON string.
 * Validates that no plaintext secrets are present before serialization.
 *
 * @param state - The persisted state object (must contain only encrypted/public data)
 * @returns JSON string safe for storage
 * @throws If plaintext secrets are detected
 */
export function serialize(state: PersistedState): string {
  // Safety net: scan for plaintext secrets before writing
  assertNoPlaintextSecrets(state);

  return JSON.stringify(state);
}

/**
 * Deserialize a JSON string to persisted state.
 * Validates format version, runs migrations, and returns the v-current shape.
 *
 * @param json - JSON string from storage
 * @returns Parsed PersistedState
 * @throws If format is invalid or newer than this client supports
 */
export function deserialize(json: string): PersistedState {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error('Invalid persisted state: not valid JSON');
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Invalid persisted state: not an object');
  }

  const state = parsed as Record<string, unknown>;

  if (typeof state.formatVersion !== 'number') {
    throw new Error('Invalid persisted state: missing formatVersion');
  }

  if (state.formatVersion > CURRENT_FORMAT_VERSION) {
    throw new Error('Vault was written by a newer version of Telebridge.');
  }

  if (state.formatVersion < 1) {
    throw new Error(`Invalid format version: ${state.formatVersion}`);
  }

  // Validate required fields before migrating — migrations assume the core
  // scaffold is well-formed.
  if (typeof state.passwordSalt !== 'string') {
    throw new Error('Invalid persisted state: missing passwordSalt');
  }
  if (typeof state.passwordVerifier !== 'string') {
    throw new Error('Invalid persisted state: missing passwordVerifier');
  }
  if (typeof state.argon2Params !== 'object' || state.argon2Params === null) {
    throw new Error('Invalid persisted state: missing argon2Params');
  }

  // Migrate in-place so older clients' blobs land on the current shape.
  if (state.formatVersion === 1) {
    migrateV1ToV2(state);
  }

  return state as unknown as PersistedState;
}

/**
 * Create an empty persisted state scaffold.
 * Used for first-run initialization before any keys are generated.
 */
export function createEmptyPersistedState(): PersistedState {
  return {
    formatVersion: CURRENT_FORMAT_VERSION,
    argon2Params: {
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 1,
      hashLength: 32,
    },
    passwordSalt: '',
    passwordVerifier: '',
    chatKeys: {},
    contacts: {},
    protocolVersion: 1,
    supportedVersions: [1],
  };
}
