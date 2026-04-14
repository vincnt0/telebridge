/**
 * Telebridge v2 — TelebridgeState
 *
 * The secure vault managing the full lifecycle of user cryptographic state:
 * - First-run setup (password, identity keypair, persistence)
 * - Lock/unlock with password-derived key
 * - Password changes with full re-encryption
 * - Identity keypair (Ed25519 + X25519) encrypted at rest
 * - Chat key storage (encrypted, per-chat)
 * - Contact key storage with TOFU tracking
 * - Key rotation tracking
 *
 * Security invariants:
 * - derivedKey exists ONLY in memory while unlocked
 * - On lock, all plaintext secrets are securely wiped (zeroed)
 * - Persisted state NEVER contains plaintext keys, derivedKey, or password
 *
 * V1 bugs explicitly fixed:
 * - Proper Argon2id key derivation (not bare SHA-256)
 * - Actual decrypt on unlock (not copy-encrypted-as-plaintext)
 * - Password discarded after derivation (not stored in global state)
 * - Auth tags mandatory on all AES-GCM operations
 * - Single consistent key derivation path
 */

import { x25519 } from '@noble/curves/ed25519.js';

import {
  aesDecrypt,
  aesEncrypt,
  ed25519Sign,
  ed25519Verify,
  generateEd25519Keypair,
  hashPassword,
  randomBytes,
  secureWipe,
  toBase64,
  fromBase64,
  concatBytes,
  encodeUtf8,
  constantTimeEqual,
} from '../crypto';
import type { EncryptedPayload } from '../crypto';

import { serialize, deserialize, createEmptyPersistedState, deriveKeyId } from './serialization';
import type {
  PersistedState,
  DecryptedIdentity,
  DecryptedChatKey,
  ContactKeyEntry,
  ContactRecord,
  ContactSummary,
  ImportResult,
  RotationInfo,
  ScanResult,
} from './types';
import {
  ContactTrustLevel,
  CURRENT_FORMAT_VERSION,
} from './types';
import { assertNoPlaintextSecrets } from './validation';

/** Known verifier plaintext — used to validate password correctness */
const VERIFIER_PLAINTEXT = encodeUtf8('telebridge-v2-verifier');

/**
 * Argon2id parameters used for first-run key derivation.
 *
 * Production values (64 MiB, 3 iterations) give ~20s per derivation on a
 * typical laptop — correct and painful. Under `APP_ENV=test` we downshift to
 * 1 MiB / 1 iteration (~10 ms) so the test suite finishes in minutes rather
 * than hours. Production builds never take this branch: webpack strips
 * `process.env.APP_ENV` comparisons and jest is the only environment that
 * sets the flag (see `jest.config.js` + `cross-env APP_ENV=test`).
 *
 * Persisted state stores the params used at initialize() time, so unlock()
 * and changePassword() auto-match without caring whether we're in test mode.
 */
const INIT_ARGON2_PARAMS: { memoryCost: number; timeCost: number; parallelism: number; hashLength: number } =
  typeof process !== 'undefined' && process.env?.APP_ENV === 'test'
    ? { memoryCost: 1024, timeCost: 1, parallelism: 1, hashLength: 32 }
    : { memoryCost: 65536, timeCost: 3, parallelism: 1, hashLength: 32 };

/**
 * Encode an EncryptedPayload as a single base64 string.
 * Format: [iv (12 bytes)][ciphertext (variable)][authTag (16 bytes)]
 */
function encodeEncryptedPayload(payload: EncryptedPayload): string {
  return toBase64(concatBytes(payload.iv, payload.ciphertext, payload.authTag));
}

/**
 * Decode a base64 string back to an EncryptedPayload.
 * Splits the fixed-size iv (12B) and authTag (16B) off either end;
 * the remainder is the variable-length ciphertext.
 */
function decodeEncryptedPayload(encoded: string): EncryptedPayload {
  const bytes = fromBase64(encoded);
  if (bytes.length < 12 + 1 + 16) {
    throw new Error('Encrypted payload too short');
  }
  return {
    iv: bytes.slice(0, 12),
    ciphertext: bytes.slice(12, bytes.length - 16),
    authTag: bytes.slice(bytes.length - 16),
  };
}

/**
 * Derive X25519 keypair from Ed25519 private key seed.
 * Ed25519 private key (seed, 32 bytes) can deterministically produce
 * an X25519 private key. We use the same seed for both.
 *
 * NOTE: @noble/curves ed25519 seed is 32 bytes. The X25519 private key
 * is also 32 bytes. We derive it by using the ed25519 seed directly
 * as the x25519 private key material (standard practice per RFC 7748 §6).
 */
function deriveX25519FromEd25519Seed(ed25519Seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array } {
  // Ed25519 seed (32 bytes) is directly usable as X25519 private key material
  const x25519PrivateKey = ed25519Seed.slice(); // Copy to avoid aliasing
  const x25519PublicKey = x25519.getPublicKey(x25519PrivateKey) as Uint8Array;
  return { publicKey: x25519PublicKey, privateKey: x25519PrivateKey };
}

export class TelebridgeState {
  /** Persisted state — safe to write to disk */
  private persisted: PersistedState;

  /** Derived key from Argon2id — in memory only while unlocked */
  private derivedKey: Uint8Array | undefined;

  /** Decrypted identity keys — in memory only while unlocked */
  private identity: DecryptedIdentity | undefined;

  /** Decrypted chat keys — in memory only while unlocked */
  private chatKeys: Map<string, DecryptedChatKey> = new Map();

  /** Whether the state has been initialized (first-run complete) */
  private initialized = false;

  constructor() {
    this.persisted = createEmptyPersistedState();
  }

  // ---------------------------------------------------------------------------
  // Initialization
  // ---------------------------------------------------------------------------

  /**
   * First-run setup: derive key from password, generate identity keypair,
   * encrypt everything, produce persistable state.
   *
   * @param password - User's chosen bridge password
   * @returns Serialized persisted state (safe to write to disk)
   */
  async initialize(password: string): Promise<string> {
    if (this.initialized) {
      throw new Error('TelebridgeState already initialized. Use changePassword() or load().');
    }

    const salt = randomBytes(32);

    // Derive key via Argon2id
    const derivedKey = await hashPassword(password, salt, INIT_ARGON2_PARAMS);

    // Generate Ed25519 identity keypair
    const ed25519Keypair = generateEd25519Keypair();

    // Derive X25519 keypair from Ed25519 seed
    const x25519Keypair = deriveX25519FromEd25519Seed(ed25519Keypair.privateKey);

    // Encrypt private keys with derived key
    const encryptedEd25519Private = await aesEncrypt(ed25519Keypair.privateKey, derivedKey);
    const encryptedX25519Private = await aesEncrypt(x25519Keypair.privateKey, derivedKey);

    // Create encrypted verifier (for password validation on unlock)
    const encryptedVerifier = await aesEncrypt(VERIFIER_PLAINTEXT, derivedKey);

    // Build persisted state
    this.persisted = {
      formatVersion: CURRENT_FORMAT_VERSION,
      argon2Params: { ...INIT_ARGON2_PARAMS },
      passwordSalt: toBase64(salt),
      passwordVerifier: encodeEncryptedPayload(encryptedVerifier),
      identity: {
        ed25519PublicKey: toBase64(ed25519Keypair.publicKey),
        x25519PublicKey: toBase64(x25519Keypair.publicKey),
        encryptedEd25519PrivateKey: encodeEncryptedPayload(encryptedEd25519Private),
        encryptedX25519PrivateKey: encodeEncryptedPayload(encryptedX25519Private),
      },
      chatKeys: {},
      contacts: {},
      protocolVersion: 1,
      supportedVersions: [1],
    };

    // Set in-memory state
    this.derivedKey = derivedKey;
    this.identity = {
      ed25519PublicKey: ed25519Keypair.publicKey,
      ed25519PrivateKey: ed25519Keypair.privateKey,
      x25519PublicKey: x25519Keypair.publicKey,
      x25519PrivateKey: x25519Keypair.privateKey,
    };
    this.chatKeys = new Map();
    this.initialized = true;

    return serialize(this.persisted);
  }

  /**
   * Load from persisted state (e.g., from disk). State remains locked
   * until unlock() is called.
   */
  load(json: string): void {
    this.persisted = deserialize(json);
    this.initialized = true;
    // Remain locked — derivedKey and plaintext keys are not populated
    this.derivedKey = undefined;
    this.identity = undefined;
    this.chatKeys = new Map();
  }

  // ---------------------------------------------------------------------------
  // Lock / Unlock
  // ---------------------------------------------------------------------------

  /**
   * Lock the vault: wipe all plaintext secrets from memory.
   */
  lock(): void {
    // Wipe derived key
    if (this.derivedKey) {
      secureWipe(this.derivedKey);
      this.derivedKey = undefined;
    }

    // Wipe identity private keys
    if (this.identity) {
      secureWipe(this.identity.ed25519PrivateKey);
      secureWipe(this.identity.x25519PrivateKey);
      this.identity = undefined;
    }

    // Wipe all decrypted chat keys
    for (const [, chatKey] of this.chatKeys) {
      secureWipe(chatKey.key);
      if (chatKey.previousKey) {
        secureWipe(chatKey.previousKey);
      }
    }
    this.chatKeys = new Map();
  }

  /**
   * Unlock the vault: derive key from password, validate, decrypt all secrets.
   *
   * @param password - User's bridge password
   * @throws If password is wrong or state is not initialized
   */
  async unlock(password: string): Promise<void> {
    if (!this.initialized) {
      throw new Error('TelebridgeState not initialized. Call initialize() first.');
    }

    if (!this.isLocked()) {
      return; // Already unlocked — no-op
    }

    const salt = fromBase64(this.persisted.passwordSalt);

    // Derive key via Argon2id with stored params
    const derivedKey = await hashPassword(password, salt, this.persisted.argon2Params);

    // Validate password by decrypting the verifier
    try {
      const verifierPayload = decodeEncryptedPayload(this.persisted.passwordVerifier);
      const decryptedVerifier = await aesDecrypt(verifierPayload, derivedKey);

      if (!constantTimeEqual(decryptedVerifier, VERIFIER_PLAINTEXT)) {
        secureWipe(derivedKey);
        throw new Error('Incorrect password');
      }
    } catch (err) {
      secureWipe(derivedKey);
      if (err instanceof Error && err.message === 'Incorrect password') {
        throw err;
      }
      // AES-GCM decryption failure = wrong key
      throw new Error('Incorrect password');
    }

    // Password verified — set derived key
    this.derivedKey = derivedKey;

    // Decrypt identity private keys
    if (this.persisted.identity) {
      const ed25519Private = await aesDecrypt(
        decodeEncryptedPayload(this.persisted.identity.encryptedEd25519PrivateKey),
        derivedKey,
      );
      const x25519Private = await aesDecrypt(
        decodeEncryptedPayload(this.persisted.identity.encryptedX25519PrivateKey),
        derivedKey,
      );

      this.identity = {
        ed25519PublicKey: fromBase64(this.persisted.identity.ed25519PublicKey),
        ed25519PrivateKey: ed25519Private,
        x25519PublicKey: fromBase64(this.persisted.identity.x25519PublicKey),
        x25519PrivateKey: x25519Private,
      };
    }

    // Decrypt all chat keys
    this.chatKeys = new Map();
    for (const [chatId, record] of Object.entries(this.persisted.chatKeys)) {
      const decryptedKey = await aesDecrypt(
        decodeEncryptedPayload(record.encryptedKey),
        derivedKey,
      );

      let previousKey: Uint8Array | undefined;
      if (record.previousEncryptedKey) {
        previousKey = await aesDecrypt(
          decodeEncryptedPayload(record.previousEncryptedKey),
          derivedKey,
        );
      }

      this.chatKeys.set(chatId, {
        key: decryptedKey,
        keyId: record.keyId,
        established: record.established,
        rotationVersion: record.rotationVersion,
        lastRotatedAt: record.lastRotatedAt,
        previousKey,
        previousKeyId: record.previousKeyId,
        messageCount: record.messageCount ?? 0,
      });
    }
  }

  /**
   * Check if the vault is locked.
   */
  isLocked(): boolean {
    return this.derivedKey === undefined;
  }

  /**
   * Check if the state has been initialized (first-run complete or loaded).
   */
  isInitialized(): boolean {
    return this.initialized;
  }

  // ---------------------------------------------------------------------------
  // Password Management
  // ---------------------------------------------------------------------------

  /**
   * Change the bridge password. Re-encrypts all secrets under the new key.
   *
   * @param currentPassword - Current password for verification
   * @param newPassword - New password to set
   * @returns Updated serialized persisted state
   */
  async changePassword(currentPassword: string, newPassword: string): Promise<string> {
    this.assertUnlocked();

    // Verify current password by re-deriving and checking
    const salt = fromBase64(this.persisted.passwordSalt);
    const checkKey = await hashPassword(currentPassword, salt, this.persisted.argon2Params);

    if (!this.derivedKey || !constantTimeEqual(checkKey, this.derivedKey)) {
      secureWipe(checkKey);
      throw new Error('Current password is incorrect');
    }
    secureWipe(checkKey);

    // Derive new key with fresh salt
    const newSalt = randomBytes(32);
    const newDerivedKey = await hashPassword(newPassword, newSalt, this.persisted.argon2Params);

    // Re-encrypt verifier with new key
    const encryptedVerifier = await aesEncrypt(VERIFIER_PLAINTEXT, newDerivedKey);

    // Re-encrypt identity private keys
    if (this.identity) {
      const encryptedEd25519Private = await aesEncrypt(this.identity.ed25519PrivateKey, newDerivedKey);
      const encryptedX25519Private = await aesEncrypt(this.identity.x25519PrivateKey, newDerivedKey);

      this.persisted.identity = {
        ...this.persisted.identity!,
        encryptedEd25519PrivateKey: encodeEncryptedPayload(encryptedEd25519Private),
        encryptedX25519PrivateKey: encodeEncryptedPayload(encryptedX25519Private),
      };
    }

    // Re-encrypt all chat keys
    for (const [chatId, chatKey] of this.chatKeys) {
      const encryptedKey = await aesEncrypt(chatKey.key, newDerivedKey);
      let previousEncryptedKey: string | undefined;
      if (chatKey.previousKey) {
        const encPrev = await aesEncrypt(chatKey.previousKey, newDerivedKey);
        previousEncryptedKey = encodeEncryptedPayload(encPrev);
      }

      this.persisted.chatKeys[chatId] = {
        ...this.persisted.chatKeys[chatId],
        encryptedKey: encodeEncryptedPayload(encryptedKey),
        previousEncryptedKey,
      };
    }

    // Update persisted state
    this.persisted.passwordSalt = toBase64(newSalt);
    this.persisted.passwordVerifier = encodeEncryptedPayload(encryptedVerifier);

    // Wipe old derived key, set new one
    secureWipe(this.derivedKey!);
    this.derivedKey = newDerivedKey;

    return serialize(this.persisted);
  }

  // ---------------------------------------------------------------------------
  // Identity
  // ---------------------------------------------------------------------------

  /**
   * Get the identity keypair. Only available when unlocked.
   *
   * @returns Object with public and private keys for Ed25519 and X25519
   */
  getIdentityKeyPair(): DecryptedIdentity {
    this.assertUnlocked();
    if (!this.identity) {
      throw new Error('No identity keypair generated');
    }
    return this.identity;
  }

  /**
   * Get identity public keys (available even when locked, if initialized).
   */
  getPublicKeys(): { ed25519PublicKey: Uint8Array; x25519PublicKey: Uint8Array } | undefined {
    if (!this.persisted.identity) return undefined;
    return {
      ed25519PublicKey: fromBase64(this.persisted.identity.ed25519PublicKey),
      x25519PublicKey: fromBase64(this.persisted.identity.x25519PublicKey),
    };
  }

  // ---------------------------------------------------------------------------
  // Chat Keys
  // ---------------------------------------------------------------------------

  /**
   * Store a chat symmetric key. Encrypts and persists.
   *
   * @param chatId - Telegram chat ID
   * @param key - 32-byte AES-256 key
   * @param keyId - 4-byte key identifier (hex string)
   * @returns Updated serialized persisted state
   */
  async storeChatKey(chatId: string, key: Uint8Array, keyId?: string): Promise<string> {
    this.assertUnlocked();

    const resolvedKeyId = keyId ?? toHexId(randomBytes(4));
    const now = Date.now();

    // Encrypt the key for persistence
    const encryptedKey = await aesEncrypt(key, this.derivedKey!);

    // Stamp the chat-key entry with the contact's active keyId at negotiation
    // time. 1:1 chats use chatId === peer user id; group chats and chats
    // without a contact record get an empty string (orphan — §3.5).
    const contact = this.persisted.contacts[chatId];
    const derivedFromKeyId = contact ? contact.activeKeyId : '';

    // Store in persisted state
    this.persisted.chatKeys[chatId] = {
      encryptedKey: encodeEncryptedPayload(encryptedKey),
      keyId: resolvedKeyId,
      established: now,
      rotationVersion: 0,
      lastRotatedAt: now,
      messageCount: 0,
      derivedFromKeyId,
    };

    // Store in memory
    this.chatKeys.set(chatId, {
      key: key.slice(), // Copy
      keyId: resolvedKeyId,
      established: now,
      rotationVersion: 0,
      lastRotatedAt: now,
      messageCount: 0,
    });

    return serialize(this.persisted);
  }

  /**
   * Get a decrypted chat key. Only available when unlocked.
   *
   * @param chatId - Telegram chat ID
   * @returns Decrypted 32-byte AES key, or undefined if no key for this chat
   */
  getChatKey(chatId: string): Uint8Array | undefined {
    this.assertUnlocked();
    return this.chatKeys.get(chatId)?.key;
  }

  /**
   * Drop a chat symmetric key. Future outgoing messages on this chat go in
   * cleartext until a new key exchange runs. No-op if the chat has no key.
   *
   * @param chatId - Telegram chat ID
   * @returns Updated serialized persisted state
   */
  async removeChatKey(chatId: string): Promise<string> {
    this.assertUnlocked();

    const existing = this.chatKeys.get(chatId);
    if (existing) {
      existing.key.fill(0);
      this.chatKeys.delete(chatId);
    }
    delete this.persisted.chatKeys[chatId];

    return serialize(this.persisted);
  }

  /**
   * Rotate a chat key: store new key, increment version, preserve previous.
   *
   * @param chatId - Telegram chat ID
   * @param newKey - New 32-byte AES-256 key
   * @param newKeyId - Optional new key ID
   * @returns Updated serialized persisted state
   */
  async rotateKey(chatId: string, newKey: Uint8Array, newKeyId?: string): Promise<string> {
    this.assertUnlocked();

    const existing = this.chatKeys.get(chatId);
    if (!existing) {
      throw new Error(`No existing key for chat ${chatId} to rotate`);
    }

    const resolvedNewKeyId = newKeyId ?? toHexId(randomBytes(4));
    const now = Date.now();

    // Encrypt new key
    const encryptedNewKey = await aesEncrypt(newKey, this.derivedKey!);

    // Encrypt previous key (for migration window)
    const encryptedPreviousKey = await aesEncrypt(existing.key, this.derivedKey!);

    // Preserve the contact-key binding across rotations (the rotation keeps
    // the same peer identity — only the session key is refreshed). Fall back
    // to the contact's current activeKeyId if the pre-rotation record didn't
    // carry a stamp (legacy blob migrated in-place with no matching contact).
    const priorRecord = this.persisted.chatKeys[chatId];
    const contact = this.persisted.contacts[chatId];
    const derivedFromKeyId = priorRecord?.derivedFromKeyId || (contact ? contact.activeKeyId : '');

    // Update persisted state
    this.persisted.chatKeys[chatId] = {
      encryptedKey: encodeEncryptedPayload(encryptedNewKey),
      keyId: resolvedNewKeyId,
      established: existing.established,
      rotationVersion: existing.rotationVersion + 1,
      lastRotatedAt: now,
      previousEncryptedKey: encodeEncryptedPayload(encryptedPreviousKey),
      previousKeyId: existing.keyId,
      messageCount: 0,
      derivedFromKeyId,
    };

    // Update in-memory state
    const previousKey = existing.key.slice(); // Copy before overwrite
    if (existing.previousKey) {
      secureWipe(existing.previousKey); // Wipe the old previous key
    }

    this.chatKeys.set(chatId, {
      key: newKey.slice(),
      keyId: resolvedNewKeyId,
      established: existing.established,
      rotationVersion: existing.rotationVersion + 1,
      lastRotatedAt: now,
      previousKey,
      previousKeyId: existing.keyId,
      messageCount: 0,
    });

    return serialize(this.persisted);
  }

  /**
   * Get rotation info for a chat key.
   *
   * @param chatId - Telegram chat ID
   * @returns Rotation metadata or undefined if no key exists
   */
  getRotationInfo(chatId: string): RotationInfo | undefined {
    // Works whether locked or unlocked — reads from persisted state
    const record = this.persisted.chatKeys[chatId];
    if (!record) return undefined;

    return {
      keyId: record.keyId,
      rotationVersion: record.rotationVersion,
      lastRotatedAt: record.lastRotatedAt,
      hasPreviousKey: record.previousEncryptedKey !== undefined,
      previousKeyId: record.previousKeyId,
    };
  }

  /**
   * Get the previous (pre-rotation) chat key for migration window.
   * Only available when unlocked.
   */
  getPreviousChatKey(chatId: string): Uint8Array | undefined {
    this.assertUnlocked();
    return this.chatKeys.get(chatId)?.previousKey;
  }

  /**
   * Get the full decrypted chat key record (including messageCount).
   * Only available when unlocked.
   *
   * @param chatId - Telegram chat ID
   * @returns Full decrypted chat key record, or undefined if no key exists
   */
  getDecryptedChatKeyRecord(chatId: string): DecryptedChatKey | undefined {
    this.assertUnlocked();
    return this.chatKeys.get(chatId);
  }

  /**
   * Increment the message count for a chat key (for rotation tracking).
   * Updates both in-memory and persisted state.
   *
   * @param chatId - Telegram chat ID
   * @returns Updated serialized persisted state
   * @throws If no key exists for the chat
   */
  incrementMessageCount(chatId: string): string {
    this.assertUnlocked();

    const chatKey = this.chatKeys.get(chatId);
    if (!chatKey) {
      throw new Error(`No key for chat ${chatId} to increment message count`);
    }

    chatKey.messageCount += 1;

    const record = this.persisted.chatKeys[chatId];
    if (record) {
      record.messageCount = chatKey.messageCount;
    }

    return serialize(this.persisted);
  }

  /**
   * Get a contact's X25519 public key as Uint8Array.
   * Convenience method for key exchange initiation.
   *
   * @param contactId - Telegram user ID
   * @returns 32-byte X25519 public key, or undefined if contact not known
   */
  getContactX25519PublicKey(contactId: string): Uint8Array | undefined {
    const record = this.persisted.contacts[contactId];
    if (!record) return undefined;
    const active = findActiveKey(record);
    if (!active) return undefined;
    return fromBase64(active.x25519PublicKey);
  }

  // ---------------------------------------------------------------------------
  // Contact Keys (TOFU)
  // ---------------------------------------------------------------------------

  /**
   * Store a contact's public key with TOFU tracking.
   * - First time: stored as initial trust
   * - Key changed: flagged as Changed, old key moved to history
   * - Same key: no-op
   *
   * @param contactId - Telegram user ID
   * @param ed25519PublicKey - Contact's Ed25519 public key
   * @param x25519PublicKey - Contact's X25519 public key
   * @returns Object indicating whether this was first-seen, changed, or unchanged
   */
  storeContactKey(
    contactId: string,
    ed25519PublicKey: Uint8Array,
    x25519PublicKey: Uint8Array,
  ): { status: 'new' | 'changed' | 'unchanged' } {
    const existing = this.persisted.contacts[contactId];
    const ed25519Base64 = toBase64(ed25519PublicKey);
    const x25519Base64 = toBase64(x25519PublicKey);
    const keyId = deriveKeyId(ed25519Base64);
    const now = Date.now();

    if (!existing) {
      // First encounter — TOFU accept, single-entry archive.
      const entry: ContactKeyEntry = {
        keyId,
        ed25519PublicKey: ed25519Base64,
        x25519PublicKey: x25519Base64,
        origin: 'tofu',
        firstSeen: now,
        lastUsed: now,
      };
      this.persisted.contacts[contactId] = {
        userId: contactId,
        keys: [entry],
        activeKeyId: keyId,
        trustLevel: ContactTrustLevel.Initial,
        firstSeen: now,
      };
      return { status: 'new' };
    }

    // Existing archive — look up the entry that matches the wire key by
    // content-addressable id. Don't key on x25519 alone: the identity key
    // is what pins the contact.
    const matching = existing.keys.find((k) => k.keyId === keyId);
    if (matching && matching.keyId === existing.activeKeyId) {
      // Wire matches the active entry — record last-used, keep x25519 fresh
      // (the prekey can legitimately rotate under the same identity key).
      matching.lastUsed = now;
      if (matching.x25519PublicKey !== x25519Base64) {
        matching.x25519PublicKey = x25519Base64;
      }
      return { status: 'unchanged' };
    }

    // Key doesn't match the active entry. Per §3c we NEVER overwrite: append
    // the new key to the archive as inactive (archivedAt stamped, activeKeyId
    // unchanged). Flip trustLevel to Changed so the UI can banner the user.
    if (!matching) {
      existing.keys.push({
        keyId,
        ed25519PublicKey: ed25519Base64,
        x25519PublicKey: x25519Base64,
        origin: 'tofu',
        firstSeen: now,
        lastUsed: now,
        archivedAt: now,
      });
    } else {
      // We've seen this key before (archived). Bump lastUsed but leave it
      // archived — the action layer decides whether to promote.
      matching.lastUsed = now;
    }
    existing.trustLevel = ContactTrustLevel.Changed;

    return { status: 'changed' };
  }

  /**
   * Get a contact's active public key and trust status.
   *
   * Back-compat shape: returns the active ContactKeyEntry's bytes hoisted to
   * the top level under the legacy field names so existing callers keep
   * working. The per-contact key archive is accessible via `.keys` /
   * `.activeKeyId` on the same object.
   *
   * @param contactId - Telegram user ID
   * @returns Flat-shape record or undefined if not known
   */
  getContactKey(contactId: string): (ContactRecord & {
    ed25519PublicKey: string;
    x25519PublicKey: string;
    verifiedAt?: number;
    publicKey: Uint8Array;
  }) | undefined {
    const record = this.persisted.contacts[contactId];
    if (!record) return undefined;
    const active = findActiveKey(record);
    if (!active) return undefined;

    const verifiedAt = record.trustLevel === ContactTrustLevel.Verified ? active.lastUsed : undefined;
    return {
      ...record,
      ed25519PublicKey: active.ed25519PublicKey,
      x25519PublicKey: active.x25519PublicKey,
      verifiedAt,
      publicKey: fromBase64(active.ed25519PublicKey),
    };
  }

  /**
   * Mark a contact's active key as manually verified (post-hoc QR flow).
   * Lifts trust to Verified and tags the active entry's origin.
   *
   * @param contactId - Telegram user ID
   */
  verifyContact(contactId: string): void {
    const record = this.persisted.contacts[contactId];
    if (!record) {
      throw new Error(`Unknown contact: ${contactId}`);
    }
    const active = findActiveKey(record);
    if (!active) {
      throw new Error(`Contact ${contactId} has no active key`);
    }
    record.trustLevel = ContactTrustLevel.Verified;
    active.origin = 'post-hoc-qr';
    active.lastUsed = Date.now();
  }

  // ---------------------------------------------------------------------------
  // In-person scan + key archive management (§6.1.4)
  // ---------------------------------------------------------------------------

  /**
   * Apply an in-person QR scan to the contact archive. Per plan §3 case
   * dispatcher. The caller must have already verified the bundle signature;
   * this method only mutates the vault.
   */
  storeContactKeyFromScan(
    userId: string,
    ed25519PublicKey: Uint8Array,
    x25519PublicKey: Uint8Array,
    _signature: Uint8Array,
  ): ScanResult {
    const ed25519Base64 = toBase64(ed25519PublicKey);
    const x25519Base64 = toBase64(x25519PublicKey);
    const keyId = deriveKeyId(ed25519Base64);
    const now = Date.now();

    const existing = this.persisted.contacts[userId];
    if (!existing) {
      this.persisted.contacts[userId] = {
        userId,
        keys: [{
          keyId,
          ed25519PublicKey: ed25519Base64,
          x25519PublicKey: x25519Base64,
          origin: 'in-person-scan',
          firstSeen: now,
          lastUsed: now,
        }],
        activeKeyId: keyId,
        trustLevel: ContactTrustLevel.Verified,
        firstSeen: now,
      };
      return { kind: 'fresh', keyId, needsUserConfirmation: false };
    }

    const matching = existing.keys.find((k) => k.keyId === keyId);
    if (matching && matching.keyId === existing.activeKeyId) {
      matching.lastUsed = now;
      if (matching.origin === 'tofu') {
        matching.origin = 'in-person-scan';
      }
      existing.trustLevel = ContactTrustLevel.Verified;
      return { kind: 'matchedActive', keyId, needsUserConfirmation: false };
    }

    if (matching) {
      // Archived entry — bump lastUsed but don't auto-promote.
      matching.lastUsed = now;
      return { kind: 'matchedArchived', keyId, needsUserConfirmation: true };
    }

    // Brand-new key for an existing contact — append as inactive.
    existing.keys.push({
      keyId,
      ed25519PublicKey: ed25519Base64,
      x25519PublicKey: x25519Base64,
      origin: 'in-person-scan',
      firstSeen: now,
      archivedAt: now,
    });
    return { kind: 'newKeyAddedInactive', keyId, needsUserConfirmation: true };
  }

  /**
   * Promote an archived key to active. Archives the previous active key.
   * No-op if the target is already active.
   */
  setActiveKey(userId: string, keyId: string): void {
    const record = this.persisted.contacts[userId];
    if (!record) {
      throw new Error(`Unknown contact: ${userId}`);
    }
    const target = record.keys.find((k) => k.keyId === keyId);
    if (!target) {
      throw new Error(`Key ${keyId} not found on contact ${userId}`);
    }
    if (record.activeKeyId === keyId) return;

    const now = Date.now();
    const previousActive = record.keys.find((k) => k.keyId === record.activeKeyId);
    if (previousActive) {
      previousActive.archivedAt = now;
    }
    target.archivedAt = undefined;
    record.activeKeyId = keyId;
  }

  /**
   * Archive a non-active, non-sole key. Refuses the active key (use
   * {@link setActiveKey} first) or the sole key (use {@link deleteKey} or
   * {@link revokeContactKey} instead).
   */
  archiveKey(userId: string, keyId: string): void {
    const record = this.persisted.contacts[userId];
    if (!record) {
      throw new Error(`Unknown contact: ${userId}`);
    }
    const target = record.keys.find((k) => k.keyId === keyId);
    if (!target) {
      throw new Error(`Key ${keyId} not found on contact ${userId}`);
    }
    if (record.keys.length === 1) {
      throw new Error('Cannot archive sole key — use deleteKey or revokeContactKey instead');
    }
    if (record.activeKeyId === keyId) {
      throw new Error('Cannot archive the active key — set a different key active first');
    }
    target.archivedAt = Date.now();
  }

  /**
   * Delete a key entry. Per Q-IP-7, deleting the active key auto-promotes
   * the most-recently-used archived entry. Deleting the sole key removes
   * the entire {@link ContactRecord}.
   */
  deleteKey(userId: string, keyId: string): { autoPromoted?: string; contactRemoved: boolean } {
    const record = this.persisted.contacts[userId];
    if (!record) {
      throw new Error(`Unknown contact: ${userId}`);
    }
    const targetIndex = record.keys.findIndex((k) => k.keyId === keyId);
    if (targetIndex === -1) {
      throw new Error(`Key ${keyId} not found on contact ${userId}`);
    }

    if (record.keys.length === 1) {
      delete this.persisted.contacts[userId];
      return { contactRemoved: true };
    }

    const isActive = record.activeKeyId === keyId;
    record.keys.splice(targetIndex, 1);

    if (!isActive) {
      return { contactRemoved: false };
    }

    // Auto-promote the most-recently-used archived entry.
    const candidate = [...record.keys].sort((a, b) => {
      const aStamp = a.lastUsed ?? a.firstSeen;
      const bStamp = b.lastUsed ?? b.firstSeen;
      return bStamp - aStamp;
    })[0];
    candidate.archivedAt = undefined;
    record.activeKeyId = candidate.keyId;
    return { autoPromoted: candidate.keyId, contactRemoved: false };
  }

  /**
   * Serialize + self-sign a key entry for out-of-band transfer. Returns both
   * the raw JSON blob and a `tb1://ck/<base64url>` QR-friendly form.
   *
   * Distinct scheme from `tb1://pk/` (bootstrap bundle) to prevent
   * cross-decoding; see plan §3.5 "Export / import formats".
   */
  exportKey(userId: string, keyId: string): { json: string; qrText: string } {
    this.assertUnlocked();
    if (!this.identity) {
      throw new Error('No identity keypair available');
    }
    const record = this.persisted.contacts[userId];
    if (!record) {
      throw new Error(`Unknown contact: ${userId}`);
    }
    const entry = record.keys.find((k) => k.keyId === keyId);
    if (!entry) {
      throw new Error(`Key ${keyId} not found on contact ${userId}`);
    }

    const payload = {
      type: 'tb1.contactKey' as const,
      keyId: entry.keyId,
      ed25519PublicKey: entry.ed25519PublicKey,
      x25519PublicKey: entry.x25519PublicKey,
      origin: entry.origin,
      firstSeen: entry.firstSeen,
      label: entry.label,
    };
    const signable = encodeUtf8(JSON.stringify(payload));
    const signature = ed25519Sign(signable, this.identity.ed25519PrivateKey);
    const signed = {
      ...payload,
      signature: toBase64(signature),
      signedBy: toBase64(this.identity.ed25519PublicKey),
    };
    const json = JSON.stringify(signed);
    const qrText = `tb1://ck/${toBase64Url(encodeUtf8(json))}`;
    return { json, qrText };
  }

  /**
   * Parse + verify an exported key payload and append it to the target
   * contact's archive as inactive. Dedupes by keyId.
   */
  importKey(targetUserId: string, payload: string): ImportResult {
    const CK_PREFIX = 'tb1://ck/';
    let jsonText: string;
    if (payload.startsWith(CK_PREFIX)) {
      try {
        jsonText = new TextDecoder().decode(fromBase64Url(payload.slice(CK_PREFIX.length)));
      } catch {
        throw new Error('Import payload is not valid base64url');
      }
    } else {
      jsonText = payload;
    }

    let parsed: {
      type?: string;
      keyId?: string;
      ed25519PublicKey?: string;
      x25519PublicKey?: string;
      origin?: ContactKeyEntry['origin'];
      firstSeen?: number;
      label?: string;
      signature?: string;
      signedBy?: string;
    };
    try {
      parsed = JSON.parse(jsonText);
    } catch {
      throw new Error('Import payload is not valid JSON');
    }
    if (parsed.type !== 'tb1.contactKey'
      || !parsed.keyId
      || !parsed.ed25519PublicKey
      || !parsed.x25519PublicKey
      || !parsed.origin
      || typeof parsed.firstSeen !== 'number'
      || !parsed.signature
      || !parsed.signedBy) {
      throw new Error('Import payload is missing required fields');
    }

    // Re-serialize the canonical signable form (strip signature + signedBy).
    const canonical = {
      type: 'tb1.contactKey' as const,
      keyId: parsed.keyId,
      ed25519PublicKey: parsed.ed25519PublicKey,
      x25519PublicKey: parsed.x25519PublicKey,
      origin: parsed.origin,
      firstSeen: parsed.firstSeen,
      label: parsed.label,
    };
    const signable = encodeUtf8(JSON.stringify(canonical));
    const signature = fromBase64(parsed.signature);
    const signedBy = fromBase64(parsed.signedBy);
    if (!ed25519Verify(signable, signature, signedBy)) {
      throw new Error('Import signature invalid');
    }

    const recomputedKeyId = deriveKeyId(parsed.ed25519PublicKey);
    if (recomputedKeyId !== parsed.keyId) {
      throw new Error('Import keyId does not match ed25519PublicKey');
    }

    const record = this.persisted.contacts[targetUserId];
    if (!record) {
      throw new Error(`Unknown contact: ${targetUserId}`);
    }
    if (record.keys.some((k) => k.keyId === parsed.keyId)) {
      return { kind: 'duplicate', keyId: parsed.keyId };
    }

    const now = Date.now();
    record.keys.push({
      keyId: parsed.keyId,
      ed25519PublicKey: parsed.ed25519PublicKey,
      x25519PublicKey: parsed.x25519PublicKey,
      origin: 'imported',
      firstSeen: now,
      label: parsed.label,
      archivedAt: now,
    });
    return { kind: 'imported', keyId: parsed.keyId };
  }

  /**
   * Enumerate known contacts. Never returns raw key bytes — only metadata
   * safe to render in a list view.
   */
  listContacts(): ContactSummary[] {
    const out: ContactSummary[] = [];
    for (const [userId, record] of Object.entries(this.persisted.contacts)) {
      const active = findActiveKey(record);
      if (!active) continue;
      out.push({
        userId,
        trustLevel: record.trustLevel,
        activeKeyId: record.activeKeyId,
        keyCount: record.keys.length,
        activeKeyOrigin: active.origin,
      });
    }
    return out;
  }

  /**
   * Return a defensive copy of the per-contact key archive. Sorted active
   * first, then archived in `lastUsed desc` order.
   */
  listContactKeys(userId: string): ContactKeyEntry[] {
    const record = this.persisted.contacts[userId];
    if (!record) return [];
    const copies = record.keys.map((k) => ({ ...k }));
    copies.sort((a, b) => {
      const aActive = a.keyId === record.activeKeyId ? 1 : 0;
      const bActive = b.keyId === record.activeKeyId ? 1 : 0;
      if (aActive !== bActive) return bActive - aActive;
      const aStamp = a.lastUsed ?? a.firstSeen;
      const bStamp = b.lastUsed ?? b.firstSeen;
      return bStamp - aStamp;
    });
    return copies;
  }

  /**
   * Drop a contact's archive entirely and cascade-clean any chat sessions
   * that were negotiated against its keys. Returns the list of chatIds
   * whose chat-key records were removed so the action layer can clear
   * corresponding `prekeyPublishedChatIds` entries.
   */
  revokeContactKey(userId: string): { droppedChatIds: string[] } {
    const record = this.persisted.contacts[userId];
    if (!record) {
      return { droppedChatIds: [] };
    }
    const doomedKeyIds = new Set(record.keys.map((k) => k.keyId));
    delete this.persisted.contacts[userId];

    const droppedChatIds: string[] = [];
    for (const [chatId, chatRecord] of Object.entries(this.persisted.chatKeys)) {
      if (chatRecord.derivedFromKeyId && doomedKeyIds.has(chatRecord.derivedFromKeyId)) {
        delete this.persisted.chatKeys[chatId];
        const inMemory = this.chatKeys.get(chatId);
        if (inMemory) {
          secureWipe(inMemory.key);
          if (inMemory.previousKey) secureWipe(inMemory.previousKey);
          this.chatKeys.delete(chatId);
        }
        droppedChatIds.push(chatId);
      }
    }
    return { droppedChatIds };
  }

  // ---------------------------------------------------------------------------
  // Persistence
  // ---------------------------------------------------------------------------

  /**
   * Get the current persisted state as a serialized JSON string.
   * Safe to write to disk — validated to contain no plaintext secrets.
   */
  toPersistable(): string {
    return serialize(this.persisted);
  }

  /**
   * Get the raw persisted state object (for direct integration with global state).
   * Validated to contain no plaintext secrets.
   */
  getPersistedState(): PersistedState {
    assertNoPlaintextSecrets(this.persisted);
    return { ...this.persisted };
  }

  // ---------------------------------------------------------------------------
  // Internal Helpers
  // ---------------------------------------------------------------------------

  private assertUnlocked(): void {
    if (this.isLocked()) {
      throw new Error('TelebridgeState is locked. Call unlock() first.');
    }
  }
}

/** base64url encode (URL-safe alphabet, no padding). */
function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** base64url decode — mirror of toBase64Url. */
function fromBase64Url(text: string): Uint8Array {
  let normalized = text.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (normalized.length % 4)) % 4;
  normalized += '='.repeat(padLen);
  return fromBase64(normalized);
}

/** Convert 4 random bytes to a hex key ID string */
function toHexId(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Resolve a ContactRecord's active key entry. Returns undefined if archive invariant is broken. */
function findActiveKey(record: ContactRecord): ContactKeyEntry | undefined {
  return record.keys.find((k) => k.keyId === record.activeKeyId);
}
