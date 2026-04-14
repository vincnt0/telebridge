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

import { serialize, deserialize, createEmptyPersistedState } from './serialization';
import type {
  PersistedState,
  DecryptedIdentity,
  DecryptedChatKey,
  ContactRecord,
  ChatKeyRecord,
  RotationInfo,
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

    // Store in persisted state
    this.persisted.chatKeys[chatId] = {
      encryptedKey: encodeEncryptedPayload(encryptedKey),
      keyId: resolvedKeyId,
      established: now,
      rotationVersion: 0,
      lastRotatedAt: now,
      messageCount: 0,
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
    return fromBase64(record.x25519PublicKey);
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

    if (!existing) {
      // First encounter — TOFU accept
      this.persisted.contacts[contactId] = {
        ed25519PublicKey: ed25519Base64,
        x25519PublicKey: x25519Base64,
        trustLevel: ContactTrustLevel.Initial,
        firstSeen: Date.now(),
        keyHistory: [],
      };
      return { status: 'new' };
    }

    // Check if key changed
    if (existing.ed25519PublicKey === ed25519Base64 && existing.x25519PublicKey === x25519Base64) {
      return { status: 'unchanged' };
    }

    // Key changed — push old key to history, flag as Changed
    existing.keyHistory.push({
      ed25519PublicKey: existing.ed25519PublicKey,
      x25519PublicKey: existing.x25519PublicKey,
      seenAt: Date.now(),
    });

    existing.ed25519PublicKey = ed25519Base64;
    existing.x25519PublicKey = x25519Base64;
    existing.trustLevel = ContactTrustLevel.Changed;
    existing.verifiedAt = undefined;

    return { status: 'changed' };
  }

  /**
   * Get a contact's public key and trust status.
   *
   * @param contactId - Telegram user ID
   * @returns Contact record or undefined if not known
   */
  getContactKey(contactId: string): (ContactRecord & { publicKey: Uint8Array }) | undefined {
    const record = this.persisted.contacts[contactId];
    if (!record) return undefined;

    return {
      ...record,
      publicKey: fromBase64(record.ed25519PublicKey),
    };
  }

  /**
   * Mark a contact key as manually verified.
   *
   * @param contactId - Telegram user ID
   */
  verifyContact(contactId: string): void {
    const record = this.persisted.contacts[contactId];
    if (!record) {
      throw new Error(`Unknown contact: ${contactId}`);
    }
    record.trustLevel = ContactTrustLevel.Verified;
    record.verifiedAt = Date.now();
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

/** Convert 4 random bytes to a hex key ID string */
function toHexId(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
