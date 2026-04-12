/**
 * Telebridge v2 — Send-Side Encryption
 *
 * Encrypts outgoing message text/captions for chats with active symmetric keys.
 * Uses the TelebridgeState vault (singleton) for key access and the protocol
 * encoder for wire format serialization.
 *
 * Wire format: tb1.s.<base64(keyId(4B) ‖ nonce(12B) ‖ ciphertext(var) ‖ authTag(16B) ‖ sig(64B))>
 * Signature covers: keyId ‖ nonce ‖ ciphertext ‖ authTag
 */

import type { SymmetricMessagePayload } from './protocol/types';

import { encodeSymmetricMessage } from './protocol/encode';
import {
  aesEncrypt,
  concatBytes,
  ed25519Sign,
  encodeUtf8,
  fromHex,
} from './crypto';
import { TelebridgeState } from './state';

// ---------------------------------------------------------------------------
// Singleton vault instance
// ---------------------------------------------------------------------------

let vaultInstance: TelebridgeState | undefined;

/** Get the global TelebridgeState vault. Creates on first access. */
export function getTelebridgeVault(): TelebridgeState {
  if (!vaultInstance) {
    vaultInstance = new TelebridgeState();
  }
  return vaultInstance;
}

/**
 * Replace the vault instance (for loading persisted state or testing).
 * The caller is responsible for calling load()/unlock() on the new instance.
 */
export function setTelebridgeVault(vault: TelebridgeState): void {
  vaultInstance = vault;
}

// ---------------------------------------------------------------------------
// Guard: should we encrypt for this chat?
// ---------------------------------------------------------------------------

/**
 * Check whether outgoing messages to `chatId` should be encrypted.
 *
 * Returns true when:
 * 1. The vault is initialized and unlocked
 * 2. The chat has an active symmetric key
 *
 * @param chatId — Telegram chat ID (string)
 */
export function shouldEncryptChat(chatId: string): boolean {
  const vault = getTelebridgeVault();

  if (!vault.isInitialized() || vault.isLocked()) {
    return false;
  }

  // getChatKey returns undefined when there's no key for this chat
  return vault.getChatKey(chatId) !== undefined;
}

// ---------------------------------------------------------------------------
// Core encryption
// ---------------------------------------------------------------------------

/**
 * Encrypt plaintext for an outgoing message in `chatId`.
 *
 * Performs:
 * 1. UTF-8 encode the plaintext
 * 2. AES-256-GCM encrypt with the chat's symmetric key
 * 3. Split Web Crypto output into ciphertext + auth tag
 * 4. Sign (keyId ‖ nonce ‖ ciphertext ‖ authTag) with Ed25519 identity key
 * 5. Encode as tb1.s wire format string
 *
 * @param plaintext — Message text to encrypt
 * @param chatId — Telegram chat ID for key lookup
 * @returns tb1.s.<base64> wire format string
 * @throws If vault is locked, no chat key, or no identity key
 */
export async function encryptOutgoingText(plaintext: string, chatId: string): Promise<string> {
  const vault = getTelebridgeVault();

  // Get the decrypted chat key + keyId
  const chatKey = vault.getChatKey(chatId);
  if (!chatKey) {
    throw new Error(`No chat key for chat ${chatId}`);
  }

  // Get identity for signing
  const identity = vault.getIdentityKeyPair();

  // Get the keyId from the rotation info (hex string → 4 bytes)
  const rotationInfo = vault.getRotationInfo(chatId);
  if (!rotationInfo) {
    throw new Error(`No rotation info for chat ${chatId}`);
  }
  const keyIdBytes = fromHex(rotationInfo.keyId);

  // 1. UTF-8 encode
  const plaintextBytes = encodeUtf8(plaintext);

  // 2. AES-256-GCM encrypt — returns { iv, ciphertext, authTag } as separate fields
  const encrypted = await aesEncrypt(plaintextBytes, chatKey);

  // 3. Sign: keyId ‖ iv ‖ ciphertext ‖ authTag (everything except the signature itself)
  const signedData = concatBytes(keyIdBytes, encrypted.iv, encrypted.ciphertext, encrypted.authTag);
  const signature = ed25519Sign(signedData, identity.ed25519PrivateKey);

  // 4. Build SymmetricMessagePayload and encode to wire format
  const payload: SymmetricMessagePayload = {
    keyId: keyIdBytes,
    nonce: encrypted.iv,
    ciphertext: encrypted.ciphertext,
    authTag: encrypted.authTag,
    signature,
  };

  return encodeSymmetricMessage(payload);
}

// ---------------------------------------------------------------------------
// Convenience: encrypt params.text and/or params.caption in place
// ---------------------------------------------------------------------------

/**
 * Encrypt text and caption fields of a send params object if the chat
 * has an active encryption key. Returns the (possibly modified) params.
 *
 * This is the single integration point for the message send pipeline.
 * All send paths (single, grouped, ungrouped, forward, edit) should call this.
 *
 * @param chatId — Chat the message is being sent to
 * @param text — Message text (may be undefined)
 * @param caption — Media caption (may be undefined)
 * @returns Object with encrypted text/caption, or originals if chat isn't encrypted
 */
export async function encryptSendFields(
  chatId: string,
  text: string | undefined,
  caption: string | undefined,
): Promise<{ text: string | undefined; caption: string | undefined }> {
  if (!shouldEncryptChat(chatId)) {
    return { text, caption };
  }

  const encryptedText = text ? await encryptOutgoingText(text, chatId) : undefined;
  const encryptedCaption = caption ? await encryptOutgoingText(caption, chatId) : undefined;

  return { text: encryptedText, caption: encryptedCaption };
}
