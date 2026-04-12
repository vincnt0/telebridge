/**
 * Telebridge v2 — Key Rotation Logic
 *
 * Checks whether a chat key should be rotated based on message count
 * and time thresholds, and performs rotation by generating a new key
 * and initiating a fresh key exchange.
 */

import type { DecryptedIdentity } from '../state/types';
import type { TelebridgeState } from '../state/TelebridgeState';

import { initiateKeyExchange } from './initiate';
import type { RotationCheck, RotationConfig } from './types';
import { DEFAULT_ROTATION_CONFIG } from './types';

/** Milliseconds per day */
const MS_PER_DAY = 86400000;

/**
 * Check whether a chat key should be rotated.
 *
 * Checks two conditions:
 * 1. Message count exceeds `maxMessages` threshold
 * 2. Time since last rotation exceeds `maxDays` threshold
 *
 * @param chatId - Telegram chat ID
 * @param state - TelebridgeState to read rotation info from
 * @param config - Rotation thresholds (defaults to 100 messages / 7 days)
 * @returns Whether rotation is needed and why
 */
export function shouldRotate(
  chatId: string,
  state: TelebridgeState,
  config: RotationConfig = DEFAULT_ROTATION_CONFIG,
): RotationCheck {
  const info = state.getRotationInfo(chatId);
  if (!info) {
    return { shouldRotate: false };
  }

  // Check message count threshold
  const chatKeyRecord = state.getDecryptedChatKeyRecord(chatId);
  if (chatKeyRecord && chatKeyRecord.messageCount >= config.maxMessages) {
    return { shouldRotate: true, reason: 'message_count' };
  }

  // Check time threshold
  const elapsed = Date.now() - info.lastRotatedAt;
  if (elapsed >= config.maxDays * MS_PER_DAY) {
    return { shouldRotate: true, reason: 'time_elapsed' };
  }

  return { shouldRotate: false };
}

/**
 * Perform a key rotation for a chat.
 *
 * Generates a completely new AES-256 chat key (not derived from the old one),
 * initiates a fresh key exchange to deliver it to the peer, and persists the
 * rotation via `state.rotateKey()` (which preserves the previous key in a
 * migration window).
 *
 * @param chatId - Telegram chat ID
 * @param myIdentity - Sender's decrypted identity keys
 * @param recipientX25519PublicKey - Recipient's 32-byte X25519 public key
 * @param state - TelebridgeState for key rotation persistence
 * @returns The wire message to send and the new key/keyId
 */
export async function performRotation(
  chatId: string,
  myIdentity: DecryptedIdentity,
  recipientX25519PublicKey: Uint8Array,
  state: TelebridgeState,
): Promise<{ wireMessage: string; newKey: Uint8Array; newKeyId: string }> {
  // Generate new key via full key exchange
  const initiation = await initiateKeyExchange(myIdentity, recipientX25519PublicKey);

  // Persist rotation — preserves previous key in migration window
  await state.rotateKey(chatId, initiation.chatKey, initiation.keyId);

  return {
    wireMessage: initiation.wireMessage,
    newKey: initiation.chatKey,
    newKeyId: initiation.keyId,
  };
}
