/**
 * Telebridge v2 — Key Exchange Responder
 *
 * Receives an incoming `tb1.kx` wire message, verifies the Ed25519 signature,
 * performs reverse ECDH to derive the wrapping key, unwraps the chat key,
 * and returns it along with TOFU status.
 *
 * The caller is responsible for persisting the chat key via
 * `TelebridgeState.storeChatKey()`.
 */

import {
  computeSharedSecret,
  concatBytes,
  constantTimeEqual,
  decrypt,
  encodeUtf8,
  fromBase64,
  secureWipe,
  verify,
} from '../crypto';
import { SIZES } from '../crypto/types';
import type { EncryptedPayload } from '../crypto/types';
import { deriveKey } from '../crypto/kdf';
import { decodeKeyExchange } from '../protocol/decode';
import type { KeyExchangePayload } from '../protocol/types';
import type { TelebridgeState } from '../state/TelebridgeState';

import type { KeyExchangeResponse } from './types';

/** HKDF info string — must be identical on initiator and responder */
const HKDF_INFO = encodeUtf8('telebridge-v2-kx');

/** Size of the key ID prefix in the wrapped payload */
const KEY_ID_SIZE = 4;

/**
 * Split the wire-format encryptedChatKey bytes back into an EncryptedPayload.
 *
 * Wire format: [iv(12B)][ciphertext(variable)][authTag(16B)]
 */
function splitEncryptedChatKey(bytes: Uint8Array): EncryptedPayload {
  const minLength = SIZES.GCM_NONCE + SIZES.GCM_TAG + 1;
  if (bytes.length < minLength) {
    throw new Error(
      `Encrypted chat key too short: ${bytes.length} bytes (minimum ${minLength})`,
    );
  }

  const iv = bytes.slice(0, SIZES.GCM_NONCE);
  const ciphertext = bytes.slice(SIZES.GCM_NONCE, bytes.length - SIZES.GCM_TAG);
  const authTag = bytes.slice(bytes.length - SIZES.GCM_TAG);

  return { iv, ciphertext, authTag };
}

/**
 * Respond to an incoming key exchange handshake.
 *
 * Decodes the wire message, verifies the sender's signature against the
 * caller-supplied pinned identity key (NOT the key embedded in the message),
 * performs ECDH to derive the wrapping key, and unwraps the chat key.
 *
 * The pinned key must be established out-of-band — either via a prior `tb1.pk`
 * publication or an in-person bundle scan. Passing `undefined` yields a
 * `needsPrekey` result so the caller can queue the kx until the pinning
 * message lands; passing a key that differs byte-for-byte from the one on
 * the wire yields `identityMismatch` (refuse: likely race-to-pin MITM).
 *
 * @param wireMessage - The `tb1.kx` wire-format string
 * @param myIdentity - Responder's decrypted identity keys (needs x25519PrivateKey)
 * @param state - TelebridgeState for TOFU contact key storage
 * @param senderId - Telegram user ID of the sender (for contact tracking)
 * @param pinnedSenderIdKey - Previously-pinned Ed25519 identity for this sender, or undefined
 * @returns Discriminated result: success chat key, or needsPrekey/identityMismatch
 * @throws If signature verification fails or decryption fails
 */
export async function respondToKeyExchange(
  wireMessage: string,
  myIdentity: { x25519PrivateKey: Uint8Array },
  state: TelebridgeState,
  senderId: string,
  pinnedSenderIdKey: Uint8Array | undefined,
): Promise<KeyExchangeResponse> {
  // 1. Decode the wire message
  const payload: KeyExchangePayload = decodeKeyExchange(wireMessage);

  // 2. Gate on pinned identity — refuse to derive a chat key from an
  //    unverified sender key. An attacker who delivers `tb1.kx` before the
  //    legitimate contact's `tb1.pk` would otherwise silently TOFU-pin.
  if (!pinnedSenderIdKey) {
    return { status: 'needsPrekey' };
  }

  // 3. Strict equality: the wire-embedded key MUST match the pinned key.
  if (!constantTimeEqual(pinnedSenderIdKey, payload.senderIdKey)) {
    return { status: 'identityMismatch' };
  }

  // 4. Reconstruct signable payload and verify signature AGAINST the pinned
  //    key. The byte-equality check above makes this load-bearing: even though
  //    the bytes are equal in the happy path, verifying against the pinned
  //    reference (not the wire-embedded copy) is the correct semantic.
  const signablePayload = concatBytes(
    payload.senderIdKey,
    payload.ephemeralX25519,
    payload.encryptedChatKey,
  );
  const isValid = verify(signablePayload, payload.signature, pinnedSenderIdKey);
  if (!isValid) {
    throw new Error('Key exchange signature verification failed — message may be tampered');
  }

  // 5. Refresh TOFU record — preserve prior X25519 public key if already pinned.
  const existingContact = state.getContactKey(senderId);
  const senderX25519ForContact = existingContact
    ? fromBase64(existingContact.x25519PublicKey)
    : new Uint8Array(SIZES.X25519_PUBLIC_KEY);

  const tofuResult = state.storeContactKey(
    senderId,
    payload.senderIdKey,
    senderX25519ForContact,
  );

  // 6. Perform ECDH: my static X25519 private × sender's ephemeral X25519 public
  const sharedSecret = computeSharedSecret(myIdentity.x25519PrivateKey, payload.ephemeralX25519);

  // 7. Derive wrapping key via HKDF-SHA256 (identical info string as initiator)
  const wrappingKey = deriveKey(sharedSecret, undefined, HKDF_INFO);

  // 8. Split and decrypt the wrapped payload (keyId + chatKey)
  const encryptedPayload = splitEncryptedChatKey(payload.encryptedChatKey);
  const wrappedPlaintext = await decrypt(encryptedPayload, wrappingKey);

  const expectedLength = KEY_ID_SIZE + SIZES.AES_KEY;
  if (wrappedPlaintext.length !== expectedLength) {
    throw new Error(
      `Unwrapped payload has wrong size: ${wrappedPlaintext.length} bytes (expected ${expectedLength})`,
    );
  }

  // Extract keyId (first 4 bytes) and chatKey (remaining 32 bytes)
  const keyIdBytes = wrappedPlaintext.slice(0, KEY_ID_SIZE);
  const chatKey = wrappedPlaintext.slice(KEY_ID_SIZE);
  const keyId = Array.from(keyIdBytes).map((b) => b.toString(16).padStart(2, '0')).join('');

  // 9. Wipe wrapping key and shared secret
  secureWipe(wrappingKey);
  secureWipe(sharedSecret);

  return {
    status: 'ok',
    chatKey,
    keyId,
    senderPublicKey: payload.senderIdKey,
    tofuStatus: tofuResult.status === 'new' ? 'new'
      : tofuResult.status === 'changed' ? 'changed'
        : 'unchanged',
  };
}
