/**
 * Telebridge v2 — Key Exchange Initiator
 *
 * Generates a fresh AES-256 chat key, wraps it via X25519 ECDH + HKDF + AES-GCM,
 * signs the payload with the sender's Ed25519 identity key, and encodes the result
 * as a `tb1.kx` wire-format message.
 *
 * The ephemeral X25519 keypair is wiped after use. The wrapping key and shared
 * secret are wiped after use. Only the chat key survives for local storage.
 *
 * The keyId (4 bytes) is embedded alongside the chat key in the encrypted blob
 * so both initiator and responder share the same key identifier.
 */

import {
  computeSharedSecret,
  concatBytes,
  encrypt,
  generateKeyExchangeKeyPair,
  randomBytes,
  secureWipe,
  sign,
  toHex,
} from '../crypto';
import { HKDF_INFO } from '../crypto/hkdfInfo';
import { SIZES } from '../crypto/types';
import { deriveKey } from '../crypto/kdf';
import { encodeKeyExchange } from '../protocol/encode';
import type { DecryptedIdentity } from '../state/types';

import type { KeyExchangeInitiation } from './types';

/** Size of the key ID prefix in the wrapped payload */
const KEY_ID_SIZE = 4;

/**
 * Initiate a key exchange handshake.
 *
 * Generates a fresh AES-256 chat key, wraps it for the recipient using
 * X25519 ECDH, and produces a signed `tb1.kx` wire message.
 *
 * @param myIdentity - Sender's decrypted identity keys (Ed25519 + X25519)
 * @param recipientX25519PublicKey - Recipient's 32-byte X25519 public key
 * @returns The wire message, chat key, and key ID for local storage
 */
export async function initiateKeyExchange(
  myIdentity: DecryptedIdentity,
  recipientX25519PublicKey: Uint8Array,
): Promise<KeyExchangeInitiation> {
  // 1. Generate fresh AES-256 chat key
  const chatKey = randomBytes(SIZES.AES_KEY);

  // 2. Generate 4-byte key ID
  const keyIdBytes = randomBytes(KEY_ID_SIZE);
  const keyId = toHex(keyIdBytes);

  // 3. Generate ephemeral X25519 keypair
  const ephemeral = generateKeyExchangeKeyPair();

  // 4. Perform ECDH: ephemeral private × recipient public → raw shared secret
  const sharedSecret = computeSharedSecret(ephemeral.privateKey, recipientX25519PublicKey);

  // 5. Derive wrapping key via HKDF-SHA256
  const wrappingKey = deriveKey(sharedSecret, undefined, HKDF_INFO.KX);

  // 6. Wrap keyId + chatKey together so responder gets both
  const wrappedPlaintext = concatBytes(keyIdBytes, chatKey);
  const encryptedPayload = await encrypt(wrappedPlaintext, wrappingKey);
  secureWipe(wrappedPlaintext);

  // Serialize encrypted payload as iv ‖ ciphertext ‖ authTag for wire format
  const encryptedChatKeyBytes = concatBytes(
    encryptedPayload.iv,
    encryptedPayload.ciphertext,
    encryptedPayload.authTag,
  );

  // 7. Build signable payload: senderIdKey ‖ ephemeralX25519 ‖ encryptedChatKey
  const signablePayload = concatBytes(
    myIdentity.ed25519PublicKey,
    ephemeral.publicKey,
    encryptedChatKeyBytes,
  );

  // 8. Sign with Ed25519 identity key
  const signature = sign(signablePayload, myIdentity.ed25519PrivateKey);

  // 9. Encode as tb1.kx wire message
  const wireMessage = encodeKeyExchange({
    senderIdKey: myIdentity.ed25519PublicKey,
    ephemeralX25519: ephemeral.publicKey,
    encryptedChatKey: encryptedChatKeyBytes,
    signature,
  });

  // 10. Wipe ephemeral private key, wrapping key, shared secret
  secureWipe(ephemeral.privateKey);
  secureWipe(wrappingKey);
  secureWipe(sharedSecret);

  return { wireMessage, chatKey, keyId };
}
