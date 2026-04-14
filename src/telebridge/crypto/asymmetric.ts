/**
 * Telebridge v2 — Layer 4 Asymmetric Per-Message Encryption
 *
 * Implements the "Send Secured" (tb1.a) envelope: one fresh X25519 ephemeral
 * keypair per invocation, DH with the recipient's long-term X25519 public key,
 * HKDF → 32-byte AES-256-GCM key, encrypt plaintext, sign the envelope with
 * the sender's Ed25519 identity key.
 *
 * Wire payload layout (shared with `encode.ts:55` / `decode.ts:109`):
 *   [ephemeralX25519(32B)][nonce(12B)][ciphertext(var)][authTag(16B)][signature(64B)]
 *
 * Signature covers: ephemeralX25519 ‖ nonce ‖ ciphertext ‖ authTag
 *
 * The primitive does NOT touch the vault, state, protocol encoder/decoder,
 * or Telegram send path — it is intentionally a pure function of its inputs
 * so it can be re-used for encrypt-to-self, encrypt-to-recipient, group
 * fan-out, etc. Callers are responsible for looking up key material and
 * routing the resulting payload through `encodeSecuredMessage`.
 */

import { decrypt as aesDecrypt, encrypt as aesEncrypt } from './aes';
import { HKDF_INFO } from './hkdfInfo';
import { deriveKey } from './kdf';
import { computeSharedSecret, generateKeyExchangeKeyPair } from './keyexchange';
import { sign as ed25519Sign, verify as ed25519Verify } from './signing';
import { SIZES } from './types';
import { concatBytes, decodeUtf8, secureWipe } from './utils';
import type { SecuredMessagePayload } from '../protocol/types';

/**
 * Outcome of `decryptEnvelope`. `notForMe` means GCM auth failed (the envelope
 * wasn't encrypted to our key — the normal "hide from list" path for the
 * encrypt-to-self fan-out). `invalidSignature` means GCM succeeded but the
 * Ed25519 verify failed — treat as a warning, not a filter.
 */
export type DecryptEnvelopeResult =
  | { ok: true; plaintext: Uint8Array }
  | { ok: false; reason: 'notForMe' | 'invalidSignature' };

/**
 * Encrypt a plaintext for a single recipient X25519 public key.
 *
 * Generates a fresh ephemeral X25519 keypair per call; the private half is
 * wiped before returning. Returns a structured payload ready for
 * `encodeSecuredMessage`.
 */
export async function encryptForRecipient(
  plaintext: Uint8Array,
  recipientX25519Pub: Uint8Array,
  senderEd25519Priv: Uint8Array,
): Promise<SecuredMessagePayload> {
  if (recipientX25519Pub.length !== SIZES.X25519_PUBLIC_KEY) {
    throw new Error(`recipientX25519Pub must be ${SIZES.X25519_PUBLIC_KEY} bytes`);
  }
  if (senderEd25519Priv.length !== SIZES.ED25519_PRIVATE_KEY) {
    throw new Error(`senderEd25519Priv must be ${SIZES.ED25519_PRIVATE_KEY} bytes`);
  }

  const ephemeral = generateKeyExchangeKeyPair();

  const sharedSecret = computeSharedSecret(ephemeral.privateKey, recipientX25519Pub);
  // Derive per-envelope content key. HKDF_INFO.SECURED enforces
  // domain-separation from Layer 2 KX, which uses the same X25519 primitive.
  const contentKey = deriveKey(sharedSecret, undefined, HKDF_INFO.SECURED);

  let encrypted;
  try {
    encrypted = await aesEncrypt(plaintext, contentKey);
  } finally {
    secureWipe(contentKey);
    secureWipe(sharedSecret);
    secureWipe(ephemeral.privateKey);
  }

  // Signature covers the wire-stable envelope fields (everything except the
  // signature itself) — pinning them prevents a transport attacker from
  // swapping ciphertext while reusing the sender's identity claim.
  const signable = concatBytes(
    ephemeral.publicKey,
    encrypted.iv,
    encrypted.ciphertext,
    encrypted.authTag,
  );
  const signature = ed25519Sign(signable, senderEd25519Priv);

  return {
    ephemeralX25519: ephemeral.publicKey,
    nonce: encrypted.iv,
    ciphertext: encrypted.ciphertext,
    authTag: encrypted.authTag,
    signature,
  };
}

/**
 * Attempt to decrypt a Secured envelope.
 *
 * The flow is auth-first: run DH with our X25519 private key, HKDF to the
 * content key, and let GCM arbitrate whether the envelope was actually for
 * us. A GCM failure is the normal "not for me" path (encrypt-to-self fan-out
 * always produces a sibling envelope that we can't open). Only after GCM
 * auth succeeds do we verify the Ed25519 signature — by then we know the
 * content is intact, and the caller wants to know whether the *sender*
 * identity claim checks out.
 */
export async function decryptEnvelope(
  payload: SecuredMessagePayload,
  myX25519Priv: Uint8Array,
  senderEd25519Pub: Uint8Array,
): Promise<DecryptEnvelopeResult> {
  if (myX25519Priv.length !== SIZES.X25519_PRIVATE_KEY) {
    throw new Error(`myX25519Priv must be ${SIZES.X25519_PRIVATE_KEY} bytes`);
  }
  if (senderEd25519Pub.length !== SIZES.ED25519_PUBLIC_KEY) {
    throw new Error(`senderEd25519Pub must be ${SIZES.ED25519_PUBLIC_KEY} bytes`);
  }

  const sharedSecret = computeSharedSecret(myX25519Priv, payload.ephemeralX25519);
  const contentKey = deriveKey(sharedSecret, undefined, HKDF_INFO.SECURED);

  let plaintext: Uint8Array;
  try {
    plaintext = await aesDecrypt(
      { iv: payload.nonce, ciphertext: payload.ciphertext, authTag: payload.authTag },
      contentKey,
    );
  } catch {
    // GCM auth failed — the envelope was not encrypted to our DH output.
    // Standard case for the encrypt-to-self sibling of every Send Secured.
    secureWipe(contentKey);
    secureWipe(sharedSecret);
    return { ok: false, reason: 'notForMe' };
  } finally {
    secureWipe(contentKey);
    secureWipe(sharedSecret);
  }

  const signable = concatBytes(
    payload.ephemeralX25519,
    payload.nonce,
    payload.ciphertext,
    payload.authTag,
  );
  if (!ed25519Verify(signable, payload.signature, senderEd25519Pub)) {
    return { ok: false, reason: 'invalidSignature' };
  }

  return { ok: true, plaintext };
}

/** Convenience: decrypt and UTF-8 decode in one call. */
export async function decryptEnvelopeToText(
  payload: SecuredMessagePayload,
  myX25519Priv: Uint8Array,
  senderEd25519Pub: Uint8Array,
): Promise<
  | { ok: true; text: string }
  | { ok: false; reason: 'notForMe' | 'invalidSignature' }
> {
  const result = await decryptEnvelope(payload, myX25519Priv, senderEd25519Pub);
  if (!result.ok) return result;
  return { ok: true, text: decodeUtf8(result.plaintext) };
}
