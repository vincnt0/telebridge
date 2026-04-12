import { computeSharedSecret, generateKeyExchangeKeyPair } from '../keyexchange';
import { deriveKey } from '../kdf';

describe('X25519 ECDH Key Exchange', () => {
  test('Alice and Bob compute identical shared secrets', () => {
    const alice = generateKeyExchangeKeyPair();
    const bob = generateKeyExchangeKeyPair();

    const secretAlice = computeSharedSecret(alice.privateKey, bob.publicKey);
    const secretBob = computeSharedSecret(bob.privateKey, alice.publicKey);

    expect(secretAlice).toEqual(secretBob);
  });

  test('shared secret is 32 bytes', () => {
    const alice = generateKeyExchangeKeyPair();
    const bob = generateKeyExchangeKeyPair();

    const secret = computeSharedSecret(alice.privateKey, bob.publicKey);
    expect(secret.length).toBe(32);
  });

  test('shared secret differs with wrong private key', () => {
    const alice = generateKeyExchangeKeyPair();
    const bob = generateKeyExchangeKeyPair();
    const charlie = generateKeyExchangeKeyPair();

    const secretAB = computeSharedSecret(alice.privateKey, bob.publicKey);
    const secretCB = computeSharedSecret(charlie.privateKey, bob.publicKey);

    expect(secretAB).not.toEqual(secretCB);
  });

  test('shared secret is not all zeros', () => {
    const alice = generateKeyExchangeKeyPair();
    const bob = generateKeyExchangeKeyPair();

    const secret = computeSharedSecret(alice.privateKey, bob.publicKey);
    const allZeros = new Uint8Array(32);
    expect(secret).not.toEqual(allZeros);
  });

  test('shared secret is post-processed through HKDF (integration)', () => {
    const alice = generateKeyExchangeKeyPair();
    const bob = generateKeyExchangeKeyPair();

    const rawSecret = computeSharedSecret(alice.privateKey, bob.publicKey);
    const info = new TextEncoder().encode('Telebridge-v2-chat-key');

    // Derive an actual encryption key from the raw secret
    const derivedKey = deriveKey(rawSecret, undefined, info);
    expect(derivedKey.length).toBe(32);
    // Derived key should differ from raw secret
    expect(derivedKey).not.toEqual(rawSecret);
  });

  test('generates keypairs with correct sizes', () => {
    const kp = generateKeyExchangeKeyPair();
    expect(kp.publicKey.length).toBe(32);
    expect(kp.privateKey.length).toBe(32);
  });
});
