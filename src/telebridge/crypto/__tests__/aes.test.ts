import { Crypto } from '@peculiar/webcrypto';

import { decrypt, encrypt } from '../aes';
import { SIZES } from '../types';
import { randomBytes } from '../utils';

// Polyfill Web Crypto for Node/jsdom test environment
Object.defineProperty(globalThis, 'crypto', { value: new Crypto() });

describe('AES-256-GCM', () => {
  const key = randomBytes(SIZES.AES_KEY);
  const plaintext = new TextEncoder().encode('Hello, Telebridge v2!');

  test('encrypt → decrypt roundtrip returns original plaintext', async () => {
    const payload = await encrypt(plaintext, key);
    const decrypted = await decrypt(payload, key);
    expect(decrypted).toEqual(plaintext);
  });

  test('encrypt → decrypt roundtrip with AAD', async () => {
    const aad = new TextEncoder().encode('chat-id-12345');
    const payload = await encrypt(plaintext, key, aad);
    const decrypted = await decrypt(payload, key, aad);
    expect(decrypted).toEqual(plaintext);
  });

  test('EncryptedPayload contains separate iv, ciphertext, and authTag', async () => {
    const payload = await encrypt(plaintext, key);
    expect(payload.iv).toBeInstanceOf(Uint8Array);
    expect(payload.ciphertext).toBeInstanceOf(Uint8Array);
    expect(payload.authTag).toBeInstanceOf(Uint8Array);
    expect(payload.iv.length).toBe(SIZES.GCM_NONCE);
    expect(payload.authTag.length).toBe(SIZES.GCM_TAG);
  });

  test('decrypt fails with wrong key', async () => {
    const wrongKey = randomBytes(SIZES.AES_KEY);
    const payload = await encrypt(plaintext, key);
    await expect(decrypt(payload, wrongKey)).rejects.toThrow();
  });

  test('decrypt fails with tampered ciphertext (auth tag validation)', async () => {
    const payload = await encrypt(plaintext, key);
    const tampered = new Uint8Array(payload.ciphertext);
    tampered[0] ^= 0xff;
    await expect(decrypt({ iv: payload.iv, ciphertext: tampered, authTag: payload.authTag }, key)).rejects.toThrow();
  });

  test('decrypt fails with tampered auth tag', async () => {
    const payload = await encrypt(plaintext, key);
    const tamperedTag = new Uint8Array(payload.authTag);
    tamperedTag[0] ^= 0xff;
    await expect(decrypt({ iv: payload.iv, ciphertext: payload.ciphertext, authTag: tamperedTag }, key)).rejects.toThrow();
  });

  test('decrypt fails with tampered IV', async () => {
    const payload = await encrypt(plaintext, key);
    const tamperedIv = new Uint8Array(payload.iv);
    tamperedIv[0] ^= 0xff;
    await expect(decrypt({ iv: tamperedIv, ciphertext: payload.ciphertext, authTag: payload.authTag }, key)).rejects.toThrow();
  });

  test('decrypt fails with wrong AAD', async () => {
    const aad = new TextEncoder().encode('correct-aad');
    const wrongAad = new TextEncoder().encode('wrong-aad');
    const payload = await encrypt(plaintext, key, aad);
    await expect(decrypt(payload, key, wrongAad)).rejects.toThrow();
  });

  test('decrypt fails when AAD was used but not provided', async () => {
    const aad = new TextEncoder().encode('some-aad');
    const payload = await encrypt(plaintext, key, aad);
    await expect(decrypt(payload, key)).rejects.toThrow();
  });

  test('each encryption produces a unique IV', async () => {
    const payload1 = await encrypt(plaintext, key);
    const payload2 = await encrypt(plaintext, key);
    expect(payload1.iv).not.toEqual(payload2.iv);
  });

  test('IV is 12 bytes', async () => {
    const payload = await encrypt(plaintext, key);
    expect(payload.iv.length).toBe(12);
  });

  test('rejects key of wrong size', async () => {
    const shortKey = randomBytes(16);
    await expect(encrypt(plaintext, shortKey)).rejects.toThrow();
  });

  test('handles empty plaintext', async () => {
    const empty = new Uint8Array(0);
    const payload = await encrypt(empty, key);
    const decrypted = await decrypt(payload, key);
    expect(decrypted).toEqual(empty);
  });
});
