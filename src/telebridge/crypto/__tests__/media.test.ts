import { Crypto } from '@peculiar/webcrypto';

import {
  encryptMedia,
  decryptMedia,
  encryptForUpload,
  decryptAfterDownload,
  isEncryptedMedia,
  shouldEncryptMediaType,
  MediaType,
  FILE_FORMAT_VERSION,
} from '../../media';
import { SIZES } from '../types';
import { randomBytes } from '../utils';

// Polyfill Web Crypto for Node/jsdom test environment
Object.defineProperty(globalThis, 'crypto', { value: new Crypto() });

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateKey(): Uint8Array {
  return randomBytes(SIZES.AES_KEY);
}

function generateTestBuffer(size: number): Uint8Array {
  const buf = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    buf[i] = i % 256;
  }
  return buf;
}

// ---------------------------------------------------------------------------
// Core encrypt → decrypt roundtrip
// ---------------------------------------------------------------------------

describe('Media Encryption — Roundtrip', () => {
  const key = generateKey();

  test('encrypt → decrypt roundtrip returns original data (small file)', async () => {
    const original = new TextEncoder().encode('Hello, Telebridge media!');
    const encrypted = await encryptMedia(original, key);
    const result = await decryptMedia(encrypted, key);

    expect(result.success).toBe(true);
    expect(result.data).toEqual(original);
  });

  test('encrypt → decrypt roundtrip with 1 byte payload', async () => {
    const original = new Uint8Array([0x42]);
    const encrypted = await encryptMedia(original, key);
    const result = await decryptMedia(encrypted, key);

    expect(result.success).toBe(true);
    expect(result.data).toEqual(original);
  });

  test('encrypt → decrypt roundtrip with empty-ish binary data', async () => {
    const original = new Uint8Array([0x00, 0x00, 0x00]);
    const encrypted = await encryptMedia(original, key);
    const result = await decryptMedia(encrypted, key);

    expect(result.success).toBe(true);
    expect(result.data).toEqual(original);
  });

  test('encrypt → decrypt roundtrip with 1KB file', async () => {
    const original = generateTestBuffer(1024);
    const encrypted = await encryptMedia(original, key);
    const result = await decryptMedia(encrypted, key);

    expect(result.success).toBe(true);
    expect(result.data).toEqual(original);
  });

  test('encrypt → decrypt roundtrip with 100KB file', async () => {
    const original = generateTestBuffer(100 * 1024);
    const encrypted = await encryptMedia(original, key);
    const result = await decryptMedia(encrypted, key);

    expect(result.success).toBe(true);
    expect(result.data).toEqual(original);
  });

  test('encrypt → decrypt roundtrip with 1MB file', async () => {
    const original = generateTestBuffer(1024 * 1024);
    const encrypted = await encryptMedia(original, key);
    const result = await decryptMedia(encrypted, key);

    expect(result.success).toBe(true);
    expect(result.data).toEqual(original);
  });

  test('encrypt → decrypt roundtrip with >10MB file', async () => {
    const original = generateTestBuffer(11 * 1024 * 1024);
    const encrypted = await encryptMedia(original, key);
    const result = await decryptMedia(encrypted, key);

    expect(result.success).toBe(true);
    expect(result.data).toEqual(original);
  }, 30000);

  test('different keys produce different ciphertext', async () => {
    const original = new TextEncoder().encode('same message');
    const key1 = generateKey();
    const key2 = generateKey();

    const enc1 = await encryptMedia(original, key1);
    const enc2 = await encryptMedia(original, key2);

    // Ciphertext should differ (ignoring version byte + nonce which also differ)
    expect(enc1).not.toEqual(enc2);
  });

  test('same key with same data produces different ciphertext (random nonce)', async () => {
    const original = new TextEncoder().encode('same message');
    const enc1 = await encryptMedia(original, key);
    const enc2 = await encryptMedia(original, key);

    // Nonces (and therefore ciphertext) should differ even for identical input
    expect(enc1).not.toEqual(enc2);

    // But both should decrypt to the same plaintext
    const r1 = await decryptMedia(enc1, key);
    const r2 = await decryptMedia(enc2, key);
    expect(r1.data).toEqual(original);
    expect(r2.data).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// Binary format verification
// ---------------------------------------------------------------------------

describe('Media Encryption — Wire Format', () => {
  const key = generateKey();

  test('encrypted output starts with version byte 0x01', async () => {
    const original = new Uint8Array([1, 2, 3]);
    const encrypted = await encryptMedia(original, key);

    expect(encrypted[0]).toBe(FILE_FORMAT_VERSION);
    expect(encrypted[0]).toBe(0x01);
  });

  test('encrypted output has correct structure: version(1) + nonce(12) + ciphertext(var) + tag(16)', async () => {
    const original = new Uint8Array(100);
    const encrypted = await encryptMedia(original, key);

    // Minimum: 1 + 12 + ciphertext + 16
    expect(encrypted.length).toBeGreaterThan(1 + 12 + 16);

    // Version
    expect(encrypted[0]).toBe(0x01);

    // Total size should be: 1 (version) + 12 (nonce) + 100 (ciphertext = same as plaintext for GCM) + 16 (tag)
    expect(encrypted.length).toBe(1 + 12 + 100 + 16);
  });

  test('nonce is 12 bytes at offset 1', async () => {
    const original = new Uint8Array([0x42]);
    const encrypted = await encryptMedia(original, key);

    const nonce = encrypted.slice(1, 13);
    expect(nonce.length).toBe(12);

    // Nonce should not be all zeros (statistically impossible for random)
    const allZero = nonce.every((b) => b === 0);
    expect(allZero).toBe(false);
  });

  test('auth tag is last 16 bytes', async () => {
    const original = new Uint8Array([0x42]);
    const encrypted = await encryptMedia(original, key);

    const authTag = encrypted.slice(encrypted.length - 16);
    expect(authTag.length).toBe(16);
  });
});

// ---------------------------------------------------------------------------
// Auth tag verification (v1 bug fix)
// ---------------------------------------------------------------------------

describe('Media Encryption — Auth Tag Integrity', () => {
  const key = generateKey();

  test('tampered ciphertext is detected (auth tag failure)', async () => {
    const original = new TextEncoder().encode('sensitive data');
    const encrypted = await encryptMedia(original, key);

    // Flip a bit in the ciphertext area (after version + nonce, before auth tag)
    const tampered = encrypted.slice();
    const ciphertextStart = 1 + 12;
    const ciphertextEnd = tampered.length - 16;
    if (ciphertextStart < ciphertextEnd) {
      tampered[ciphertextStart] ^= 0xFF;
    }

    const result = await decryptMedia(tampered, key);
    expect(result.success).toBe(false);
    expect(result.error).toContain('wrong key or tampered');
  });

  test('tampered auth tag is detected', async () => {
    const original = new TextEncoder().encode('sensitive data');
    const encrypted = await encryptMedia(original, key);

    // Flip a bit in the auth tag
    const tampered = encrypted.slice();
    tampered[tampered.length - 1] ^= 0xFF;

    const result = await decryptMedia(tampered, key);
    expect(result.success).toBe(false);
  });

  test('tampered nonce fails decryption', async () => {
    const original = new TextEncoder().encode('sensitive data');
    const encrypted = await encryptMedia(original, key);

    // Flip a bit in the nonce
    const tampered = encrypted.slice();
    tampered[1] ^= 0xFF;

    const result = await decryptMedia(tampered, key);
    expect(result.success).toBe(false);
  });

  test('wrong key fails decryption', async () => {
    const original = new TextEncoder().encode('sensitive data');
    const encrypted = await encryptMedia(original, key);

    const wrongKey = generateKey();
    const result = await decryptMedia(encrypted, wrongKey);
    expect(result.success).toBe(false);
    expect(result.error).toContain('wrong key or tampered');
  });
});

// ---------------------------------------------------------------------------
// Key validation
// ---------------------------------------------------------------------------

describe('Media Encryption — Key Validation', () => {
  test('encrypt rejects key shorter than 32 bytes', async () => {
    const shortKey = randomBytes(16);
    const data = new Uint8Array([1, 2, 3]);

    await expect(encryptMedia(data, shortKey)).rejects.toThrow('32 bytes');
  });

  test('encrypt rejects key longer than 32 bytes', async () => {
    const longKey = randomBytes(64);
    const data = new Uint8Array([1, 2, 3]);

    await expect(encryptMedia(data, longKey)).rejects.toThrow('32 bytes');
  });

  test('decrypt returns error for wrong-size key', async () => {
    const key = generateKey();
    const data = new Uint8Array([1, 2, 3]);
    const encrypted = await encryptMedia(data, key);

    const result = await decryptMedia(encrypted, randomBytes(16));
    expect(result.success).toBe(false);
    expect(result.error).toContain('32 bytes');
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('Media Encryption — Edge Cases', () => {
  test('buffer too small to be encrypted fails gracefully', async () => {
    const key = generateKey();
    const tooSmall = new Uint8Array(5); // Way too small

    const result = await decryptMedia(tooSmall, key);
    expect(result.success).toBe(false);
    expect(result.error).toContain('too small');
  });

  test('unsupported version byte fails gracefully', async () => {
    const key = generateKey();
    const data = new Uint8Array([1, 2, 3]);
    const encrypted = await encryptMedia(data, key);

    // Change version to unsupported
    const modified = encrypted.slice();
    modified[0] = 0xFF;

    const result = await decryptMedia(modified, key);
    expect(result.success).toBe(false);
    expect(result.error).toContain('Unsupported');
  });

  test('version 0x00 is not supported (avoids v1 buffer stamp confusion)', async () => {
    const key = generateKey();
    const fakeV1 = new Uint8Array(100);
    fakeV1[0] = 0x00; // v1 buffer stamp started with 0x00

    const result = await decryptMedia(fakeV1, key);
    expect(result.success).toBe(false);
  });

  test('handles binary data with null bytes throughout', async () => {
    const key = generateKey();
    const original = new Uint8Array(1000);
    original.fill(0x00);

    const encrypted = await encryptMedia(original, key);
    const result = await decryptMedia(encrypted, key);

    expect(result.success).toBe(true);
    expect(result.data).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

describe('isEncryptedMedia', () => {
  test('detects valid encrypted media', async () => {
    const key = generateKey();
    const data = new Uint8Array([1, 2, 3]);
    const encrypted = await encryptMedia(data, key);

    expect(isEncryptedMedia(encrypted)).toBe(true);
  });

  test('rejects buffer too small', () => {
    expect(isEncryptedMedia(new Uint8Array(5))).toBe(false);
  });

  test('rejects buffer with wrong version', () => {
    const buf = new Uint8Array(100);
    buf[0] = 0xFF;
    expect(isEncryptedMedia(buf)).toBe(false);
  });

  test('rejects empty buffer', () => {
    expect(isEncryptedMedia(new Uint8Array(0))).toBe(false);
  });

  // Note: version 0x01 with sufficient length passes — this is by design.
  // Random data starting with 0x01 could be a false positive, but the
  // actual GCM decryption will fail cleanly with auth tag verification.
  test('false positive (random data starting with 0x01) is handled by decryption failure', async () => {
    const key = generateKey();
    const fakeEncrypted = new Uint8Array(100);
    fakeEncrypted[0] = 0x01; // Looks like Telebridge
    crypto.getRandomValues(fakeEncrypted.subarray(1)); // Random garbage

    expect(isEncryptedMedia(fakeEncrypted)).toBe(true); // Passes detection
    const result = await decryptMedia(fakeEncrypted, key);
    expect(result.success).toBe(false); // But fails auth tag check
  });
});

// ---------------------------------------------------------------------------
// Media type coverage (v1 bug fix verification)
// ---------------------------------------------------------------------------

describe('shouldEncryptMediaType — All types covered', () => {
  test('photos ARE encrypted (v1 skipped these as "quick")', () => {
    expect(shouldEncryptMediaType(MediaType.Photo)).toBe(true);
  });

  test('videos ARE encrypted (v1 skipped these as "quick")', () => {
    expect(shouldEncryptMediaType(MediaType.Video)).toBe(true);
  });

  test('voice messages ARE encrypted (v1 did not handle)', () => {
    expect(shouldEncryptMediaType(MediaType.Voice)).toBe(true);
  });

  test('documents ARE encrypted', () => {
    expect(shouldEncryptMediaType(MediaType.Document)).toBe(true);
  });

  test('animations (GIFs) ARE encrypted', () => {
    expect(shouldEncryptMediaType(MediaType.Animation)).toBe(true);
  });

  test('video notes ARE encrypted', () => {
    expect(shouldEncryptMediaType(MediaType.VideoNote)).toBe(true);
  });

  test('stickers are NOT encrypted (public assets per spec)', () => {
    expect(shouldEncryptMediaType(MediaType.Sticker)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Upload / Download pipeline integration
// ---------------------------------------------------------------------------

describe('encryptForUpload / decryptAfterDownload', () => {
  const key = generateKey();

  test('encrypts when key and encryptable media type provided', async () => {
    const original = generateTestBuffer(500);
    const encrypted = await encryptForUpload(original, key, MediaType.Photo);

    expect(encrypted).not.toEqual(original);
    expect(encrypted[0]).toBe(FILE_FORMAT_VERSION);

    // Should round-trip through download
    const decrypted = await decryptAfterDownload(encrypted, key);
    expect(decrypted).toEqual(original);
  });

  test('passes through when no key (unencrypted chat)', async () => {
    const original = generateTestBuffer(500);
    const result = await encryptForUpload(original, undefined, MediaType.Photo);
    expect(result).toBe(original); // Same reference — not copied
  });

  test('passes through for stickers even with key', async () => {
    const original = generateTestBuffer(500);
    const result = await encryptForUpload(original, key, MediaType.Sticker);
    expect(result).toBe(original); // Same reference
  });

  test('download passes through when no key', async () => {
    const original = generateTestBuffer(500);
    const encrypted = await encryptMedia(original, key);

    const result = await decryptAfterDownload(encrypted, undefined);
    expect(result).toBe(encrypted); // Same reference — returned as-is
  });

  test('download passes through for non-Telebridge data', async () => {
    // Regular JPEG-like data (starts with 0xFF 0xD8)
    const jpegLike = new Uint8Array(1000);
    jpegLike[0] = 0xFF;
    jpegLike[1] = 0xD8;

    const result = await decryptAfterDownload(jpegLike, key);
    expect(result).toBe(jpegLike); // Same reference — not a Telebridge file
  });

  test('download falls back to original on decryption failure', async () => {
    const original = generateTestBuffer(500);
    const encrypted = await encryptMedia(original, key);

    // Try to decrypt with wrong key
    const wrongKey = generateKey();
    const result = await decryptAfterDownload(encrypted, wrongKey);

    // Should return original encrypted buffer as fallback
    expect(result).toEqual(encrypted);
  });

  test('full pipeline: all media types (photo, video, voice, document, animation, videoNote)', async () => {
    const types = [
      MediaType.Photo,
      MediaType.Video,
      MediaType.Voice,
      MediaType.Document,
      MediaType.Animation,
      MediaType.VideoNote,
    ];

    for (const mediaType of types) {
      const original = generateTestBuffer(1000 + types.indexOf(mediaType));
      const encrypted = await encryptForUpload(original, key, mediaType);

      expect(encrypted[0]).toBe(FILE_FORMAT_VERSION);
      expect(encrypted.length).toBeGreaterThan(original.length); // Overhead from version + nonce + tag

      const decrypted = await decryptAfterDownload(encrypted, key);
      expect(decrypted).toEqual(original);
    }
  });
});

// ---------------------------------------------------------------------------
// Large file test (>10MB threshold from spec)
// ---------------------------------------------------------------------------

describe('Large File Handling', () => {
  test('11MB file encrypts and decrypts correctly', async () => {
    const key = generateKey();
    const size = 11 * 1024 * 1024; // 11MB
    const original = new Uint8Array(size);
    // Fill with pattern so we can verify correctness
    for (let i = 0; i < size; i++) {
      original[i] = i % 251; // Use prime to avoid alignment patterns
    }

    const encrypted = await encryptMedia(original, key);

    // Verify size: original + 1 (version) + 12 (nonce) + 16 (tag) = original + 29
    expect(encrypted.length).toBe(size + 29);

    const result = await decryptMedia(encrypted, key);
    expect(result.success).toBe(true);
    expect(result.data!.length).toBe(size);
    expect(result.data).toEqual(original);
  }, 30000);
});
