/**
 * Telebridge v2 — Validation Unit Tests
 */

import { assertNoPlaintextSecrets, assertEncryptedPayload } from '../validation';

describe('assertNoPlaintextSecrets', () => {
  it('should pass for clean objects', () => {
    expect(() => assertNoPlaintextSecrets({
      formatVersion: 1,
      passwordSalt: 'abc123==',
      identity: {
        encryptedEd25519PrivateKey: 'longbase64string...',
      },
    })).not.toThrow();
  });

  it('should throw for derivedKey field', () => {
    expect(() => assertNoPlaintextSecrets({
      derivedKey: 'should-not-be-here',
    })).toThrow('SECURITY VIOLATION');
  });

  it('should throw for nested plaintext fields', () => {
    expect(() => assertNoPlaintextSecrets({
      identity: {
        password: 'leaked!',
      },
    })).toThrow('SECURITY VIOLATION');
  });

  it('should throw for privateKey field', () => {
    expect(() => assertNoPlaintextSecrets({
      privateKey: new Uint8Array(32),
    })).toThrow('SECURITY VIOLATION');
  });

  it('should handle null and undefined gracefully', () => {
    expect(() => assertNoPlaintextSecrets(undefined)).not.toThrow();
    expect(() => assertNoPlaintextSecrets(null)).not.toThrow();
  });
});

describe('assertEncryptedPayload', () => {
  it('should pass for sufficiently long base64 strings', () => {
    const longString = 'A'.repeat(60);
    expect(() => assertEncryptedPayload(longString, 'test')).not.toThrow();
  });

  it('should throw for too-short strings', () => {
    expect(() => assertEncryptedPayload('short', 'test')).toThrow('too short');
  });

  it('should throw for empty strings', () => {
    expect(() => assertEncryptedPayload('', 'test')).toThrow('non-empty');
  });
});
