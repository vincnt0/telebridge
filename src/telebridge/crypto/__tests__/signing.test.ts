import { generateSigningKeyPair, sign, verify } from '../signing';

describe('Ed25519 Signing', () => {
  const keypair = generateSigningKeyPair();
  const message = new TextEncoder().encode('Trust is not optional');

  test('sign → verify succeeds with correct key', () => {
    const signature = sign(message, keypair.privateKey);
    expect(verify(message, signature, keypair.publicKey)).toBe(true);
  });

  test('verify fails with wrong public key', () => {
    const otherKeypair = generateSigningKeyPair();
    const signature = sign(message, keypair.privateKey);
    expect(verify(message, signature, otherKeypair.publicKey)).toBe(false);
  });

  test('verify fails with tampered message', () => {
    const signature = sign(message, keypair.privateKey);
    const tampered = new TextEncoder().encode('Trust is optional');
    expect(verify(tampered, signature, keypair.publicKey)).toBe(false);
  });

  test('verify fails with tampered signature', () => {
    const signature = sign(message, keypair.privateKey);
    const tampered = new Uint8Array(signature);
    tampered[0] ^= 0xff;
    expect(verify(message, tampered, keypair.publicKey)).toBe(false);
  });

  test('generates valid keypair with correct sizes', () => {
    expect(keypair.publicKey.length).toBe(32);
    expect(keypair.privateKey.length).toBe(32);
  });

  test('signature is 64 bytes', () => {
    const signature = sign(message, keypair.privateKey);
    expect(signature.length).toBe(64);
  });

  test('different messages produce different signatures', () => {
    const msg1 = new TextEncoder().encode('message one');
    const msg2 = new TextEncoder().encode('message two');
    const sig1 = sign(msg1, keypair.privateKey);
    const sig2 = sign(msg2, keypair.privateKey);
    expect(sig1).not.toEqual(sig2);
  });

  test('signs and verifies empty message', () => {
    const empty = new Uint8Array(0);
    const signature = sign(empty, keypair.privateKey);
    expect(verify(empty, signature, keypair.publicKey)).toBe(true);
  });
});
