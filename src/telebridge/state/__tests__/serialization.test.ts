/**
 * Telebridge — serialization & vault-format migration tests.
 *
 * Covers the v1 → v2 migration introduced with the per-contact key archive
 * (§6.1.3): ContactRecord shape change, ChatKeyRecord gains derivedFromKeyId,
 * formatVersion bump.
 */

import { Crypto } from '@peculiar/webcrypto';

// Polyfill Web Crypto for Node/jsdom test environment
Object.defineProperty(globalThis, 'crypto', { value: new Crypto() });

import { randomBytes, toBase64 } from '../../crypto';
import { deserialize, deriveKeyId, migrateContactRecord, serialize } from '../serialization';
import { ContactTrustLevel, CURRENT_FORMAT_VERSION } from '../types';
import type { PersistedState } from '../types';

function makeV1Scaffold(overrides: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    formatVersion: 1,
    argon2Params: {
      memoryCost: 1024, timeCost: 1, parallelism: 1, hashLength: 32,
    },
    passwordSalt: toBase64(randomBytes(32)),
    // 40+ char dummy value — validation only checks length and type.
    passwordVerifier: 'A'.repeat(64),
    chatKeys: {},
    contacts: {},
    protocolVersion: 1,
    supportedVersions: [1],
    ...overrides,
  };
}

function makeLegacyContact(
  trustLevel: ContactTrustLevel,
  opts: { withVerifiedAt?: boolean; firstSeen?: number } = {},
) {
  const ed25519PublicKey = toBase64(randomBytes(32));
  const x25519PublicKey = toBase64(randomBytes(32));
  const firstSeen = opts.firstSeen ?? 1_700_000_000_000;
  return {
    ed25519PublicKey,
    x25519PublicKey,
    trustLevel,
    firstSeen,
    verifiedAt: opts.withVerifiedAt ? firstSeen + 10_000 : undefined,
    keyHistory: [],
  };
}

describe('serialization — v1 → v2 migration', () => {
  describe('migrateContactRecord matrix — {Initial, Verified, Changed} × {with/without verifiedAt}', () => {
    const matrix: Array<{ level: ContactTrustLevel; withVerifiedAt: boolean; expectedOrigin: string }> = [
      { level: ContactTrustLevel.Initial, withVerifiedAt: false, expectedOrigin: 'tofu' },
      { level: ContactTrustLevel.Initial, withVerifiedAt: true, expectedOrigin: 'tofu' },
      { level: ContactTrustLevel.Changed, withVerifiedAt: false, expectedOrigin: 'tofu' },
      { level: ContactTrustLevel.Changed, withVerifiedAt: true, expectedOrigin: 'tofu' },
      { level: ContactTrustLevel.Verified, withVerifiedAt: false, expectedOrigin: 'post-hoc-qr' },
      { level: ContactTrustLevel.Verified, withVerifiedAt: true, expectedOrigin: 'post-hoc-qr' },
    ];

    for (const { level, withVerifiedAt, expectedOrigin } of matrix) {
      it(`migrates trustLevel=${level} ${withVerifiedAt ? 'with' : 'without'} verifiedAt → origin=${expectedOrigin}`, () => {
        const legacy = makeLegacyContact(level, { withVerifiedAt });
        const migrated = migrateContactRecord('user-xyz', legacy);

        expect(migrated.userId).toBe('user-xyz');
        expect(migrated.trustLevel).toBe(level);
        expect(migrated.firstSeen).toBe(legacy.firstSeen);
        expect(migrated.keys.length).toBe(1);
        expect(migrated.activeKeyId).toBe(migrated.keys[0].keyId);

        const entry = migrated.keys[0];
        expect(entry.origin).toBe(expectedOrigin);
        expect(entry.keyId).toBe(deriveKeyId(legacy.ed25519PublicKey));
        expect(entry.ed25519PublicKey).toBe(legacy.ed25519PublicKey);
        expect(entry.x25519PublicKey).toBe(legacy.x25519PublicKey);
        expect(entry.firstSeen).toBe(legacy.firstSeen);
        expect(entry.lastUsed).toBe(withVerifiedAt ? legacy.verifiedAt : legacy.firstSeen);
      });
    }
  });

  it('stamps chat-key derivedFromKeyId from the matching contact at migration time', () => {
    const legacy = makeLegacyContact(ContactTrustLevel.Verified, { withVerifiedAt: true });
    const v1 = makeV1Scaffold({
      contacts: { 'peer-1': legacy },
      chatKeys: {
        'peer-1': {
          encryptedKey: 'x'.repeat(64),
          keyId: 'deadbeef',
          established: 1_700_000_000_000,
          rotationVersion: 0,
          lastRotatedAt: 1_700_000_000_000,
          messageCount: 0,
        },
      },
    });

    const migrated = deserialize(JSON.stringify(v1));
    expect(migrated.formatVersion).toBe(CURRENT_FORMAT_VERSION);

    const expectedKeyId = deriveKeyId(legacy.ed25519PublicKey);
    expect(migrated.contacts['peer-1'].activeKeyId).toBe(expectedKeyId);
    expect(migrated.chatKeys['peer-1'].derivedFromKeyId).toBe(expectedKeyId);
  });

  it('leaves orphan chat-key derivedFromKeyId = "" when no matching contact exists', () => {
    const v1 = makeV1Scaffold({
      contacts: {},
      chatKeys: {
        'orphan-chat': {
          encryptedKey: 'y'.repeat(64),
          keyId: 'cafebabe',
          established: 1_700_000_000_000,
          rotationVersion: 0,
          lastRotatedAt: 1_700_000_000_000,
          messageCount: 0,
        },
      },
    });

    const migrated = deserialize(JSON.stringify(v1));
    expect(migrated.chatKeys['orphan-chat'].derivedFromKeyId).toBe('');
  });

  it('errors cleanly when parsing a blob written by a newer format version', () => {
    const future = makeV1Scaffold({ formatVersion: CURRENT_FORMAT_VERSION + 1 });
    expect(() => deserialize(JSON.stringify(future)))
      .toThrow('Vault was written by a newer version of Telebridge.');
  });

  it('round-trips migrated v1 → v2 → serialize → deserialize without losing fields', () => {
    const legacy = makeLegacyContact(ContactTrustLevel.Changed, { withVerifiedAt: true });
    const v1 = makeV1Scaffold({
      contacts: { 'peer-rt': legacy },
      chatKeys: {
        'peer-rt': {
          encryptedKey: 'z'.repeat(64),
          keyId: '12345678',
          established: 1_700_000_001_000,
          rotationVersion: 2,
          lastRotatedAt: 1_700_000_002_000,
          previousEncryptedKey: 'p'.repeat(64),
          previousKeyId: 'deadbeef',
          messageCount: 42,
        },
      },
    });

    const firstPass = deserialize(JSON.stringify(v1));
    const reSerialized = serialize(firstPass as PersistedState);
    const secondPass = deserialize(reSerialized);

    expect(secondPass.formatVersion).toBe(CURRENT_FORMAT_VERSION);
    expect(secondPass.contacts['peer-rt'].keys.length).toBe(1);
    expect(secondPass.contacts['peer-rt'].keys[0].ed25519PublicKey).toBe(legacy.ed25519PublicKey);
    expect(secondPass.contacts['peer-rt'].keys[0].x25519PublicKey).toBe(legacy.x25519PublicKey);
    expect(secondPass.contacts['peer-rt'].trustLevel).toBe(ContactTrustLevel.Changed);
    expect(secondPass.contacts['peer-rt'].activeKeyId).toBe(deriveKeyId(legacy.ed25519PublicKey));

    const chat = secondPass.chatKeys['peer-rt'];
    expect(chat.derivedFromKeyId).toBe(deriveKeyId(legacy.ed25519PublicKey));
    expect(chat.rotationVersion).toBe(2);
    expect(chat.previousKeyId).toBe('deadbeef');
    expect(chat.messageCount).toBe(42);
    expect(chat.established).toBe(1_700_000_001_000);
  });
});
