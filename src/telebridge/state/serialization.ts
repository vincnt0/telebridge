/**
 * Telebridge v2 — State Serialization
 *
 * Serialize/deserialize TelebridgeState to/from a persistable JSON format.
 * CRITICAL: Only encrypted fields make it to the output.
 * Includes format version for future migration.
 */

import type { PersistedState } from './types';
import { CURRENT_FORMAT_VERSION } from './types';
import { assertNoPlaintextSecrets } from './validation';

/**
 * Serialize persisted state to a JSON string.
 * Validates that no plaintext secrets are present before serialization.
 *
 * @param state - The persisted state object (must contain only encrypted/public data)
 * @returns JSON string safe for storage
 * @throws If plaintext secrets are detected
 */
export function serialize(state: PersistedState): string {
  // Safety net: scan for plaintext secrets before writing
  assertNoPlaintextSecrets(state);

  return JSON.stringify(state);
}

/**
 * Deserialize a JSON string to persisted state.
 * Validates format version and structure.
 *
 * @param json - JSON string from storage
 * @returns Parsed PersistedState
 * @throws If format is invalid or version is unsupported
 */
export function deserialize(json: string): PersistedState {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error('Invalid persisted state: not valid JSON');
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Invalid persisted state: not an object');
  }

  const state = parsed as Record<string, unknown>;

  if (typeof state.formatVersion !== 'number') {
    throw new Error('Invalid persisted state: missing formatVersion');
  }

  if (state.formatVersion > CURRENT_FORMAT_VERSION) {
    throw new Error(
      `Unsupported format version ${state.formatVersion}. `
      + `This client supports up to version ${CURRENT_FORMAT_VERSION}. `
      + 'Please update Telebridge.',
    );
  }

  // Migrate from older versions if needed in future
  // For now, version 1 is the only version
  if (state.formatVersion < 1) {
    throw new Error(`Invalid format version: ${state.formatVersion}`);
  }

  // Validate required fields
  if (typeof state.passwordSalt !== 'string') {
    throw new Error('Invalid persisted state: missing passwordSalt');
  }
  if (typeof state.passwordVerifier !== 'string') {
    throw new Error('Invalid persisted state: missing passwordVerifier');
  }
  if (typeof state.argon2Params !== 'object' || state.argon2Params === null) {
    throw new Error('Invalid persisted state: missing argon2Params');
  }

  return parsed as PersistedState;
}

/**
 * Create an empty persisted state scaffold.
 * Used for first-run initialization before any keys are generated.
 */
export function createEmptyPersistedState(): PersistedState {
  return {
    formatVersion: CURRENT_FORMAT_VERSION,
    argon2Params: {
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 1,
      hashLength: 32,
    },
    passwordSalt: '',
    passwordVerifier: '',
    chatKeys: {},
    contacts: {},
    protocolVersion: 1,
    supportedVersions: [1],
  };
}
