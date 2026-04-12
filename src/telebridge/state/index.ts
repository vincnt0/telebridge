/**
 * Telebridge v2 — State Module Barrel Export
 *
 * This is the sole import point for state management.
 * Consumers should import from 'src/telebridge/state' only.
 */

export { TelebridgeState } from './TelebridgeState';

// Types
export type {
  ChatKeyRecord,
  ContactKeyHistoryEntry,
  ContactRecord,
  DecryptedChatKey,
  DecryptedIdentity,
  IdentityKeys,
  PersistedState,
  RotationInfo,
  StoredArgon2Params,
} from './types';
export {
  ContactTrustLevel,
  CURRENT_FORMAT_VERSION,
  PLAINTEXT_FIELD_NAMES,
} from './types';

// Serialization
export { deserialize, serialize } from './serialization';

// Validation
export { assertNoPlaintextSecrets } from './validation';
