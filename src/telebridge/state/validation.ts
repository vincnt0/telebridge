/**
 * Telebridge v2 — State Validation
 *
 * Runtime validation ensuring persisted state NEVER contains plaintext secrets.
 * This is a safety net — called before every write-to-disk operation.
 */

import { PLAINTEXT_FIELD_NAMES } from './types';

/**
 * Recursively scan an object for forbidden plaintext field names.
 * Throws if any are found.
 *
 * @param obj - The object to scan (typically serialized persisted state)
 * @param path - Current path for error messages
 */
export function assertNoPlaintextSecrets(obj: unknown, path = 'root'): void {
  if (obj === undefined || obj === null || typeof obj !== 'object') {
    return;
  }

  const record = obj as Record<string, unknown>;

  for (const key of Object.keys(record)) {
    for (const forbidden of PLAINTEXT_FIELD_NAMES) {
      if (key === forbidden) {
        throw new Error(
          `SECURITY VIOLATION: Plaintext field "${forbidden}" found at ${path}.${key}. `
          + 'This field must NEVER be persisted.',
        );
      }
    }

    // Only recurse into plain objects/arrays, not strings or other primitives
    const value = record[key];
    if (typeof value === 'object' && value !== null) {
      assertNoPlaintextSecrets(value, `${path}.${key}`);
    }
  }
}

/**
 * Validate that a value looks like a base64-encoded encrypted payload,
 * not a raw plaintext secret. A valid encrypted payload should be
 * a non-empty base64 string of sufficient length (nonce + ciphertext + tag).
 */
export function assertEncryptedPayload(value: string, fieldName: string): void {
  if (!value || typeof value !== 'string') {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  // Minimum AES-GCM payload: 12 (nonce) + 1 (min ciphertext) + 16 (tag) = 29 bytes
  // Base64 of 29 bytes = 40 chars minimum
  if (value.length < 40) {
    throw new Error(
      `${fieldName} appears too short to be an encrypted payload (${value.length} chars). `
      + 'Possible plaintext leak.',
    );
  }
}
