/**
 * Telebridge v2 — Decryption Result Types
 *
 * Used by the message render pipeline to communicate decryption outcomes.
 * Each status maps to a distinct user-facing state (success, locked, failed, etc.).
 */

/** Possible outcomes of attempting to decrypt a Telebridge message */
export type DecryptionStatus =
  | 'success'
  | 'noKey'
  | 'wrongKey'
  | 'invalidSignature'
  | 'malformed';

/** Result of a decryption attempt on a single message */
export interface DecryptionResult {
  /** Outcome of the decryption attempt */
  status: DecryptionStatus;
  /** Decrypted plaintext — only present when status === 'success' */
  text?: string;
  /** Whether the sender's Ed25519 signature was verified */
  isSignatureVerified?: boolean;
  /** Human-readable error for debugging (not shown to users) */
  error?: string;
}
