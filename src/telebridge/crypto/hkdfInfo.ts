/**
 * Telebridge v2 — HKDF Domain-Separation Constants
 *
 * Every HKDF derivation in the codebase MUST pass an `info` string from this
 * module. Distinct info strings guarantee that two protocols sharing the same
 * input keying material still produce non-overlapping derived keys — a
 * standard HKDF domain-separation requirement (RFC 5869 §3.2).
 *
 * Adding a new mode: reserve the string here, update call sites, add a test
 * that the string is byte-stable across protocol versions.
 *
 * Code-review finding LOW (docs/notes/code-review-2026-04-14.md): Layer 2 KX
 * previously used the bare literal `'telebridge-v2-kx'` inline. Layer 4
 * Secured Messages share the same X25519 DH primitive, so without an explicit
 * info string the derived AES key would be indistinguishable from a KX
 * wrapping key for the same DH output. Hence `SECURED` below.
 */
import { encodeUtf8 } from './utils';

export const HKDF_INFO = {
  /** Layer 2 key-exchange chat-key wrapping key */
  KX: encodeUtf8('telebridge-v2-kx'),
  /** Layer 4 Secured Messages per-envelope content key */
  SECURED: encodeUtf8('telebridge-v2-secured'),
} as const;
