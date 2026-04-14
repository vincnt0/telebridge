/**
 * Telebridge v2 — Message Detection & Header Parsing
 *
 * Identifies Telebridge protocol messages and extracts header components.
 * A Telebridge message starts with "tb" followed by a digit — cleanly
 * distinguishes from v1 format ("b.") and regular text.
 */

import { HEADER_PATTERN, VALID_MODES } from './constants';
import type { TelebridgeHeader } from './types';

/**
 * Check whether a string is a Telebridge protocol message.
 * Returns true if text starts with "tb" followed by a digit.
 */
export function isTelebridgeMessage(text: string): boolean {
  if (text.length < 3) return false;
  return text.charCodeAt(0) === 0x74 // 't'
    && text.charCodeAt(1) === 0x62   // 'b'
    && text.charCodeAt(2) >= 0x30    // '0'
    && text.charCodeAt(2) <= 0x39;   // '9'
}

/**
 * Check whether a message is a Telebridge machine message.
 *
 * Machine messages (kx = key exchange, pk = prekey publication) carry
 * handshake bytes and should never be shown in the user-facing chat log,
 * chat-list previews, or search results.
 */
export function isTelebridgeMachineMessage(text: string): boolean {
  return text.startsWith('tb1.kx.') || text.startsWith('tb1.pk.');
}

/**
 * Parse the protocol header from a wire-format string.
 * Extracts version number and mode identifier.
 *
 * Returns undefined for invalid or unrecognized formats.
 */
export function parseHeader(text: string): TelebridgeHeader | undefined {
  const match = HEADER_PATTERN.exec(text);
  if (!match) return undefined;

  const version = parseInt(match[1], 10);
  const mode = match[2];

  if (!VALID_MODES.has(mode)) return undefined;

  return { version, mode };
}

/**
 * Extract the base64 payload portion after the header.
 * Returns undefined if the header is invalid or no payload follows.
 *
 * For "tb1.s.AAAA..." returns "AAAA..."
 */
export function getPayloadBase64(text: string): string | undefined {
  const match = HEADER_PATTERN.exec(text);
  if (!match) return undefined;

  const mode = match[2];
  if (!VALID_MODES.has(mode)) return undefined;

  // match[0] is the full header including trailing dot (e.g. "tb1.s.")
  const payload = text.slice(match[0].length);
  if (payload.length === 0) return undefined;

  return payload;
}
