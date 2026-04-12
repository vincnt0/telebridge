/**
 * Telebridge v2 — Detection Utilities (Render Pipeline)
 *
 * Thin wrappers re-exporting detection from the protocol module.
 * Exists so the render pipeline can import from 'src/telebridge/detect'
 * without reaching into protocol internals.
 */

export { isTelebridgeMessage, parseHeader } from './protocol';
