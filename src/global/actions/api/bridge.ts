/**
 * Telebridge bridge actions — minimal Phase 2 surface.
 *
 * This file is intentionally narrow: it only wires the runtime decrypted
 * plaintext cache used by the render path. Full lock/unlock/first-run
 * handlers arrive with the Phase 3 UI commit.
 */

import type { ActionReturnType } from '../../types';

import { addActionHandler } from '../../index';

addActionHandler('bridgeSetDecryptedText', (global, actions, payload): ActionReturnType => {
  const { messageKey, text } = payload;
  // Skip writes if the cached entry already matches — spare a needless re-render.
  if (global.bridge.decryptedByKey[messageKey] === text) {
    return undefined;
  }
  return {
    ...global,
    bridge: {
      ...global.bridge,
      decryptedByKey: {
        ...global.bridge.decryptedByKey,
        [messageKey]: text,
      },
    },
  };
});

addActionHandler('bridgeClearDecryptedCache', (global): ActionReturnType => {
  return {
    ...global,
    bridge: {
      ...global.bridge,
      decryptedByKey: {},
    },
  };
});
