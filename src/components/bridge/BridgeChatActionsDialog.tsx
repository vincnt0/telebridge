import { sha256 } from '@noble/hashes/sha2.js';

import {
  memo, useEffect, useLayoutEffect, useMemo, useRef, useState,
} from '../../lib/teact/teact';
import { getActions, withGlobal } from '../../global';

import { STRICTERDOM_ENABLED } from '../../config';
import { disableStrict, enableStrict } from '../../lib/fasterdom/stricterdom';
import { toBase64 } from '../../telebridge/crypto';
import { getTelebridgeVault } from '../../telebridge/send';
import buildClassName from '../../util/buildClassName';

import useAsync from '../../hooks/useAsync';
import useLang from '../../hooks/useLang';
import useLastCallback from '../../hooks/useLastCallback';

import Icon from '../common/icons/Icon';
import Button from '../ui/Button';
import Modal from '../ui/Modal';
import BridgeIdentityQrView from './BridgeIdentityQrView';
import BridgeScannerView from './BridgeScannerView';

import styles from './BridgeChatActionsDialog.module.scss';

const QR_SIZE = 240;
const QR_MUTATION_DURATION = 50;
const SAFETY_NUMBER_GROUP_SIZE = 5;
const SAFETY_NUMBER_GROUPS = 12;

type ViewMode = 'menu' | 'verify' | 'confirmRemove' | 'scan' | 'showMyQr';

type OwnProps = {
  isOpen: boolean;
  chatId: string;
  onClose: NoneToVoidFunction;
};

type StateProps = {
  isInitialized: boolean;
  isUnlocked: boolean;
  hasContactKey: boolean;
  tofuStatus?: 'new' | 'changed' | 'unchanged' | 'verified';
  isBusy: boolean;
};

// Singleton-per-module loader — matches the pattern in AuthQrCode.
let qrCodeStylingPromise: Promise<typeof import('qr-code-styling')> | undefined;
function ensureQrCodeStyling() {
  if (!qrCodeStylingPromise) {
    qrCodeStylingPromise = import('qr-code-styling');
  }
  return qrCodeStylingPromise;
}

const BridgeChatActionsDialog = ({
  isOpen,
  chatId,
  isInitialized,
  isUnlocked,
  hasContactKey,
  tofuStatus,
  isBusy,
  onClose,
}: OwnProps & StateProps) => {
  const {
    bridgeRemoveChatKey, bridgeVerifyContact, bridgeApplyInPersonScan, showNotification,
  } = getActions();
  const lang = useLang();

  const [view, setView] = useState<ViewMode>('menu');
  const qrContainerRef = useRef<HTMLDivElement>();
  const [isQrMounted, setIsQrMounted] = useState(false);

  useEffect(() => {
    if (!isOpen) {
      setView('menu');
      setIsQrMounted(false);
    }
  }, [isOpen]);

  // Derive the pair fingerprint + QR payload once per dialog-open. Sorting the
  // two public keys before hashing makes the safety number symmetric: both
  // sides compute the same digits regardless of who's looking at whom.
  const { result: fingerprint } = useAsync(async () => {
    if (!isOpen || !isUnlocked || !isInitialized || !hasContactKey) return undefined;
    const vault = getTelebridgeVault();
    const myKeys = vault.getPublicKeys();
    const contactX25519 = vault.getContactX25519PublicKey(chatId);
    if (!myKeys || !contactX25519) return undefined;

    const a = toBase64(myKeys.x25519PublicKey);
    const b = toBase64(contactX25519);
    const [first, second] = a < b ? [myKeys.x25519PublicKey, contactX25519] : [contactX25519, myKeys.x25519PublicKey];
    const combined = new Uint8Array(first.length + second.length);
    combined.set(first, 0);
    combined.set(second, first.length);
    const digest = sha256(combined);

    const safetyNumber = formatSafetyNumber(digest);
    const qrPayload = `tb1-verify:${toBase64(digest)}`;
    return { safetyNumber, qrPayload };
  }, [isOpen, isUnlocked, isInitialized, hasContactKey, chatId]);

  const { result: qrCode } = useAsync(async () => {
    if (view !== 'verify') return undefined;
    const QrCodeStyling = (await ensureQrCodeStyling()).default;
    return new QrCodeStyling({
      width: QR_SIZE,
      height: QR_SIZE,
      margin: 8,
      type: 'svg',
      dotsOptions: { type: 'rounded' },
      cornersSquareOptions: { type: 'extra-rounded' },
      qrOptions: { errorCorrectionLevel: 'M' },
    });
  }, [view]);

  useLayoutEffect(() => {
    if (view !== 'verify' || !qrCode || !fingerprint || !qrContainerRef.current) {
      return undefined;
    }

    if (STRICTERDOM_ENABLED) disableStrict();

    qrCode.update({ data: fingerprint.qrPayload });
    if (!isQrMounted) {
      qrCode.append(qrContainerRef.current);
      setIsQrMounted(true);
    }

    if (STRICTERDOM_ENABLED) {
      setTimeout(() => enableStrict(), QR_MUTATION_DURATION);
    }
    return undefined;
  }, [view, qrCode, fingerprint, isQrMounted]);

  const handleOpenVerify = useLastCallback(() => setView('verify'));
  const handleOpenConfirmRemove = useLastCallback(() => setView('confirmRemove'));
  const handleOpenScan = useLastCallback(() => setView('scan'));
  const handleOpenShowMyQr = useLastCallback(() => {
    if (!isUnlocked) {
      showNotification({ message: lang('BridgeShowMyQrUnlockRequired') });
      onClose();
      return;
    }
    setView('showMyQr');
  });
  const handleBackToMenu = useLastCallback(() => {
    setIsQrMounted(false);
    setView('menu');
  });

  const handleBundleDetected = useLastCallback((bundleText: string) => {
    bridgeApplyInPersonScan({ peerUserId: chatId, bundleText });
    onClose();
  });

  const handleMarkVerified = useLastCallback(() => {
    bridgeVerifyContact({ contactId: chatId });
    onClose();
  });

  const handleConfirmRemove = useLastCallback(() => {
    bridgeRemoveChatKey({ chatId });
    onClose();
  });

  const verifiedBadge = useMemo(() => {
    if (tofuStatus === 'verified') return lang('BridgeVerifiedBadge');
    if (tofuStatus === 'changed') return lang('BridgeKeyChangedBadge');
    return lang('BridgeUnverifiedBadge');
  }, [tofuStatus, lang]);

  const badgeModifier = tofuStatus === 'verified'
    ? styles.verified
    : tofuStatus === 'changed'
      ? styles.changed
      : styles.unverified;

  const title = view === 'verify'
    ? lang('BridgeVerifyContactTitle')
    : view === 'confirmRemove'
      ? lang('BridgeRemoveKeyTitle')
      : view === 'showMyQr'
        ? lang('BridgeShowMyQrTitle')
        : view === 'scan'
          ? lang('BridgeScannerTitle')
          : lang('BridgeEncryptedChatMenuTitle');

  if (view === 'scan') {
    return (
      <BridgeScannerView
        isOpen={isOpen}
        onBundleDetected={handleBundleDetected}
        onCancel={handleBackToMenu}
      />
    );
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={title}
      hasCloseButton
      className={styles.modal}
    >
      {view === 'menu' && (
        <div className={styles.menu}>
          <div className={buildClassName(styles.statusRow, badgeModifier)}>
            <Icon name="lock" className={styles.statusIcon} />
            <span className={styles.statusLabel}>{verifiedBadge}</span>
          </div>
          <button
            type="button"
            className={styles.menuItem}
            onClick={handleOpenVerify}
            disabled={!hasContactKey}
          >
            <Icon name="check" className={styles.menuItemIcon} />
            <span>{lang('BridgeVerifyContactMenuItem')}</span>
          </button>
          <button
            type="button"
            className={styles.menuItem}
            onClick={handleOpenScan}
          >
            <Icon name="camera" className={styles.menuItemIcon} />
            <span>{lang('BridgeScanMenuItem')}</span>
          </button>
          <button
            type="button"
            className={styles.menuItem}
            onClick={handleOpenShowMyQr}
          >
            <Icon name="eye" className={styles.menuItemIcon} />
            <span>{lang('BridgeShowMyQrMenuItem')}</span>
          </button>
          <button
            type="button"
            className={buildClassName(styles.menuItem, styles.menuItemDanger)}
            onClick={handleOpenConfirmRemove}
          >
            <Icon name="delete" className={styles.menuItemIcon} />
            <span>{lang('BridgeRemoveKeyMenuItem')}</span>
          </button>
          {!hasContactKey && (
            <p className={styles.hint}>{lang('BridgeNoContactKey')}</p>
          )}
        </div>
      )}

      {view === 'verify' && (
        <div className={styles.verify}>
          <p className={styles.description}>{lang('BridgeVerifyContactText')}</p>
          <div className={styles.qrWrapper}>
            <div ref={qrContainerRef} className={styles.qrInner} />
          </div>
          <p className={styles.safetyLabel}>{lang('BridgeSafetyNumberLabel')}</p>
          <pre className={styles.safetyNumber}>
            {fingerprint?.safetyNumber ?? ''}
          </pre>
          <div className={styles.verifyActions}>
            <Button color="translucent" onClick={handleBackToMenu} disabled={isBusy}>
              {lang('Back')}
            </Button>
            <Button color="primary" onClick={handleMarkVerified} disabled={isBusy}>
              {lang('BridgeMarkVerifiedButton')}
            </Button>
          </div>
        </div>
      )}

      {view === 'showMyQr' && (
        <div className={styles.verify}>
          <BridgeIdentityQrView />
          <div className={styles.verifyActions}>
            <Button color="translucent" onClick={handleBackToMenu}>
              {lang('Back')}
            </Button>
          </div>
        </div>
      )}

      {view === 'confirmRemove' && (
        <div className={styles.confirm}>
          <p className={styles.description}>{lang('BridgeRemoveKeyText')}</p>
          <div className={styles.verifyActions}>
            <Button color="translucent" onClick={handleBackToMenu} disabled={isBusy}>
              {lang('Cancel')}
            </Button>
            <Button color="danger" onClick={handleConfirmRemove} disabled={isBusy}>
              {lang('BridgeRemoveKeyConfirm')}
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );
};

// Format the 32-byte digest as 12 × 5-digit groups, Signal-style.
// Each group = 4 bytes → mod 100000 → 5 digits, zero-padded.
function formatSafetyNumber(digest: Uint8Array): string {
  const groups: string[] = [];
  for (let i = 0; i < SAFETY_NUMBER_GROUPS; i++) {
    const offset = i * 4;
    const value = (
      (digest[offset] << 24)
      | (digest[offset + 1] << 16)
      | (digest[offset + 2] << 8)
      | digest[offset + 3]
    ) >>> 0;
    groups.push(String(value % 100000).padStart(SAFETY_NUMBER_GROUP_SIZE, '0'));
  }
  // Render in 3 rows × 4 groups for readability.
  const rows: string[] = [];
  for (let r = 0; r < 3; r++) {
    rows.push(groups.slice(r * 4, r * 4 + 4).join(' '));
  }
  return rows.join('\n');
}

export default memo(withGlobal<OwnProps>(
  (global, { chatId }): Complete<StateProps> => ({
    isInitialized: global.bridge.isInitialized,
    isUnlocked: global.bridge.isUnlocked,
    hasContactKey: Boolean(global.bridge.contactKeyIds[chatId]),
    tofuStatus: global.bridge.contactTofuStatusByContactId[chatId],
    isBusy: Boolean(global.bridge.isBusy),
  }),
)(BridgeChatActionsDialog));
