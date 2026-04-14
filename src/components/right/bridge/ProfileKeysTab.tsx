import {
  memo, useEffect, useMemo, useState,
} from '../../../lib/teact/teact';
import { getActions, withGlobal } from '../../../global';

import { getTelebridgeVault } from '../../../telebridge/send';
import buildClassName from '../../../util/buildClassName';

import useFlag from '../../../hooks/useFlag';
import useLang from '../../../hooks/useLang';
import useLastCallback from '../../../hooks/useLastCallback';

import BridgeIdentityQrView from '../../bridge/BridgeIdentityQrView';
import BridgeScannerView from '../../bridge/BridgeScannerView';
import BridgeContactKeyHistoryRow from '../../left/settings/BridgeContactKeyHistoryRow';
import Button from '../../ui/Button';
import Modal from '../../ui/Modal';

import styles from './ProfileKeysTab.module.scss';

type OwnProps = {
  chatId: string;
};

type StateProps = {
  isBridgeUnlocked: boolean;
  isBridgeInitialized: boolean;
  hasContactKey: boolean;
  hasChatKey: boolean;
  isKxInProgress: boolean;
  isDebugMode: boolean;
  persistedJson?: string;
  lastExport?: {
    peerUserId: string;
    keyId: string;
    json: string;
    qrText: string;
  };
  lastError?: string;
  contactKeyIds: Record<string, true>;
};

type StatusBadge = 'unlocked' | 'locked' | 'notSetUp';

const ProfileKeysTab = ({
  chatId,
  isBridgeUnlocked,
  isBridgeInitialized,
  hasContactKey,
  hasChatKey,
  isKxInProgress,
  isDebugMode,
  persistedJson,
  lastExport,
  lastError,
  contactKeyIds,
}: OwnProps & StateProps) => {
  const { bridgeImportContactKey, bridgeApplyInPersonScan, bridgeSetManualChatKey } = getActions();

  const lang = useLang();

  const [isImportOpen, openImport, closeImport] = useFlag(false);
  const [isScanOpen, openScan, closeScan] = useFlag(false);
  const [isMyQrOpen, openMyQr, closeMyQr] = useFlag(false);
  const [isManualKeyOpen, openManualKeyModal, closeManualKeyModal] = useFlag(false);
  const [importText, setImportText] = useState('');
  const [manualKeyText, setManualKeyText] = useState('');

  // Mirror SettingsBridgeContacts: bump a token after every mutating action so
  // the embedded history row re-pulls from the vault. Folding all the bridge
  // signals together is intentional belt-and-suspenders.
  const contactCount = useMemo(() => Object.keys(contactKeyIds).length, [contactKeyIds]);
  const refreshToken = useMemo(
    () => `${contactCount}|${persistedJson ?? ''}|${lastExport ? lastExport.keyId : ''}|${lastError ?? ''}`,
    [contactCount, persistedJson, lastExport, lastError],
  );

  const statusBadge: StatusBadge = !isBridgeInitialized
    ? 'notSetUp'
    : isBridgeUnlocked ? 'unlocked' : 'locked';

  // Pull the active contact key id directly from the vault (only safe while
  // unlocked). Refresh whenever the vault mutates so badge stays accurate.
  const [activeShortKeyId, setActiveShortKeyId] = useState<string | undefined>(undefined);
  useEffect(() => {
    if (!isBridgeUnlocked || !hasContactKey) {
      setActiveShortKeyId(undefined);
      return;
    }
    const vault = getTelebridgeVault();
    const entries = vault.listContactKeys(chatId);
    const active = entries.find((k) => !k.archivedAt) ?? entries[0];
    setActiveShortKeyId(active ? active.keyId.slice(0, 8) : undefined);
  }, [chatId, isBridgeUnlocked, hasContactKey, refreshToken]);

  const handleImportSubmit = useLastCallback(() => {
    const trimmed = importText.trim();
    if (!trimmed) return;
    bridgeImportContactKey({ peerUserId: chatId, payload: trimmed });
    setImportText('');
    closeImport();
  });

  const handleBundleDetected = useLastCallback((bundleText: string) => {
    bridgeApplyInPersonScan({ peerUserId: chatId, bundleText });
    closeScan();
  });

  const handleManualKeySubmit = useLastCallback(() => {
    const trimmed = manualKeyText.trim();
    if (!trimmed) return;
    bridgeSetManualChatKey({ chatId, keyText: trimmed });
    setManualKeyText('');
    closeManualKeyModal();
  });

  return (
    <div className={styles.root}>
      <KeysTabStatusSection
        statusBadge={statusBadge}
        hasContactKey={hasContactKey}
        hasChatKey={hasChatKey}
        isKxInProgress={isKxInProgress}
        activeShortKeyId={activeShortKeyId}
      />

      {isBridgeUnlocked && hasContactKey && (
        <section className={styles.section}>
          <h4 className={styles.sectionTitle}>{lang('BridgeKeysTabActiveSection')}</h4>
          <BridgeContactKeyHistoryRow
            userId={chatId}
            refreshToken={refreshToken}
            lastExport={lastExport}
            lastError={lastError}
          />
        </section>
      )}

      {isBridgeUnlocked && (
        <KeysTabActionButtons
          onImport={openImport}
          onScan={openScan}
          onShowMyQr={openMyQr}
        />
      )}

      {isDebugMode && (
        <section className={styles.devToolsSection}>
          <h4 className={styles.sectionTitle}>{lang('BridgeKeysTabDevToolsSection')}</h4>
          <p className={styles.devToolsHint}>{lang('BridgeKeysTabDevToolsHint')}</p>
          <Button size="smaller" color="danger" onClick={openManualKeyModal}>
            {lang('BridgeKeysTabDevToolsSetKeyButton')}
          </Button>
        </section>
      )}

      <Modal
        isOpen={isManualKeyOpen}
        onClose={closeManualKeyModal}
        title={lang('BridgeKeysTabDevToolsDialogTitle')}
        hasCloseButton
      >
        <p className={styles.devToolsDialogText}>{lang('BridgeKeysTabDevToolsDialogText')}</p>
        <textarea
          className={styles.importTextarea}
          value={manualKeyText}
          placeholder={lang('BridgeKeysTabDevToolsPlaceholder')}
          onChange={(e) => setManualKeyText(e.currentTarget.value)}
        />
        <div className={styles.dialogActions}>
          <Button color="translucent" onClick={closeManualKeyModal}>
            {lang('Cancel')}
          </Button>
          <Button color="danger" onClick={handleManualKeySubmit} disabled={!manualKeyText.trim()}>
            {lang('BridgeKeysTabDevToolsSubmit')}
          </Button>
        </div>
      </Modal>

      <Modal
        isOpen={isImportOpen}
        onClose={closeImport}
        title={lang('BridgeKeysTabImportButton')}
        hasCloseButton
      >
        <textarea
          className={styles.importTextarea}
          value={importText}
          placeholder={lang('BridgeContactImportPlaceholder')}
          onChange={(e) => setImportText(e.currentTarget.value)}
        />
        <div className={styles.dialogActions}>
          <Button color="translucent" onClick={closeImport}>
            {lang('Cancel')}
          </Button>
          <Button color="primary" onClick={handleImportSubmit} disabled={!importText.trim()}>
            {lang('BridgeContactImportSubmit')}
          </Button>
        </div>
      </Modal>

      {isScanOpen && (
        <BridgeScannerView
          isOpen={isScanOpen}
          onBundleDetected={handleBundleDetected}
          onCancel={closeScan}
        />
      )}

      <Modal
        isOpen={isMyQrOpen}
        onClose={closeMyQr}
        title={lang('BridgeShowMyQrTitle')}
        hasCloseButton
      >
        <BridgeIdentityQrView />
      </Modal>
    </div>
  );
};

type StatusSectionProps = {
  statusBadge: StatusBadge;
  hasContactKey: boolean;
  hasChatKey: boolean;
  isKxInProgress: boolean;
  activeShortKeyId?: string;
};

const KeysTabStatusSection = ({
  statusBadge, hasContactKey, hasChatKey, isKxInProgress, activeShortKeyId,
}: StatusSectionProps) => {
  const lang = useLang();

  const badgeLabel = statusBadge === 'unlocked'
    ? lang('BridgeStatusUnlocked')
    : statusBadge === 'locked'
      ? lang('BridgeStatusLocked')
      : lang('BridgeStatusNotInitialized');

  const badgeClass = statusBadge === 'unlocked'
    ? styles.badgeUnlocked
    : statusBadge === 'locked'
      ? styles.badgeLocked
      : styles.badgeMuted;

  const chatKeyLine = isKxInProgress
    ? lang('BridgeKeysTabChatKeyKxInProgress')
    : hasChatKey
      ? lang('BridgeKeysTabChatKeyActive', { keyId: '—' })
      : lang('BridgeKeysTabChatKeyNone');

  return (
    <section className={styles.statusSection}>
      <div className={styles.statusRow}>
        <span className={buildClassName(styles.badge, badgeClass)}>{badgeLabel}</span>
      </div>
      <div className={styles.statusLine}>
        <span className={styles.statusLabel}>{lang('BridgeKeysTabKeyId')}</span>
        <span className={styles.statusValue}>
          {hasContactKey
            ? (activeShortKeyId ?? lang('BridgeContactKeyActiveBadge'))
            : lang('BridgeNoContactKey')}
        </span>
      </div>
      <div className={styles.statusLine}>
        <span className={styles.statusLabel}>{lang('BridgeKeysTabChatKeySection')}</span>
        <span className={styles.statusValue}>{chatKeyLine}</span>
      </div>
      {!hasContactKey && (
        <p className={styles.banner}>{lang('BridgeKeysTabEmptyText')}</p>
      )}
    </section>
  );
};

type ActionButtonsProps = {
  onImport: NoneToVoidFunction;
  onScan: NoneToVoidFunction;
  onShowMyQr: NoneToVoidFunction;
};

const KeysTabActionButtons = ({ onImport, onScan, onShowMyQr }: ActionButtonsProps) => {
  const lang = useLang();
  return (
    <div className={styles.actionRow}>
      <Button size="smaller" onClick={onImport}>
        {lang('BridgeKeysTabImportButton')}
      </Button>
      <Button size="smaller" onClick={onScan}>
        {lang('BridgeKeysTabScanButton')}
      </Button>
      <Button size="smaller" onClick={onShowMyQr}>
        {lang('BridgeKeysTabShowMyQrButton')}
      </Button>
    </div>
  );
};

export default memo(withGlobal<OwnProps>(
  (global, { chatId }): Complete<StateProps> => ({
    isBridgeUnlocked: global.bridge.isUnlocked,
    isBridgeInitialized: global.bridge.isInitialized,
    hasContactKey: Boolean(global.bridge.contactKeyIds[chatId]),
    hasChatKey: Boolean(global.bridge.chatKeyIds[chatId]),
    isKxInProgress: Boolean(global.bridge.kxInProgressChatIds[chatId]),
    isDebugMode: global.bridge.isDebugMode,
    persistedJson: global.bridge.persistedJson,
    lastExport: global.bridge.bridgeLastExport,
    lastError: global.bridge.lastError,
    contactKeyIds: global.bridge.contactKeyIds,
  }),
)(ProfileKeysTab));
