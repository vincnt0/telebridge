import {
  memo, useEffect, useMemo, useState,
} from '../../../lib/teact/teact';
import { getActions } from '../../../global';

import type { ContactKeyEntry, ContactKeyOrigin } from '../../../telebridge/state/types';

import { getTelebridgeVault } from '../../../telebridge/send';
import buildClassName from '../../../util/buildClassName';
import { copyTextToClipboard } from '../../../util/clipboard';

import useFlag from '../../../hooks/useFlag';
import useLang from '../../../hooks/useLang';
import useLastCallback from '../../../hooks/useLastCallback';

// 3A owns this component; it accepts a bundleText prop to render an arbitrary tb1:// URL.
import BridgeIdentityQrView from '../../bridge/BridgeIdentityQrView';
import Button from '../../ui/Button';
import ConfirmDialog from '../../ui/ConfirmDialog';
import Modal from '../../ui/Modal';

import styles from './SettingsBridgeContacts.module.scss';

type OwnProps = {
  userId: string;
  // Opaque token — parent changes it after any mutating action dispatch so
  // we re-pull from the vault. The actual value has no meaning; only its
  // identity matters as an effect dependency.
  refreshToken: string;
  lastExport?: {
    peerUserId: string;
    keyId: string;
    json: string;
    qrText: string;
  };
  lastError?: string;
};

const BridgeContactKeyHistoryRow = ({
  userId, refreshToken, lastExport, lastError,
}: OwnProps) => {
  const {
    bridgeSetActiveContactKey,
    bridgeArchiveContactKey,
    bridgeDeleteContactKey,
    bridgeExportContactKey,
    bridgeImportContactKey,
    bridgeRevokeContactKey,
    bridgeClearLastExport,
    showNotification,
  } = getActions();

  const lang = useLang();

  const [entries, setEntries] = useState<ContactKeyEntry[]>([]);
  const [activeKeyId, setActiveKeyId] = useState<string>('');

  useEffect(() => {
    const vault = getTelebridgeVault();
    const next = vault.listContactKeys(userId);
    setEntries(next);
    const active = next.find((k) => !k.archivedAt);
    setActiveKeyId(active ? active.keyId : (next[0]?.keyId ?? ''));
  }, [userId, refreshToken]);

  const [deleteTargetKeyId, setDeleteTargetKeyId] = useState<string | undefined>(undefined);
  const [isImportOpen, openImport, closeImport] = useFlag(false);
  const [isRevokeOpen, openRevoke, closeRevoke] = useFlag(false);
  const [exportView, setExportView] = useState<'qr' | 'text' | undefined>(undefined);
  const [importText, setImportText] = useState('');
  // Error message captured at the moment of an import attempt — we stash the
  // error snapshot before the attempt so we can compare lastError after.
  const [importAttemptId, setImportAttemptId] = useState(0);

  const handleSetActive = useLastCallback((keyId: string) => {
    bridgeSetActiveContactKey({ peerUserId: userId, keyId });
  });

  const handleArchive = useLastCallback((keyId: string) => {
    bridgeArchiveContactKey({ peerUserId: userId, keyId });
  });

  const handleDeleteClick = useLastCallback((keyId: string) => {
    setDeleteTargetKeyId(keyId);
  });

  const closeDeleteConfirm = useLastCallback(() => {
    setDeleteTargetKeyId(undefined);
  });

  const confirmDelete = useLastCallback(() => {
    if (deleteTargetKeyId) {
      bridgeDeleteContactKey({ peerUserId: userId, keyId: deleteTargetKeyId });
    }
    setDeleteTargetKeyId(undefined);
  });

  const handleExportQr = useLastCallback((keyId: string) => {
    setExportView('qr');
    bridgeExportContactKey({ peerUserId: userId, keyId });
  });

  const handleExportText = useLastCallback((keyId: string) => {
    setExportView('text');
    bridgeExportContactKey({ peerUserId: userId, keyId });
  });

  // When the transient export slot lands for this contact in "text" view, copy
  // + toast + clear immediately. For "qr" view we keep the slot open until the
  // modal closes (the QR needs the qrText to render).
  useEffect(() => {
    if (!lastExport || lastExport.peerUserId !== userId) return;
    if (exportView !== 'text') return;
    copyTextToClipboard(lastExport.json);
    showNotification({ message: lang('BridgeContactExportCopiedToast') });
    bridgeClearLastExport();
    setExportView(undefined);
  }, [lastExport, userId, exportView, lang]);

  const closeExport = useLastCallback(() => {
    bridgeClearLastExport();
    setExportView(undefined);
  });

  const handleImportSubmit = useLastCallback(() => {
    if (!importText.trim()) return;
    setImportAttemptId((n) => n + 1);
    bridgeImportContactKey({ peerUserId: userId, payload: importText.trim() });
    setImportText('');
    closeImport();
  });

  const handleRevokeConfirm = useLastCallback(() => {
    bridgeRevokeContactKey({ peerUserId: userId });
    closeRevoke();
  });

  const isSoleKey = entries.length <= 1;

  const qrPayload = useMemo(() => {
    if (exportView !== 'qr' || !lastExport || lastExport.peerUserId !== userId) return undefined;
    return lastExport.qrText;
  }, [exportView, lastExport, userId]);

  const deleteTargetIsActive = deleteTargetKeyId !== undefined && deleteTargetKeyId === activeKeyId;

  return (
    <div className={styles.expanded}>
      {entries.map((entry) => {
        const isActive = entry.keyId === activeKeyId;
        const canArchive = isActive && !isSoleKey;
        return (
          <div key={entry.keyId} className={styles.keyCard}>
            <div className={styles.keyHeader}>
              <span>{entry.keyId.slice(0, 8)}</span>
              {isActive ? (
                <span className={styles.activeTag}>{lang('BridgeContactKeyActiveBadge')}</span>
              ) : (
                <span className={styles.archivedTag}>{lang('BridgeContactKeyArchivedBadge')}</span>
              )}
            </div>
            <div className={styles.keyMeta}>
              {lang(originLangKey(entry.origin))}
            </div>
            <div className={styles.keyMeta}>
              {lang('BridgeContactKeyFirstSeenLabel')}
              {': '}
              {formatShortDate(entry.firstSeen)}
            </div>
            {entry.lastUsed !== undefined && (
              <div className={styles.keyMeta}>
                {lang('BridgeContactKeyLastUsedLabel')}
                {': '}
                {formatRelative(entry.lastUsed)}
              </div>
            )}
            <div className={styles.keyActions}>
              {!isActive && (
                <button
                  type="button"
                  className={styles.actionButton}
                  onClick={() => handleSetActive(entry.keyId)}
                >
                  {lang('BridgeContactKeySetActive')}
                </button>
              )}
              {isActive && (
                <button
                  type="button"
                  className={styles.actionButton}
                  disabled={!canArchive}
                  onClick={() => handleArchive(entry.keyId)}
                >
                  {lang('BridgeContactKeyArchive')}
                </button>
              )}
              <button
                type="button"
                className={buildClassName(styles.actionButton, styles.actionDanger)}
                onClick={() => handleDeleteClick(entry.keyId)}
              >
                {lang('BridgeContactKeyDelete')}
              </button>
              <button
                type="button"
                className={styles.actionButton}
                onClick={() => handleExportQr(entry.keyId)}
              >
                {lang('BridgeContactKeyExportQr')}
              </button>
              <button
                type="button"
                className={styles.actionButton}
                onClick={() => handleExportText(entry.keyId)}
              >
                {lang('BridgeContactKeyExportText')}
              </button>
            </div>
          </div>
        );
      })}

      <div className={styles.sectionDivider} />

      <div className={styles.footerActions}>
        <Button size="smaller" onClick={openImport}>
          {lang('BridgeContactImportButton')}
        </Button>
        <Button size="smaller" color="danger" onClick={openRevoke}>
          {lang('BridgeContactRevokeButton')}
        </Button>
      </div>

      {lastError && importAttemptId > 0 && (
        <p className={styles.errorHint}>
          {lang(errorLangKey(lastError))}
        </p>
      )}

      <ConfirmDialog
        isOpen={deleteTargetKeyId !== undefined}
        onClose={closeDeleteConfirm}
        title={lang('BridgeContactKeyDelete')}
        text={deleteTargetIsActive ? lang('BridgeContactDeleteActiveConfirm') : undefined}
        confirmLabel={lang('BridgeContactKeyDelete')}
        confirmIsDestructive
        confirmHandler={confirmDelete}
      />

      <ConfirmDialog
        isOpen={isRevokeOpen}
        onClose={closeRevoke}
        title={lang('BridgeContactRevokeButton')}
        text={lang('BridgeContactRevokeConfirm')}
        confirmLabel={lang('BridgeContactRevokeButton')}
        confirmIsDestructive
        confirmHandler={handleRevokeConfirm}
      />

      <Modal
        isOpen={isImportOpen}
        onClose={closeImport}
        title={lang('BridgeContactImportDialogTitle')}
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

      <Modal
        isOpen={exportView === 'qr' && Boolean(qrPayload)}
        onClose={closeExport}
        title={lang('BridgeContactKeyExportQr')}
        hasCloseButton
      >
        {qrPayload && <BridgeIdentityQrView bundleText={qrPayload} />}
        <div className={styles.dialogActions}>
          <Button color="primary" onClick={closeExport}>
            {lang('Close')}
          </Button>
        </div>
      </Modal>
    </div>
  );
};

function originLangKey(origin: ContactKeyOrigin) {
  switch (origin) {
    case 'in-person-scan': return 'BridgeContactKeyOriginInPerson';
    case 'post-hoc-qr': return 'BridgeContactKeyOriginPostHocQr';
    case 'imported': return 'BridgeContactKeyOriginImported';
    case 'tofu':
    default:
      return 'BridgeContactKeyOriginTofu';
  }
}

function errorLangKey(err: string): 'BridgeImportDuplicate' | 'BridgeImportInvalid' | 'BridgeInvalidScanBundle' {
  if (err === 'BridgeImportDuplicate') return 'BridgeImportDuplicate';
  if (err === 'BridgeInvalidScanBundle') return 'BridgeInvalidScanBundle';
  return 'BridgeImportInvalid';
}

function formatShortDate(ts: number): string {
  const d = new Date(ts);
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function formatRelative(ts: number): string {
  const delta = Date.now() - ts;
  const seconds = Math.max(0, Math.floor(delta / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return formatShortDate(ts);
}

export default memo(BridgeContactKeyHistoryRow);
