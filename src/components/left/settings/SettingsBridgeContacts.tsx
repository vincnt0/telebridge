import {
  memo, useEffect, useMemo, useState,
} from '../../../lib/teact/teact';
import { withGlobal } from '../../../global';

import type { ApiChat, ApiUser } from '../../../api/types';
import type { ContactKeyOrigin, ContactSummary } from '../../../telebridge/state/types';

import { ContactTrustLevel } from '../../../telebridge/state/types';
import { getTelebridgeVault } from '../../../telebridge/send';

import useFlag from '../../../hooks/useFlag';
import useLang from '../../../hooks/useLang';
import useLastCallback from '../../../hooks/useLastCallback';

import BridgeIdentityQrView from '../../bridge/BridgeIdentityQrView';
import Avatar from '../../common/Avatar';
import FullNameTitle from '../../common/FullNameTitle';
import Icon from '../../common/icons/Icon';
import Button from '../../ui/Button';
import Modal from '../../ui/Modal';

import BridgeContactKeyHistoryRow from './BridgeContactKeyHistoryRow';

import styles from './SettingsBridgeContacts.module.scss';

type OwnProps = {
  isUnlocked: boolean;
};

type StateProps = {
  contactKeyIds: Record<string, true>;
  usersById: Record<string, ApiUser>;
  chatsById: Record<string, ApiChat>;
  persistedJson?: string;
  lastExport?: {
    peerUserId: string;
    keyId: string;
    json: string;
    qrText: string;
  };
  lastError?: string;
};

const SettingsBridgeContacts = ({
  isUnlocked,
  contactKeyIds,
  usersById,
  chatsById,
  persistedJson,
  lastExport,
  lastError,
}: OwnProps & StateProps) => {
  const lang = useLang();

  const [summaries, setSummaries] = useState<ContactSummary[]>([]);
  const [expandedUserId, setExpandedUserId] = useState<string | undefined>(undefined);

  // persistedJson changes on every mutating vault call — that's exactly when
  // children need to re-pull their view. contactCount, lastExport and
  // lastError are folded in as belt-and-suspenders.
  const contactCount = useMemo(() => Object.keys(contactKeyIds).length, [contactKeyIds]);

  const refreshToken = useMemo(
    () => `${contactCount}|${persistedJson ?? ''}|${lastExport ? lastExport.keyId : ''}|${lastError ?? ''}`,
    [contactCount, persistedJson, lastExport, lastError],
  );

  useEffect(() => {
    if (!isUnlocked) {
      setSummaries([]);
      return;
    }
    const vault = getTelebridgeVault();
    setSummaries(vault.listContacts());
  }, [isUnlocked, refreshToken]);

  const handleToggleExpand = useLastCallback((userId: string) => {
    setExpandedUserId((prev) => (prev === userId ? undefined : userId));
  });

  const [isMyQrOpen, openMyQr, closeMyQr] = useFlag(false);

  if (!isUnlocked) {
    return undefined;
  }

  return (
    <div className={styles.root}>
      <h4 className={styles.sectionTitle}>{lang('BridgeContactsSectionTitle')}</h4>

      {summaries.length === 0 && (
        <p className={styles.empty}>{lang('BridgeContactsEmpty')}</p>
      )}

      {summaries.map((summary) => {
        const user = usersById[summary.userId];
        const chat = chatsById[summary.userId];
        const peer = user || chat;
        const isExpanded = expandedUserId === summary.userId;
        return (
          <div key={summary.userId}>
            <button
              type="button"
              className={styles.row}
              onClick={() => handleToggleExpand(summary.userId)}
            >
              <Avatar size="medium" peer={peer} />
              <div className={styles.rowLabel}>
                {peer
                  ? <FullNameTitle peer={peer} />
                  : <span className={styles.rowName}>{summary.userId}</span>}
                <span className={styles.rowBadge}>
                  {lang(badgeLangKey(summary))}
                  {' · '}
                  {summary.keyCount}
                </span>
              </div>
              <Icon
                name={isExpanded ? 'up' : 'down'}
                className={styles.rowCaret}
              />
            </button>
            {isExpanded && (
              <BridgeContactKeyHistoryRow
                userId={summary.userId}
                refreshToken={refreshToken}
                lastExport={lastExport}
                lastError={lastError}
              />
            )}
          </div>
        );
      })}

      <div className={styles.showQrRow}>
        <Button size="smaller" onClick={openMyQr}>
          {lang('BridgeShowMyQrMenuItem')}
        </Button>
      </div>

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

function badgeLangKey(summary: ContactSummary): (
  'BridgeContactKeyOriginInPerson'
  | 'BridgeContactKeyOriginPostHocQr'
  | 'BridgeContactKeyOriginTofu'
  | 'BridgeKeyChangedBadge'
  | 'BridgeContactKeyOriginImported'
) {
  if (summary.trustLevel === ContactTrustLevel.Changed) return 'BridgeKeyChangedBadge';
  if (summary.trustLevel === ContactTrustLevel.Verified) {
    if (summary.activeKeyOrigin === 'in-person-scan') return 'BridgeContactKeyOriginInPerson';
    return 'BridgeContactKeyOriginPostHocQr';
  }
  return originLangKey(summary.activeKeyOrigin);
}

function originLangKey(origin: ContactKeyOrigin): (
  'BridgeContactKeyOriginTofu'
  | 'BridgeContactKeyOriginInPerson'
  | 'BridgeContactKeyOriginPostHocQr'
  | 'BridgeContactKeyOriginImported'
) {
  switch (origin) {
    case 'in-person-scan': return 'BridgeContactKeyOriginInPerson';
    case 'post-hoc-qr': return 'BridgeContactKeyOriginPostHocQr';
    case 'imported': return 'BridgeContactKeyOriginImported';
    case 'tofu':
    default:
      return 'BridgeContactKeyOriginTofu';
  }
}

export default memo(withGlobal<OwnProps>(
  (global): Complete<StateProps> => ({
    contactKeyIds: global.bridge.contactKeyIds,
    usersById: global.users.byId,
    chatsById: global.chats.byId,
    persistedJson: global.bridge.persistedJson,
    lastExport: global.bridge.bridgeLastExport,
    lastError: global.bridge.lastError,
  }),
)(SettingsBridgeContacts));
