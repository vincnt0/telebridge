import { memo } from '../../../lib/teact/teact';
import { getActions, withGlobal } from '../../../global';

import buildClassName from '../../../util/buildClassName';

import useFlag from '../../../hooks/useFlag';
import useHistoryBack from '../../../hooks/useHistoryBack';
import useLang from '../../../hooks/useLang';
import useLastCallback from '../../../hooks/useLastCallback';

import ChangeBridgePasswordDialog from '../../bridge/ChangeBridgePasswordDialog';
import SetupBridgeDialog from '../../bridge/SetupBridgeDialog';
import UnlockBridgeDialog from '../../bridge/UnlockBridgeDialog';
import Button from '../../ui/Button';
import SettingsBridgeContacts from './SettingsBridgeContacts';

import styles from './SettingsBridge.module.scss';

type OwnProps = {
  isActive?: boolean;
  onReset: () => void;
};

type StateProps = {
  isInitialized: boolean;
  isUnlocked: boolean;
  isBusy: boolean;
  chatKeyCount: number;
};

const SettingsBridge = ({
  isActive,
  isInitialized,
  isUnlocked,
  isBusy,
  chatKeyCount,
  onReset,
}: OwnProps & StateProps) => {
  const { bridgeLock } = getActions();
  const lang = useLang();

  const [isSetupOpen, openSetup, closeSetup] = useFlag(false);
  const [isUnlockOpen, openUnlock, closeUnlock] = useFlag(false);
  const [isChangePasswordOpen, openChangePassword, closeChangePassword] = useFlag(false);

  useHistoryBack({
    isActive,
    onBack: onReset,
  });

  const handleLock = useLastCallback(() => {
    bridgeLock();
  });

  // Status label + CSS modifier keyed off the three possible vault states.
  // Ordering: not-initialized → locked → unlocked. Each drives a different
  // primary button; we render them conditionally rather than through a
  // switch so TS narrows the transitions cleanly.
  const status = !isInitialized
    ? 'notInitialized'
    : isUnlocked
      ? 'unlocked'
      : 'locked';

  const statusLabel = !isInitialized
    ? lang('BridgeStatusNotInitialized')
    : isUnlocked
      ? lang('BridgeStatusUnlocked')
      : lang('BridgeStatusLocked');

  return (
    <div className="settings-content custom-scroll">
      <div className={styles.header}>
        <h3 className={styles.title}>{lang('BridgeTitle')}</h3>
        <p className={styles.description}>{lang('BridgeInfoDescription')}</p>
      </div>

      <div className={styles.statusRow}>
        <span className={buildClassName(styles.statusBadge, styles[status])}>
          {statusLabel}
        </span>
      </div>

      {isInitialized && isUnlocked && chatKeyCount > 0 && (
        <p className={styles.chatCount}>
          {lang('BridgeChatKeysCount', { count: chatKeyCount }, { pluralValue: chatKeyCount })}
        </p>
      )}

      <div className={styles.actions}>
        {!isInitialized && (
          <Button color="primary" onClick={openSetup} isLoading={isBusy} disabled={isBusy}>
            {lang('BridgeSetupButton')}
          </Button>
        )}
        {isInitialized && !isUnlocked && (
          <Button color="primary" onClick={openUnlock} isLoading={isBusy} disabled={isBusy}>
            {lang('BridgeUnlockButton')}
          </Button>
        )}
        {isInitialized && isUnlocked && (
          <Button onClick={openChangePassword} disabled={isBusy}>
            {lang('BridgeChangePasswordButton')}
          </Button>
        )}
        {isInitialized && isUnlocked && (
          <Button color="danger" onClick={handleLock} isLoading={isBusy} disabled={isBusy}>
            {lang('BridgeLockButton')}
          </Button>
        )}
      </div>

      {isInitialized && isUnlocked && (
        <SettingsBridgeContacts isUnlocked={isUnlocked} />
      )}

      <SetupBridgeDialog isOpen={isSetupOpen} onClose={closeSetup} />
      <UnlockBridgeDialog isOpen={isUnlockOpen} onClose={closeUnlock} />
      <ChangeBridgePasswordDialog isOpen={isChangePasswordOpen} onClose={closeChangePassword} />
    </div>
  );
};

export default memo(withGlobal<OwnProps>(
  (global): Complete<StateProps> => ({
    isInitialized: global.bridge.isInitialized,
    isUnlocked: global.bridge.isUnlocked,
    isBusy: Boolean(global.bridge.isBusy),
    chatKeyCount: Object.keys(global.bridge.chatKeyIds).length,
  }),
)(SettingsBridge));
