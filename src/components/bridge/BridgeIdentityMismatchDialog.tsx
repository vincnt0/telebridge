import { memo } from '../../lib/teact/teact';
import { getActions, withGlobal } from '../../global';

import { getUserFullName } from '../../global/helpers/users';
import { selectUser } from '../../global/selectors';

import useLang from '../../hooks/useLang';
import useLastCallback from '../../hooks/useLastCallback';

import Button from '../ui/Button';
import Modal from '../ui/Modal';

import styles from './BridgeIdentityMismatchDialog.module.scss';

type StateProps = {
  peerUserId?: string;
  scannedKeyId?: string;
  kind?: 'matchedArchived' | 'newKeyAddedInactive';
  peerName?: string;
};

const BridgeIdentityMismatchDialog = ({
  peerUserId,
  scannedKeyId,
  kind,
  peerName,
}: StateProps) => {
  const { bridgeSetActiveContactKey, bridgeClearMismatchPending } = getActions();
  const lang = useLang();

  const isOpen = Boolean(peerUserId && scannedKeyId && kind);

  const handleActivate = useLastCallback(() => {
    if (!peerUserId || !scannedKeyId) return;
    bridgeSetActiveContactKey({ peerUserId, keyId: scannedKeyId });
    bridgeClearMismatchPending();
  });

  const handleKeepCurrent = useLastCallback(() => {
    bridgeClearMismatchPending();
  });

  const title = kind === 'matchedArchived'
    ? lang('BridgeMismatchArchivedTitle')
    : lang('BridgeMismatchNewInactiveTitle');

  const displayName = peerName || '';
  const description = kind === 'matchedArchived'
    ? lang('BridgeMismatchArchivedText', { name: displayName })
    : lang('BridgeMismatchNewInactiveText', { name: displayName });

  const activateLabel = kind === 'matchedArchived'
    ? lang('BridgeMismatchReactivate')
    : lang('BridgeMismatchActivateNew');

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleKeepCurrent}
      title={title}
      hasCloseButton
      className={styles.modal}
    >
      <div className={styles.body}>
        <p className={styles.description}>{description}</p>
        <div className={styles.actions}>
          <Button color="translucent" onClick={handleKeepCurrent}>
            {lang('BridgeMismatchKeepCurrent')}
          </Button>
          <Button color="primary" onClick={handleActivate}>
            {activateLabel}
          </Button>
        </div>
      </div>
    </Modal>
  );
};

export default memo(withGlobal(
  (global): Complete<StateProps> => {
    const pending = global.bridge.bridgeMismatchPending;
    if (!pending) {
      return {
        peerUserId: undefined,
        scannedKeyId: undefined,
        kind: undefined,
        peerName: undefined,
      };
    }
    const user = selectUser(global, pending.peerUserId);
    return {
      peerUserId: pending.peerUserId,
      scannedKeyId: pending.scannedKeyId,
      kind: pending.kind,
      peerName: getUserFullName(user),
    };
  },
)(BridgeIdentityMismatchDialog));
