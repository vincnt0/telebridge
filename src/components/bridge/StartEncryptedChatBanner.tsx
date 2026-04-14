import { memo } from '../../lib/teact/teact';
import { getActions, withGlobal } from '../../global';

import buildClassName from '../../util/buildClassName';
import { isUserId } from '../../util/entities/ids';

import useLang from '../../hooks/useLang';
import useLastCallback from '../../hooks/useLastCallback';

import Icon from '../common/icons/Icon';
import Button from '../ui/Button';

import styles from './StartEncryptedChatBanner.module.scss';

type OwnProps = {
  chatId: string;
};

type StateProps = {
  shouldRender: boolean;
  isWaiting: boolean;
  isBusy: boolean;
  lastError?: string;
};

const WAITING_ERROR_KEY = 'BridgeWaitingForContactPrekey';

const StartEncryptedChatBanner = ({
  chatId,
  shouldRender,
  isWaiting,
  isBusy,
  lastError,
}: OwnProps & StateProps) => {
  const { bridgeStartKeyExchange } = getActions();
  const lang = useLang();

  const handleClick = useLastCallback(() => {
    bridgeStartKeyExchange({ chatId });
  });

  if (!shouldRender) return undefined;

  const isWaitingError = lastError === WAITING_ERROR_KEY;
  const otherError = lastError && !isWaitingError ? lastError : undefined;
  const buttonLabel = isWaiting
    ? lang('BridgeWaitingButton')
    : lang('BridgeStartEncryptedChatButton');

  return (
    <div className={buildClassName(styles.banner, isWaiting && styles.waiting)}>
      <Icon name="lock" className={styles.icon} />
      <div className={styles.body}>
        <p className={styles.description}>
          {lang('BridgeStartEncryptedChatDescription')}
        </p>
        {otherError && <p className={styles.error}>{otherError}</p>}
      </div>
      <Button
        size="tiny"
        color="primary"
        className={styles.action}
        isLoading={isBusy}
        disabled={isBusy}
        onClick={handleClick}
      >
        {buttonLabel}
      </Button>
    </div>
  );
};

export default memo(withGlobal<OwnProps>(
  (global, { chatId }): Complete<StateProps> => {
    const { bridge } = global;
    const hasKey = Boolean(bridge.chatKeyIds[chatId]);
    const shouldRender = Boolean(
      chatId
        && isUserId(chatId)
        && bridge.isInitialized
        && bridge.isUnlocked
        && !hasKey,
    );
    const isWaiting = Boolean(
      bridge.kxInProgressChatIds[chatId]
        || bridge.lastError === WAITING_ERROR_KEY,
    );

    return {
      shouldRender,
      isWaiting,
      isBusy: Boolean(bridge.isBusy),
      lastError: bridge.lastError,
    };
  },
)(StartEncryptedChatBanner));
