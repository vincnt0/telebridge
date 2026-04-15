import type { ChangeEvent, FormEvent } from 'react';
import {
  memo, useEffect, useState,
} from '../../lib/teact/teact';
import { getActions, withGlobal } from '../../global';

import buildClassName from '../../util/buildClassName';

import useLang from '../../hooks/useLang';
import useLastCallback from '../../hooks/useLastCallback';

import Button from '../ui/Button';
import Modal from '../ui/Modal';

import styles from './BridgeDialog.module.scss';

type OwnProps = {
  isOpen: boolean;
  onClose: NoneToVoidFunction;
};

type StateProps = {
  isInitialized: boolean;
  isUnlocked: boolean;
  isBusy: boolean;
  lastError?: string;
};

const SetupBridgeDialog = ({
  isOpen,
  isInitialized,
  isUnlocked,
  isBusy,
  lastError,
  onClose,
}: OwnProps & StateProps) => {
  const { bridgeSetPassword, bridgeClearError } = getActions();
  const lang = useLang();

  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [localError, setLocalError] = useState<string | undefined>();
  const [hasSubmitted, setHasSubmitted] = useState(false);

  // Auto-close once setup succeeds. The action flips both flags true on
  // success and clears lastError; we watch for that edge rather than
  // relying on the submit promise (which Teact actions don't expose).
  useEffect(() => {
    if (hasSubmitted && !isBusy && !lastError && isInitialized && isUnlocked) {
      setPassword('');
      setConfirmPassword('');
      setHasSubmitted(false);
      onClose();
    }
  }, [hasSubmitted, isBusy, lastError, isInitialized, isUnlocked, onClose]);

  // Reset local/global error state when the dialog closes so a re-open starts clean.
  useEffect(() => {
    if (!isOpen) {
      setPassword('');
      setConfirmPassword('');
      setLocalError(undefined);
      setHasSubmitted(false);
      if (lastError) bridgeClearError();
    }
  }, [isOpen]);

  const handlePasswordChange = useLastCallback((e: ChangeEvent<HTMLInputElement>) => {
    setPassword(e.target.value);
    if (localError) setLocalError(undefined);
    if (lastError) bridgeClearError();
  });

  const handleConfirmChange = useLastCallback((e: ChangeEvent<HTMLInputElement>) => {
    setConfirmPassword(e.target.value);
    if (localError) setLocalError(undefined);
  });

  const handleSubmit = useLastCallback((e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (isBusy) return;

    // Empty password path: confirm must also be empty (trivially matches).
    // Short-circuit the mismatch check so the user gets a clean no-password
    // vault without a confusing "Passwords don't match" error.
    if (!password && !confirmPassword) {
      setHasSubmitted(true);
      bridgeSetPassword({ password: '' });
      return;
    }

    if (password !== confirmPassword) {
      setLocalError(lang('BridgePasswordMismatch'));
      return;
    }

    setHasSubmitted(true);
    bridgeSetPassword({ password });
  });

  const handleSkip = useLastCallback(() => {
    if (isBusy) return;
    setPassword('');
    setConfirmPassword('');
    setLocalError(undefined);
    setHasSubmitted(true);
    bridgeSetPassword({ password: '' });
  });

  const displayedError = localError ?? lastError;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={lang('BridgeSetupDialogTitle')}
      hasCloseButton
      className={styles.modal}
    >
      <form action="" onSubmit={handleSubmit} autoComplete="off">
        <p className={styles.description}>{lang('BridgeSetupDialogText')}</p>
        <p className={styles.optionalNote}>{lang('BridgePasswordOptionalNote')}</p>
        <div className={buildClassName('input-group', password && 'touched', displayedError && 'error')}>
          <input
            className="form-control"
            type="password"
            value={password}
            onChange={handlePasswordChange}
            autoComplete="new-password"
            maxLength={256}
            disabled={isBusy}
            dir="auto"
          />
          <label>{lang('BridgePasswordLabel')}</label>
        </div>
        <div className={buildClassName('input-group', confirmPassword && 'touched', displayedError && 'error')}>
          <input
            className="form-control"
            type="password"
            value={confirmPassword}
            onChange={handleConfirmChange}
            autoComplete="new-password"
            maxLength={256}
            disabled={isBusy}
            dir="auto"
          />
          <label>{lang('BridgePasswordConfirmLabel')}</label>
        </div>
        {displayedError && <p className={styles.error}>{displayedError}</p>}
        <Button type="submit" isLoading={isBusy} disabled={isBusy}>
          {lang('BridgeSubmitSetup')}
        </Button>
        <button
          type="button"
          className={styles.skipButton}
          onClick={handleSkip}
          disabled={isBusy}
        >
          {lang('BridgeSkipPasswordButton')}
        </button>
      </form>
    </Modal>
  );
};

export default memo(withGlobal<OwnProps>(
  (global): Complete<StateProps> => ({
    isInitialized: global.bridge.isInitialized,
    isUnlocked: global.bridge.isUnlocked,
    isBusy: Boolean(global.bridge.isBusy),
    lastError: global.bridge.lastError,
  }),
)(SetupBridgeDialog));
