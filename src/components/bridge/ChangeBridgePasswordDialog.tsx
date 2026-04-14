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
  isBusy: boolean;
  lastError?: string;
};

const ChangeBridgePasswordDialog = ({
  isOpen,
  isBusy,
  lastError,
  onClose,
}: OwnProps & StateProps) => {
  const { bridgeChangePassword, bridgeClearError } = getActions();
  const lang = useLang();

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [localError, setLocalError] = useState<string | undefined>();
  const [hasSubmitted, setHasSubmitted] = useState(false);

  // Auto-close on success. The action clears lastError + isBusy on its own;
  // no new flag is set since change-password doesn't transition vault state.
  useEffect(() => {
    if (hasSubmitted && !isBusy && !lastError) {
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setHasSubmitted(false);
      onClose();
    }
  }, [hasSubmitted, isBusy, lastError, onClose]);

  useEffect(() => {
    if (!isOpen) {
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setLocalError(undefined);
      setHasSubmitted(false);
      if (lastError) bridgeClearError();
    }
  }, [isOpen]);

  const handleCurrentChange = useLastCallback((e: ChangeEvent<HTMLInputElement>) => {
    setCurrentPassword(e.target.value);
    if (localError) setLocalError(undefined);
    if (lastError) bridgeClearError();
  });

  const handleNewChange = useLastCallback((e: ChangeEvent<HTMLInputElement>) => {
    setNewPassword(e.target.value);
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

    if (!currentPassword) {
      setLocalError(lang('BridgeWrongPassword'));
      return;
    }
    if (newPassword === currentPassword) {
      setLocalError(lang('BridgeSamePassword'));
      return;
    }
    if (newPassword !== confirmPassword) {
      setLocalError(lang('BridgePasswordMismatch'));
      return;
    }

    setHasSubmitted(true);
    bridgeChangePassword({ currentPassword, newPassword });
  });

  // Vault throws 'Current password is incorrect' for a bad current password;
  // surface the same localized string used in the unlock flow.
  const displayedError = localError ?? (lastError === 'Current password is incorrect'
    ? lang('BridgeWrongPassword')
    : lastError);

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={lang('BridgeChangePasswordDialogTitle')}
      hasCloseButton
      className={styles.modal}
    >
      <form action="" onSubmit={handleSubmit} autoComplete="off">
        <p className={styles.description}>{lang('BridgeChangePasswordDialogText')}</p>
        <div className={buildClassName('input-group', currentPassword && 'touched', displayedError && 'error')}>
          <input
            className="form-control"
            type="password"
            value={currentPassword}
            onChange={handleCurrentChange}
            autoComplete="current-password"
            maxLength={256}
            disabled={isBusy}
            dir="auto"
          />
          <label>{lang('BridgeCurrentPasswordLabel')}</label>
        </div>
        <div className={buildClassName('input-group', newPassword && 'touched', displayedError && 'error')}>
          <input
            className="form-control"
            type="password"
            value={newPassword}
            onChange={handleNewChange}
            autoComplete="new-password"
            maxLength={256}
            disabled={isBusy}
            dir="auto"
          />
          <label>{lang('BridgeNewPasswordLabel')}</label>
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
          <label>{lang('BridgeNewPasswordConfirmLabel')}</label>
        </div>
        {displayedError && <p className={styles.error}>{displayedError}</p>}
        <Button type="submit" isLoading={isBusy} disabled={isBusy}>
          {lang('BridgeSubmitChangePassword')}
        </Button>
      </form>
    </Modal>
  );
};

export default memo(withGlobal<OwnProps>(
  (global): Complete<StateProps> => ({
    isBusy: Boolean(global.bridge.isBusy),
    lastError: global.bridge.lastError,
  }),
)(ChangeBridgePasswordDialog));
