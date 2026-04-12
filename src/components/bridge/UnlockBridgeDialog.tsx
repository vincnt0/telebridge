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
  isUnlocked: boolean;
  isBusy: boolean;
  lastError?: string;
};

const UnlockBridgeDialog = ({
  isOpen,
  isUnlocked,
  isBusy,
  lastError,
  onClose,
}: OwnProps & StateProps) => {
  const { bridgeUnlock, bridgeClearError } = getActions();
  const lang = useLang();

  const [password, setPassword] = useState('');
  const [hasSubmitted, setHasSubmitted] = useState(false);

  // Auto-close when the vault flips to unlocked. Watching `isUnlocked` rather
  // than the submit promise means we also close cleanly if unlock happens
  // from a different tab (the global state is shared).
  useEffect(() => {
    if (hasSubmitted && !isBusy && !lastError && isUnlocked) {
      setPassword('');
      setHasSubmitted(false);
      onClose();
    }
  }, [hasSubmitted, isBusy, lastError, isUnlocked, onClose]);

  useEffect(() => {
    if (!isOpen) {
      setPassword('');
      setHasSubmitted(false);
      if (lastError) bridgeClearError();
    }
  }, [isOpen]);

  const handlePasswordChange = useLastCallback((e: ChangeEvent<HTMLInputElement>) => {
    setPassword(e.target.value);
    if (lastError) bridgeClearError();
  });

  const handleSubmit = useLastCallback((e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (isBusy || !password) return;
    setHasSubmitted(true);
    bridgeUnlock({ password });
  });

  // Map the raw vault error onto a user-friendly string. The vault throws
  // 'Incorrect password' for both bad-password and auth-tag-mismatch cases
  // — those are the same situation from the user's point of view.
  const displayedError = lastError === 'Incorrect password'
    ? lang('BridgeWrongPassword')
    : lastError;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={lang('BridgeUnlockDialogTitle')}
      hasCloseButton
      className={styles.modal}
    >
      <form action="" onSubmit={handleSubmit} autoComplete="off">
        <p className={styles.description}>{lang('BridgeUnlockDialogText')}</p>
        <div className={buildClassName('input-group', password && 'touched', displayedError && 'error')}>
          <input
            className="form-control"
            type="password"
            value={password}
            onChange={handlePasswordChange}
            autoComplete="current-password"
            maxLength={256}
            disabled={isBusy}
            dir="auto"
          />
          <label>{lang('BridgePasswordLabel')}</label>
        </div>
        {displayedError && <p className={styles.error}>{displayedError}</p>}
        <Button type="submit" isLoading={isBusy} disabled={isBusy || !password}>
          {lang('BridgeSubmitUnlock')}
        </Button>
      </form>
    </Modal>
  );
};

export default memo(withGlobal<OwnProps>(
  (global): Complete<StateProps> => ({
    isUnlocked: global.bridge.isUnlocked,
    isBusy: Boolean(global.bridge.isBusy),
    lastError: global.bridge.lastError,
  }),
)(UnlockBridgeDialog));
