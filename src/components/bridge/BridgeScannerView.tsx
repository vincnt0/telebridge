import type { ChangeEvent } from 'react';
import {
  memo, useEffect, useRef, useState,
} from '../../lib/teact/teact';

import { BUNDLE_PREFIX } from '../../telebridge/inPerson/bundle';

import useFlag from '../../hooks/useFlag';
import useLang from '../../hooks/useLang';
import useLastCallback from '../../hooks/useLastCallback';

import Button from '../ui/Button';
import Modal from '../ui/Modal';

import styles from './BridgeScannerView.module.scss';

type OwnProps = {
  isOpen: boolean;
  onBundleDetected: (bundleText: string) => void;
  onCancel: NoneToVoidFunction;
};

// `@zxing/browser` exposes `BrowserQRCodeReader`, whose `decodeFromVideoDevice`
// returns `Promise<IScannerControls>` (stop-handle). We only use those two
// pieces of the API; typing them loosely via the dynamic import's module type
// keeps us from pulling the whole zxing type surface into the bundle chunk.
type ZxingModule = typeof import('@zxing/browser');
type ScannerControls = { stop: () => void };

let zxingPromise: Promise<ZxingModule> | undefined;
function ensureZxing() {
  if (!zxingPromise) {
    zxingPromise = import('@zxing/browser');
  }
  return zxingPromise;
}

const BridgeScannerView = ({ isOpen, onBundleDetected, onCancel }: OwnProps) => {
  const lang = useLang();

  const videoRef = useRef<HTMLVideoElement>();
  const controlsRef = useRef<ScannerControls | undefined>(undefined);
  const hasEmittedRef = useRef(false);

  const [pasteValue, setPasteValue] = useState('');
  const [hasCameraError, markCameraError, clearCameraError] = useFlag(false);

  const stopScan = useLastCallback(() => {
    if (controlsRef.current) {
      controlsRef.current.stop();
      controlsRef.current = undefined;
    }
  });

  const handleDetected = useLastCallback((text: string) => {
    if (hasEmittedRef.current) return;
    if (!text.startsWith(BUNDLE_PREFIX)) return;
    hasEmittedRef.current = true;
    stopScan();
    onBundleDetected(text);
  });

  useEffect(() => {
    if (!isOpen) {
      hasEmittedRef.current = false;
      setPasteValue('');
      clearCameraError();
      return undefined;
    }

    let isCancelled = false;

    (async () => {
      try {
        const { BrowserQRCodeReader } = await ensureZxing();
        if (isCancelled || !videoRef.current) return;
        const reader = new BrowserQRCodeReader();
        const controls = await reader.decodeFromVideoDevice(
          undefined,
          videoRef.current,
          (result) => {
            if (!result) return;
            handleDetected(result.getText());
          },
        );
        if (isCancelled) {
          controls.stop();
          return;
        }
        controlsRef.current = controls;
      } catch {
        if (!isCancelled) markCameraError();
      }
    })();

    return () => {
      isCancelled = true;
      stopScan();
    };
  }, [isOpen, handleDetected, stopScan, markCameraError, clearCameraError]);

  const handlePasteChange = useLastCallback((e: ChangeEvent<HTMLTextAreaElement>) => {
    setPasteValue(e.currentTarget.value);
  });

  const handleUsePasted = useLastCallback(() => {
    const trimmed = pasteValue.trim();
    if (!trimmed) return;
    handleDetected(trimmed);
  });

  const handleCancel = useLastCallback(() => {
    stopScan();
    onCancel();
  });

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleCancel}
      title={lang('BridgeScannerTitle')}
      hasCloseButton
      className={styles.modal}
    >
      <div className={styles.container}>
        {!hasCameraError && (
          <div className={styles.videoWrapper}>
            {/* eslint-disable-next-line jsx-a11y/media-has-caption */}
            <video
              ref={videoRef}
              className={styles.video}
              autoPlay
              playsInline
              muted
            />
          </div>
        )}

        {hasCameraError && (
          <p className={styles.errorText}>{lang('BridgeScannerPermissionDenied')}</p>
        )}

        <div className={styles.fallback}>
          <label className={styles.fallbackLabel} htmlFor="bridge-scanner-paste">
            {lang('BridgeScannerPasteFallbackPlaceholder')}
          </label>
          <textarea
            id="bridge-scanner-paste"
            className={styles.textarea}
            value={pasteValue}
            onChange={handlePasteChange}
            placeholder={BUNDLE_PREFIX}
            spellCheck={false}
            autoComplete="off"
          />
        </div>

        <div className={styles.actions}>
          <Button color="translucent" onClick={handleCancel}>
            {lang('Cancel')}
          </Button>
          <Button
            color="primary"
            onClick={handleUsePasted}
            disabled={!pasteValue.trim()}
          >
            {lang('BridgeScannerPasteButton')}
          </Button>
        </div>
      </div>
    </Modal>
  );
};

export default memo(BridgeScannerView);
