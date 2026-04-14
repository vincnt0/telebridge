import { sha256 } from '@noble/hashes/sha2.js';

import {
  memo, useLayoutEffect, useMemo, useRef, useState,
} from '../../lib/teact/teact';

import { STRICTERDOM_ENABLED } from '../../config';
import { disableStrict, enableStrict } from '../../lib/fasterdom/stricterdom';
import { toHex } from '../../telebridge/crypto';
import { encodeIdentityBundle } from '../../telebridge/inPerson/bundle';
import { getTelebridgeVault } from '../../telebridge/send';

import useAsync from '../../hooks/useAsync';
import useLang from '../../hooks/useLang';

import styles from './BridgeIdentityQrView.module.scss';

type OwnProps = {
  // Optional override — if provided (e.g. per-key export QR), render that
  // bundle instead of deriving from the local identity. Otherwise the view
  // encodes the currently-unlocked identity's bundle itself.
  bundleText?: string;
};

const QR_SIZE = 240;
const QR_MUTATION_DURATION = 50;
const FINGERPRINT_HEX_CHARS = 16;

let qrCodeStylingPromise: Promise<typeof import('qr-code-styling')> | undefined;
function ensureQrCodeStyling() {
  if (!qrCodeStylingPromise) {
    qrCodeStylingPromise = import('qr-code-styling');
  }
  return qrCodeStylingPromise;
}

const BridgeIdentityQrView = ({ bundleText }: OwnProps) => {
  const lang = useLang();

  const qrContainerRef = useRef<HTMLDivElement>();
  const [isQrMounted, setIsQrMounted] = useState(false);

  // Derive bundle text + fingerprint either from an explicit prop or from the
  // unlocked local identity. Caller is responsible for gating mount behind
  // `isUnlocked`; without that guard `getIdentityKeyPair` throws.
  const payload = useMemo(() => {
    if (bundleText) {
      return { text: bundleText, fingerprint: undefined as string | undefined };
    }
    const vault = getTelebridgeVault();
    const identity = vault.getIdentityKeyPair();
    const text = encodeIdentityBundle(identity);
    const digest = sha256(identity.ed25519PublicKey);
    const fingerprint = toHex(digest).slice(0, FINGERPRINT_HEX_CHARS);
    return { text, fingerprint };
  }, [bundleText]);

  const { result: qrCode } = useAsync(async () => {
    const QrCodeStyling = (await ensureQrCodeStyling()).default;
    return new QrCodeStyling({
      width: QR_SIZE,
      height: QR_SIZE,
      margin: 8,
      type: 'svg',
      dotsOptions: { type: 'rounded' },
      cornersSquareOptions: { type: 'extra-rounded' },
      qrOptions: { errorCorrectionLevel: 'M' },
    });
  }, []);

  useLayoutEffect(() => {
    if (!qrCode || !qrContainerRef.current) return undefined;

    if (STRICTERDOM_ENABLED) disableStrict();

    qrCode.update({ data: payload.text });
    if (!isQrMounted) {
      qrCode.append(qrContainerRef.current);
      setIsQrMounted(true);
    }

    if (STRICTERDOM_ENABLED) {
      setTimeout(() => enableStrict(), QR_MUTATION_DURATION);
    }
    return undefined;
  }, [qrCode, payload, isQrMounted]);

  return (
    <div className={styles.wrapper}>
      <div className={styles.qrWrapper}>
        <div ref={qrContainerRef} className={styles.qrInner} />
      </div>
      {payload.fingerprint && (
        <>
          <p className={styles.fingerprintLabel}>
            {lang('BridgeShowMyQrFingerprintLabel')}
          </p>
          <pre className={styles.fingerprint}>{payload.fingerprint}</pre>
        </>
      )}
    </div>
  );
};

export default memo(BridgeIdentityQrView);
