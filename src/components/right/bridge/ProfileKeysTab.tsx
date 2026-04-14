import { memo } from '../../../lib/teact/teact';

import useLang from '../../../hooks/useLang';

type OwnProps = {
  chatId: string;
};

const ProfileKeysTab = ({ chatId: _chatId }: OwnProps) => {
  const lang = useLang();

  return (
    <div className="profile-keys-tab-scaffold">
      {lang('BridgeKeysTabEmptyTitle')}
    </div>
  );
};

export default memo(ProfileKeysTab);
