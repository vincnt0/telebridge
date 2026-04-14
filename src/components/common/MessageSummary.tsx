import { memo } from '../../lib/teact/teact';
import { withGlobal } from '../../global';

import type {
  ApiFormattedText, ApiMessage, ApiPoll, ApiTypeStory,
  ApiWebPage,
} from '../../api/types';
import type { ObserveFn } from '../../hooks/useIntersectionObserver';

import {
  extractMessageText,
  getMessagePollId,
  groupStatefulContent,
  isActionMessage,
} from '../../global/helpers';
import {
  getMessageSummaryDescription,
  getMessageSummaryEmoji,
  getMessageSummaryText,
  TRUNCATED_SUMMARY_LENGTH,
} from '../../global/helpers/messageSummary';
import { selectPeerStory, selectPollFromMessage, selectWebPageFromMessage } from '../../global/selectors';
import { isTelebridgeMachineMessage, isTelebridgeMessage } from '../../telebridge/protocol';
import { getMessageKey } from '../../util/keys/messageKey';
import trimText from '../../util/trimText';
import renderText from './helpers/renderText';

import useLang from '../../hooks/useLang';

import ActionMessageText from '../middle/message/ActionMessageText';
import MessageText from './MessageText';

type OwnProps = {
  message: ApiMessage;
  forcedText?: ApiFormattedText;
  noEmoji?: boolean;
  highlight?: string;
  truncateLength?: number;
  withTranslucentThumbs?: boolean;
  inChatList?: boolean;
  emojiSize?: number;
  observeIntersectionForLoading?: ObserveFn;
  observeIntersectionForPlaying?: ObserveFn;
};

type StateProps = {
  poll?: ApiPoll;
  story?: ApiTypeStory;
  webPage?: ApiWebPage;
  bridgeDecryptedText?: string;
};

function MessageSummary({
  message,
  forcedText,
  noEmoji,
  highlight,
  truncateLength = TRUNCATED_SUMMARY_LENGTH,
  withTranslucentThumbs,
  inChatList,
  emojiSize,
  poll,
  story,
  webPage,
  observeIntersectionForLoading,
  observeIntersectionForPlaying,
}: OwnProps & StateProps) {
  const lang = useLang();

  // Telebridge: machine messages (kx/pk handshake wire payloads) must never
  // surface in previews. Render an empty span — same fallback used for
  // messages with no text content.
  const rawText = message.content.text?.text;
  if (rawText && isTelebridgeMachineMessage(rawText)) {
    return <span />;
  }

  const extractedText = extractMessageText(message, inChatList);
  const hasPoll = Boolean(getMessagePollId(message));
  const isAction = isActionMessage(message);

  const statefulContent = groupStatefulContent({ poll, story, webPage });

  if (!extractedText && !hasPoll && !isAction) {
    const summaryText = forcedText?.text
      || getMessageSummaryText(lang, message, statefulContent, noEmoji, truncateLength);
    const trimmedText = trimText(summaryText, truncateLength);

    return (
      <span>
        {highlight ? (
          renderText(trimmedText, ['emoji', 'highlight'], { highlight })
        ) : (
          renderText(trimmedText)
        )}
      </span>
    );
  }

  function renderMessageText() {
    if (isAction) {
      return <ActionMessageText message={message} asPreview />;
    }

    return (
      <MessageText
        messageOrStory={message}
        forcedText={forcedText}
        highlight={highlight}
        asPreview
        observeIntersectionForLoading={observeIntersectionForLoading}
        observeIntersectionForPlaying={observeIntersectionForPlaying}
        withTranslucentThumbs={withTranslucentThumbs}
        truncateLength={truncateLength}
        inChatList={inChatList}
        emojiSize={emojiSize}
      />
    );
  }

  const emoji = !noEmoji && getMessageSummaryEmoji(message);

  return (
    <>
      {[
        emoji ? renderText(`${emoji} `) : undefined,
        getMessageSummaryDescription(lang, message, statefulContent, renderMessageText()),
      ].flat().filter(Boolean)}
    </>
  );
}

export default memo(withGlobal<OwnProps>(
  (global, { message }): Complete<StateProps> => {
    const poll = selectPollFromMessage(global, message);
    const webPage = selectWebPageFromMessage(global, message);
    const storyData = message.content.storyData;
    const story = storyData && selectPeerStory(global, storyData.peerId, storyData.id);

    // Telebridge: subscribe to the decrypted-text cache entry for this
    // message so the summary re-renders when a background decrypt lands.
    // Drives chat-list previews and non-Message consumers of
    // getMessageSummaryText / getMessageTextWithSpoilers.
    const rawText = message.content.text?.text;
    const bridgeDecryptedText = rawText && isTelebridgeMessage(rawText)
      ? global.bridge.decryptedByKey[getMessageKey(message)]
      : undefined;

    return {
      poll,
      story,
      webPage,
      bridgeDecryptedText,
    };
  },
)(MessageSummary));
