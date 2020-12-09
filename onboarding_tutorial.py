class OnboardingTutorial:

    def __init__(self, user_id, user_name, real_name, channel):
        self.user_id = user_id
        self.user_name = user_name
        self.real_name = real_name
        self.channel = channel
        self.icon_emoji = ":female-office-worker:"
        self.timestamp = ""
        self.reaction_task_completed = False
        self.pin_task_completed = False
        text_msg = "*%s, 你好!* :woman-raising-hand: 歡迎來到我們的 `Python 量化金融 Slack小群` :moneybag:。很高興你加入我們! \n我是金融 Slack小群 *小秘書 Hyeon* （還在初步建置中）。先讓我來為你介紹這個園地裡有什麼好玩的吧:。\n\n :thumbtackr: 預設我只為你加入兩個頻道 (Channel)，#大廳-不特定主題討論，#參考-網站影片非書本類。你可以點選左側 Channels 下的 *新增頻道 (Add Channels)* 來新增你有興趣的主題。" % self.real_name
        self.WELCOME_BLOCK = {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": text_msg,
            },
        }
        self.DIVIDER_BLOCK = {"type": "divider"}

    def get_message_payload(self):
        return {
            "ts": self.timestamp,
            "channel": self.channel,
            "username": 'Hyeon',
            "blocks": [
                self.WELCOME_BLOCK,
                self.DIVIDER_BLOCK,
                *self._get_reaction_block(),
                self.DIVIDER_BLOCK,
                *self._get_pin_block(),
            ],
        }

    def _get_reaction_block(self):
        task_checkmark = self._get_checkmark(self.reaction_task_completed)
        text = (
            f"{task_checkmark} *對這個訊息回應並新增表情符號 (emoji)* :grinning:\n"
            "你可以在 Slack 裡的任何訊息上，快速地回應表情符號。"
            "回應可以做為任何的用途，例如: 投票, 標示某項任務為已完成, 表達你的情緒等等。"
        )
        information = (
            ":information_source: *<https://get.slack.help/hc/en-us/articles/206870317-Emoji-reactions|"
            "瞭解如何使用表情符號回應 (Emoji Reactions)>*"
        )
        return self._get_task_block(text, information)

    def _get_pin_block(self):
        task_checkmark = self._get_checkmark(self.pin_task_completed)
        text = (
            f"{task_checkmark} *釘選這個訊息* :round_pushpin:\n"
            "在任何頻道中或私訊，重要的資訊和檔案可以被釘選到詳細窗格 (Details Pane)"
            " ，包含群組訊息, 做為快速的參考捷徑。"
        )
        information = (
            ":information_source: *<https://get.slack.help/hc/en-us/articles/205239997-Pinning-messages-and-files"
            "|瞭解如何使用釘選特定訊息>*"
        )
        return self._get_task_block(text, information)

    @staticmethod
    def _get_checkmark(task_completed: bool) -> str:
        if task_completed:
            return ":white_check_mark:"
        return ":white_large_square:"

    @staticmethod
    def _get_task_block(text, information):
        return [
            {"type": "section", "text": {"type": "mrkdwn", "text": text}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": information}]},
        ]