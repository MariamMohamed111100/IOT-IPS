"""Push notifications through ntfy.sh and/or Telegram (both free). Dry-run when not configured.

Sending happens on a background thread: a slow or unreachable service must never delay the
engine's reaction to the next event. Secrets (the Telegram token) are never logged.
"""
from __future__ import annotations

import logging
import os
import threading
import urllib.parse
import urllib.request

log = logging.getLogger("engine.notify")

PRIORITY = {"low": "2", "medium": "3", "high": "4", "critical": "5"}
TAGS = {"low": "white_check_mark", "medium": "warning", "high": "rotating_light", "critical": "sos"}
TIMEOUT_S = 5


class Notifier:
    def __init__(self, *, background: bool = True) -> None:
        self.ntfy_server = os.getenv("NTFY_SERVER", "https://ntfy.sh").rstrip("/")
        self.ntfy_topic = os.getenv("NTFY_TOPIC", "").strip()
        self.tg_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        self.tg_chat = os.getenv("TELEGRAM_CHAT_ID", "").strip()
        self.background = background
        self.sent: list[dict] = []                        # what was asked for (handy in tests)

    @property
    def channels(self) -> list[str]:
        found = []
        if self.ntfy_topic and self.ntfy_server.startswith("https://"):
            found.append("ntfy")
        if self.tg_token and self.tg_chat:
            found.append("telegram")
        return found

    def send(self, title: str, body: str, level: str) -> list[str]:
        """Queue the message; returns the channels it goes to (`dry-run` if none configured)."""
        self.sent.append({"title": title, "body": body, "level": level})
        channels = self.channels
        if not channels:
            log.info("[dry-run notify] %s | %s", title, body)
            return ["dry-run"]
        if self.background:
            threading.Thread(target=self._deliver, args=(title, body, level, channels),
                             daemon=True, name="notify").start()
        else:
            self._deliver(title, body, level, channels)
        return channels

    def _deliver(self, title: str, body: str, level: str, channels: list[str]) -> None:
        if "ntfy" in channels:
            self._ntfy(title, body, level)
        if "telegram" in channels:
            self._telegram(title, body)

    def _scrub(self, text: str) -> str:
        return text.replace(self.tg_token, "***") if self.tg_token else text

    def _ntfy(self, title: str, body: str, level: str) -> bool:
        try:
            request = urllib.request.Request(
                f"{self.ntfy_server}/{urllib.parse.quote(self.ntfy_topic, safe='')}",
                data=body.encode("utf-8"), method="POST",
                headers={"Title": title.encode("ascii", "replace").decode(),
                         "Priority": PRIORITY.get(level, "3"), "Tags": TAGS.get(level, "warning")})
            with urllib.request.urlopen(request, timeout=TIMEOUT_S):
                return True
        except Exception as exc:                          # the network must never crash the engine
            log.warning("ntfy failed: %s", self._scrub(str(exc)))
            return False

    def _telegram(self, title: str, body: str) -> bool:
        try:
            data = urllib.parse.urlencode({"chat_id": self.tg_chat, "text": f"{title}\n{body}"})
            url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
            with urllib.request.urlopen(urllib.request.Request(url, data=data.encode()),
                                        timeout=TIMEOUT_S):
                return True
        except Exception as exc:
            log.warning("telegram failed: %s", self._scrub(str(exc)))
            return False
