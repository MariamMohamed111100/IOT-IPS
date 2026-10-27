"""Known-device allowlist for rogue-device detection (services/cyber/known_devices.yaml)."""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from pathlib import Path

import yaml

from .util import clean_text, valid_mac

log = logging.getLogger("cyber.allowlist")
MAX_BYTES = 256 * 1024


class Allowlist:
    """MAC addresses that are allowed on the network.

    Empty (or missing) means detection is OFF: with no baseline every device would look rogue and
    the first start would flood the risk engine. The file is re-read when it changes, so adding a
    device needs no restart.
    """

    def __init__(self, path: Path, clock: Callable[[], float] = time.monotonic,
                 recheck_s: float = 5.0) -> None:
        self.path, self.clock, self.recheck_s = Path(path), clock, recheck_s
        self.macs: dict[str, str] = {}
        self._mtime: int | None = None
        self._checked = float("-inf")
        self.refresh(force=True)

    @property
    def enabled(self) -> bool:
        return bool(self.macs)

    def known(self, mac: str) -> bool:
        return mac in self.macs

    def refresh(self, force: bool = False) -> None:
        now = self.clock()
        if not force and now - self._checked < self.recheck_s:
            return
        self._checked = now
        try:
            stat = self.path.stat()
        except OSError:
            if self._mtime is not None or force:
                log.warning("no known-devices file at %s: rogue-device detection is OFF",
                            self.path)
            self.macs, self._mtime = {}, None
            return
        if stat.st_mtime_ns == self._mtime:
            return
        self._mtime = stat.st_mtime_ns
        self.macs = self._load(stat.st_size)
        log.info("known devices: %d MAC address(es)%s", len(self.macs),
                 "" if self.macs else " (rogue-device detection is OFF)")

    def _load(self, size: int) -> dict[str, str]:
        if size > MAX_BYTES:
            log.error("%s is larger than %d bytes: ignored", self.path, MAX_BYTES)
            return {}
        try:
            doc = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            log.error("cannot read %s (%s): keeping detection OFF", self.path, exc)
            return {}
        entries = doc.get("devices", []) if isinstance(doc, dict) else []
        out: dict[str, str] = {}
        for entry in entries if isinstance(entries, list) else []:
            raw, name = (entry.get("mac"), entry.get("name", "")) if isinstance(entry, dict) \
                else (entry, "")
            mac = valid_mac(raw)
            if mac is None:
                log.warning("ignored invalid MAC %r in %s", clean_text(raw, 40), self.path)
                continue
            out[mac] = clean_text(name, 64)
        return out
