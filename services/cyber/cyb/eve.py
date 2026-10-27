"""Follow Suricata's eve.json (one JSON object per line) like `tail -F`."""
from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger("cyber.eve")
CHUNK = 4 * 1024 * 1024
MAX_LINE = 1024 * 1024


class EveTailer:
    """`poll()` returns the new records since the last call.

    Starts at the END of a file that already existed when we first looked (old alerts are not
    replayed into the risk score) unless ``from_start``; a file that appears later is new, so it is
    read from its first byte. Survives rotation (new inode) and truncation, keeps a half-written
    last line until it is complete, and drops lines that are not JSON objects.
    """

    def __init__(self, path: Path, from_start: bool = False) -> None:
        self.path, self.from_start = Path(path), from_start
        self._inode: int | None = None
        self._offset = 0
        self._buf = b""
        self._waiting_logged = False
        self._missing_seen = False

    def poll(self) -> list[dict]:
        try:
            stat = self.path.stat()
        except OSError:
            self._inode = None
            self._missing_seen = True
            if not self._waiting_logged:
                log.info("waiting for %s (is Suricata running?)", self.path)
                self._waiting_logged = True
            return []
        self._waiting_logged = False
        if stat.st_ino != self._inode:
            first = self._inode is None
            self._inode, self._buf = stat.st_ino, b""
            keep_history = first and not self._missing_seen and not self.from_start
            self._offset = stat.st_size if keep_history else 0
        elif stat.st_size < self._offset:                      # truncated in place
            self._offset, self._buf = 0, b""
        if stat.st_size == self._offset:
            return []
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self._offset)
                data = fh.read(CHUNK)
        except OSError as exc:
            log.warning("cannot read %s: %s", self.path, exc)
            return []
        self._offset += len(data)
        self._buf += data
        *lines, self._buf = self._buf.split(b"\n")
        if len(self._buf) > MAX_LINE:                          # a "line" with no end: junk
            self._buf = b""
        out: list[dict] = []
        for line in lines:
            if not line.strip() or len(line) > MAX_LINE:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
        return out
