"""Snapshot files on the shared data volume: ``snapshots/<event-id>.jpg`` (path stored relative)."""
from __future__ import annotations

import logging
import os
from pathlib import Path

import cv2
import numpy as np

log = logging.getLogger("vision.snapshots")


class SnapshotStore:
    def __init__(self, data_dir: Path, max_files: int = 500) -> None:
        self.root = data_dir
        self.folder = data_dir / "snapshots"
        self.max_files = max_files
        self._since_prune = 0

    def save(self, event_id: str, image: np.ndarray) -> str | None:
        """Write the JPEG atomically; return the path relative to the data volume, or None."""
        try:
            self.folder.mkdir(parents=True, exist_ok=True)
            tmp = self.folder / f".{event_id}.tmp.jpg"
            if not cv2.imwrite(str(tmp), image, [cv2.IMWRITE_JPEG_QUALITY, 85]):
                raise OSError("cv2.imwrite returned False")
            os.replace(tmp, self.folder / f"{event_id}.jpg")      # readers never see half a file
        except OSError:
            log.exception("could not write snapshot for event %s", event_id)
            return None
        self._since_prune += 1
        if self._since_prune >= 25:
            self.prune()
        return f"snapshots/{event_id}.jpg"

    def prune(self) -> int:
        """Keep only the newest ``max_files`` snapshots so the volume cannot fill up."""
        self._since_prune = 0
        files = sorted(self.folder.glob("*.jpg"), key=lambda p: p.stat().st_mtime)
        extra = files[: max(0, len(files) - self.max_files)]
        for path in extra:
            path.unlink(missing_ok=True)
        return len(extra)
