"""Frame source: a video file looped forever (simulated camera) or a live RTSP stream.

Both look the same to the pipeline: ``frames()`` yields ``(captured_at, frame)`` at no more than
``fps`` frames per second. While the camera is down it yields ``(now, None)`` after every retry, so
the caller keeps getting control and can raise ``camera.disconnected``. Skipped frames are still
read (``grab``) so an RTSP buffer never backs up and detection latency stays low. A file is paced to
its own frame rate so it behaves like a camera.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator
from typing import Any

import cv2

log = logging.getLogger("vision.source")
MAX_FILE_LAG_S = 5.0


def is_stream(source: str) -> bool:
    return "://" in source


def open_capture(source: str) -> Any:
    return cv2.VideoCapture(source)


class FrameSource:
    def __init__(
        self,
        source: str,
        fps: float = 5.0,
        *,
        opener: Callable[[str], Any] = open_capture,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        retry_seconds: float = 2.0,
    ) -> None:
        self.source = source
        self.stream = is_stream(source)
        self.interval = 1.0 / fps
        self._open, self._clock, self._sleep = opener, clock, sleep
        self.retry_seconds = retry_seconds
        self._cap: Any = None
        self.down_since: float | None = None    # None while frames are flowing
        self.loops = 0                          # completed passes over a file (for tests/logs)
        self._file_due: float | None = None     # wall-clock time the next file frame is due

    @property
    def connected(self) -> bool:
        return self.down_since is None

    def _mark_down(self) -> None:
        if self.down_since is None:
            self.down_since = self._clock()
            log.warning("camera source %s is not delivering frames", self.source)

    def _ensure_open(self) -> bool:
        if self._cap is not None:
            return True
        cap = self._open(self.source)
        if cap is not None and cap.isOpened():
            self._cap = cap
            return True
        if cap is not None:
            cap.release()
        self._mark_down()
        return False

    def _close(self) -> None:
        if self._cap is not None:
            self._cap.release()
            self._cap = None

    def frames(self) -> Iterator[tuple[float, Any | None]]:
        next_due = 0.0
        just_rewound = False
        while True:
            if not self._ensure_open():
                self._sleep(self.retry_seconds)
                yield self._clock(), None
                continue
            file_fps = 0.0 if self.stream else (self._cap.get(cv2.CAP_PROP_FPS) or 25.0)
            started = self._clock()
            if not self._cap.grab():
                if self.stream or just_rewound:
                    # stream dropped, or the file cannot be read at all: reconnect later
                    self._mark_down()
                    self._close()
                    just_rewound = False
                    self._sleep(self.retry_seconds)
                    yield self._clock(), None
                else:
                    self._cap.set(cv2.CAP_PROP_POS_FRAMES, 0)     # end of file: loop
                    self.loops += 1
                    just_rewound = True
                continue
            just_rewound = False
            late = 0.0
            if file_fps:
                # Play on wall-clock time like a real camera: while the consumer is busy detecting,
                # the video keeps "running", so a slow machine drops frames instead of slowing the
                # scene down. A frame that is already late is stale: grab it, do not deliver it.
                if self._file_due is None:
                    self._file_due = started
                self._file_due += 1.0 / file_fps
                late = self._clock() - self._file_due
                if late > MAX_FILE_LAG_S:                      # long stall (suspend): resync
                    self._file_due, late = self._clock(), 0.0
            now = self._clock()
            if now >= next_due and late <= 1.0 / (file_fps or 1.0):
                ok, frame = self._cap.retrieve()
                if ok and frame is not None:
                    self.down_since = None
                    next_due = now + self.interval
                    yield now, frame
            if file_fps and self._file_due is not None:
                self._sleep(max(0.0, self._file_due - self._clock()))

    def close(self) -> None:
        self._close()
