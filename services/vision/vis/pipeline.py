"""Turns detector output into debounced contract events.

Per frame: detect -> candidate alerts -> a candidate must appear in ``confirm_frames`` frames in a
row (kills one-frame flicker) -> per-type cooldown (no alert storm) -> snapshot -> publish.
"""
from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol

import cv2
import numpy as np

from smartsecure_common import Event

from .config import Settings
from .snapshots import SnapshotStore
from .types import Detection

log = logging.getLogger("vision.pipeline")

# detection kind -> (contract type, severity_hint)
ALERTS: dict[str, tuple[str, str]] = {
    "person": ("person.detected", "info"),
    "face_known": ("person.detected", "info"),
    "face_unknown": ("face.unknown", "high"),
    "vehicle": ("vehicle.detected", "info"),
    "package": ("package.detected", "info"),
    "fire": ("fire.detected", "critical"),
    "smoke": ("smoke.detected", "critical"),
    "motion": ("motion.outdoor", "low"),
}
NEEDS_SNAPSHOT_FIELD = {"face.unknown", "fire.detected"}     # contract: `snapshot` is required


class Detector(Protocol):
    def detect(self, frame: np.ndarray) -> list[Detection]: ...


class Sink(Protocol):
    def publish(self, event: Event) -> None: ...


@dataclass
class _Candidate:
    key: tuple[str, str]
    type: str
    severity: str
    det: Detection


class Pipeline:
    def __init__(
        self,
        settings: Settings,
        *,
        objects: Detector | None,
        faces: Detector | None,
        motion: Detector | None,
        fire: Iterable[Detector],
        snapshots: SnapshotStore,
        sink: Sink,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.s = settings
        self.objects, self.faces, self.motion = objects, faces, motion
        self.fire = list(fire)
        self.snapshots, self.sink, self.clock = snapshots, sink, clock
        self._streak: dict[tuple[str, str], int] = {}
        self._last_sent: dict[tuple[str, str], float] = {}

    # ------------------------------------------------------------------ detection
    def _detect(self, frame: np.ndarray) -> list[Detection]:
        found: list[Detection] = []
        for det in (self.objects, self.faces, self.motion, *self.fire):
            if det is None:
                continue
            try:
                found += det.detect(frame)
            except Exception:                    # one broken model must not blind the others
                log.exception("detector %s failed", type(det).__name__)
        return found

    def _candidates(self, detections: list[Detection]) -> dict[tuple[str, str], _Candidate]:
        known_present = any(d.kind == "face_known" for d in detections)
        out: dict[tuple[str, str], _Candidate] = {}
        for d in detections:
            if d.kind not in ALERTS or d.confidence < self._floor(d.kind):
                continue
            if d.kind == "motion" and self.s.zone not in self.s.outdoor_zones:
                continue                         # contract: motion.outdoor is for outdoor zones
            if d.kind == "person" and known_present:
                continue                         # the named person.detected already covers it
            typ, sev = ALERTS[d.kind]
            key = (typ, d.name or "")
            best = out.get(key)
            if best is None or d.confidence > best.det.confidence:
                out[key] = _Candidate(key, typ, sev, d)
        return out

    def _floor(self, kind: str) -> float:
        if kind.startswith("face"):
            return self.s.face_min_conf
        if kind in ("person", "vehicle", "package"):
            return self.s.min_conf
        return 0.0

    # ------------------------------------------------------------------ one frame
    def process(self, captured_at: float, frame: np.ndarray) -> list[Event]:
        cands = self._candidates(self._detect(frame))
        for key in list(self._streak):
            if key not in cands:
                self._streak[key] = 0
        sent: list[Event] = []
        for key, cand in cands.items():
            self._streak[key] = self._streak.get(key, 0) + 1
            if self._streak[key] < self.s.confirm_frames:
                continue
            now = self.clock()
            if now - self._last_sent.get(key, -1e12) < self.s.cooldown.get(cand.type, 10.0):
                continue
            self._last_sent[key] = now
            sent.append(self._emit(cand, captured_at, frame))
        return sent

    def _emit(self, cand: _Candidate, captured_at: float, frame: np.ndarray) -> Event:
        event_id = str(uuid.uuid4())
        det = cand.det
        data: dict[str, Any] = {"confidence": round(det.confidence, 3),
                                "camera_id": self.s.camera_id}
        if cand.type in ("smoke.detected", "motion.outdoor"):
            data["sensor_id"] = self.s.camera_id
        if det.name:
            data["name"] = det.name
        snapshot = self.snapshots.save(event_id, annotate(frame, cand))
        if snapshot:
            data["snapshot"] = snapshot
        elif cand.type in NEEDS_SNAPSHOT_FIELD:
            log.error("alert %s sent WITHOUT its required snapshot (disk problem?)", cand.type)
        data["latency_ms"] = round((self.clock() - captured_at) * 1000)
        event = Event(id=event_id, source="vision", type=cand.type, zone=self.s.zone,
                      severity_hint=cand.severity, data=data)         # type: ignore[arg-type]
        self.sink.publish(event)
        log.info("alert %s conf=%.2f latency=%dms", cand.type, det.confidence, data["latency_ms"])
        return event

    # ------------------------------------------------------------------ camera health
    def camera_down(self) -> Event | None:
        key = ("camera.disconnected", "")
        now = self.clock()
        if now - self._last_sent.get(key, -1e12) < self.s.cooldown["camera.disconnected"]:
            return None
        self._last_sent[key] = now
        event = Event(source="vision", type="camera.disconnected", zone=self.s.zone,
                      severity_hint="medium", data={"camera_id": self.s.camera_id})
        self.sink.publish(event)
        return event


def annotate(frame: np.ndarray, cand: _Candidate) -> np.ndarray:
    """Copy of the frame with the detection box and label drawn on it (for the timeline)."""
    img = frame.copy()
    det = cand.det
    label = f"{det.name or cand.type} {det.confidence:.0%}"
    if det.box:
        x, y, w, h = det.box
        cv2.rectangle(img, (x, y), (x + w, y + h), (0, 0, 255), 2)
        cv2.putText(img, label, (x, max(14, y - 6)), cv2.FONT_HERSHEY_SIMPLEX, 0.55,
                    (0, 0, 255), 2)
    else:
        cv2.putText(img, label, (10, 24), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
    return img
