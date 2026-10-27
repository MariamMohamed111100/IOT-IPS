from __future__ import annotations

from dataclasses import dataclass

# What detectors report. `kind` is the pipeline-level label (mapped to a contract type later).
KINDS = ("person", "vehicle", "package", "fire", "smoke", "motion", "face_unknown", "face_known")


@dataclass(frozen=True)
class Detection:
    kind: str
    confidence: float
    box: tuple[int, int, int, int] | None = None     # x, y, w, h in pixels
    name: str | None = None                           # known person's name (face_known only)
