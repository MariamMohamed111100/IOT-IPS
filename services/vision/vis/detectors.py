"""Object, motion and fire/smoke detectors. Every detector returns a list of ``Detection``.

YOLO runs through OpenCV's DNN module on an ONNX export, so the image needs no PyTorch.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import cv2
import numpy as np

from .types import Detection

log = logging.getLogger("vision.detect")

# COCO class id -> pipeline kind. COCO has no "package" class: backpack, handbag and suitcase are
# the closest stand-ins. Train/plug a real parcel model with PACKAGE_MODEL for production.
COCO_KINDS: dict[int, str] = {
    0: "person",
    2: "vehicle", 3: "vehicle", 5: "vehicle", 7: "vehicle",      # car, motorcycle, bus, truck
    24: "package", 26: "package", 28: "package",                 # backpack, handbag, suitcase
}


class YoloOnnx:
    """YOLOv8-style detector: ONNX output shape (1, 4 + classes, anchors)."""

    def __init__(self, model_path: Path, class_kinds: Mapping[int, str],
                 min_conf: float = 0.45, nms_iou: float = 0.5, size: int = 640,
                 kind_conf: Mapping[str, float] | None = None) -> None:
        self.net = cv2.dnn.readNetFromONNX(str(model_path))
        self.class_kinds = dict(class_kinds)
        self.min_conf, self.nms_iou, self.size = min_conf, nms_iou, size
        # per-kind confidence floor (a fire model needs a stricter one than a person model)
        self.class_conf = {c: (kind_conf or {}).get(k, min_conf)
                           for c, k in self.class_kinds.items()}

    def detect(self, frame: np.ndarray) -> list[Detection]:
        h, w = frame.shape[:2]
        scale = self.size / max(h, w)
        nw, nh = round(w * scale), round(h * scale)
        canvas = np.full((self.size, self.size, 3), 114, np.uint8)       # letterbox
        canvas[:nh, :nw] = cv2.resize(frame, (nw, nh))
        blob = cv2.dnn.blobFromImage(canvas, 1 / 255.0, (self.size, self.size), swapRB=True)
        self.net.setInput(blob)
        out = self.net.forward()[0].T                                     # (anchors, 4 + classes)
        scores = out[:, 4:]
        cls = scores.argmax(axis=1)
        conf = scores[np.arange(len(cls)), cls]
        floor = np.full(scores.shape[1], np.inf)           # classes we do not map never pass
        for c, t in self.class_conf.items():
            if c < len(floor):
                floor[c] = t
        keep = conf >= floor[cls]
        if not keep.any():
            return []
        out, cls, conf = out[keep], cls[keep], conf[keep]
        boxes = [[int((x - bw / 2) / scale), int((y - bh / 2) / scale),
                  int(bw / scale), int(bh / scale)] for x, y, bw, bh in out[:, :4]]
        idx = cv2.dnn.NMSBoxes(boxes, conf.tolist(), min(self.class_conf.values()), self.nms_iou)
        return [Detection(self.class_kinds[int(cls[i])], float(conf[i]), _clip(boxes[i], w, h))
                for i in np.array(idx).flatten()]


def _clip(b: list[int], w: int, h: int) -> tuple[int, int, int, int]:
    x, y = max(0, b[0]), max(0, b[1])
    return x, y, max(1, min(b[2], w - x)), max(1, min(b[3], h - y))


class MotionGated:
    """Wraps a detector: boxes of the gated kinds must be *moving* inside, or they are dropped.

    Flames flicker, a static orange parcel does not. On the demo clip fire boxes moved 39-69% of
    their pixels between frames, orange parcels at most 20% (same model, same confidence range).
    """

    def __init__(self, inner: Any, kinds: Iterable[str] = ("fire",), min_motion: float = 0.25,
                 pixel_delta: int = 12) -> None:
        self.inner, self.kinds = inner, set(kinds)
        self.min_motion, self.pixel_delta = min_motion, pixel_delta
        self.prev: np.ndarray | None = None

    def detect(self, frame: np.ndarray) -> list[Detection]:
        found = self.inner.detect(frame)
        gray = cv2.GaussianBlur(cv2.cvtColor(cv2.resize(frame, (320, 180)), cv2.COLOR_BGR2GRAY),
                                (5, 5), 0)
        prev, self.prev = self.prev, gray
        if prev is None:                           # no earlier frame: cannot tell, so do not alert
            return [d for d in found if d.kind not in self.kinds]
        diff = cv2.absdiff(gray, prev)
        h, w = frame.shape[:2]
        kept: list[Detection] = []
        for d in found:
            if d.kind in self.kinds and d.box is not None:
                x, y, bw, bh = d.box
                x0, y0 = int(x * 320 / w), int(y * 180 / h)
                x1, y1 = max(x0 + 1, int((x + bw) * 320 / w)), max(y0 + 1, int((y + bh) * 180 / h))
                region = diff[y0:y1, x0:x1]
                if region.size == 0 or float((region > self.pixel_delta).mean()) < self.min_motion:
                    continue
            elif d.kind in self.kinds:
                continue
            kept.append(d)
        return kept


class MotionDetector:
    """Background subtraction: reports one detection when enough of the frame changed."""

    def __init__(self, min_area: float = 0.01, warmup_frames: int = 10) -> None:
        self.bg = cv2.createBackgroundSubtractorMOG2(history=200, varThreshold=32,
                                                     detectShadows=False)
        self.min_area, self.warmup = min_area, warmup_frames

    def detect(self, frame: np.ndarray) -> list[Detection]:
        small = cv2.GaussianBlur(cv2.resize(frame, (320, 180)), (5, 5), 0)
        mask = self.bg.apply(small)
        if self.warmup > 0:                       # let the background model settle first
            self.warmup -= 1
            return []
        mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, np.ones((3, 3), np.uint8))
        area = float(np.count_nonzero(mask)) / mask.size
        if area < self.min_area:
            return []
        return [Detection("motion", min(1.0, area * 10))]


class FireHeuristic:
    """Demo-grade flame detector: flame-coloured, bright pixels that also flicker between frames.

    Colour alone fires on orange sofas and sunsets, so a region must also change between frames.
    Off by default (FIRE_HEURISTIC=true to enable). Production should use a trained fire/smoke
    ONNX model through ``YoloOnnx`` instead.
    """

    def __init__(self, min_area: float = 0.005) -> None:
        self.prev: np.ndarray | None = None
        self.min_area = min_area

    def detect(self, frame: np.ndarray) -> list[Detection]:
        small = cv2.resize(frame, (320, 180))
        hsv = cv2.cvtColor(small, cv2.COLOR_BGR2HSV)
        flame = cv2.inRange(hsv, (0, 120, 200), (35, 255, 255))
        gray = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY)
        moving = np.zeros_like(flame)
        if self.prev is not None:
            moving = cv2.threshold(cv2.absdiff(gray, self.prev), 25, 255, cv2.THRESH_BINARY)[1]
        self.prev = gray
        both = cv2.bitwise_and(flame, moving)
        area = float(np.count_nonzero(both)) / both.size
        if area < self.min_area:
            return []
        return [Detection("fire", min(0.6, 0.3 + area * 10))]      # capped: it is only a heuristic


def load_class_names(path: Path) -> list[str]:
    return [line.strip().lower() for line in path.read_text().splitlines() if line.strip()]


def package_class_kinds(names: list[str]) -> dict[int, str]:
    """Map a custom parcel model's class names (``package.names``) to the ``package`` kind."""
    words = ("package", "parcel", "box", "carton")
    return {i: "package" for i, name in enumerate(names) if any(w in name for w in words)}


def coco_kinds(custom_package_model: bool) -> dict[int, str]:
    """COCO ids to report. With a real parcel model the backpack/handbag/suitcase stand-ins go."""
    if not custom_package_model:
        return dict(COCO_KINDS)
    return {i: k for i, k in COCO_KINDS.items() if k != "package"}


def fire_class_kinds(names: list[str]) -> dict[int, str]:
    """Map a custom fire/smoke model's class names (``<model>.names``) to pipeline kinds."""
    kinds: dict[int, str] = {}
    for i, name in enumerate(names):
        if "smoke" in name:
            kinds[i] = "smoke"
        elif "fire" in name or "flame" in name:
            kinds[i] = "fire"
    return kinds
