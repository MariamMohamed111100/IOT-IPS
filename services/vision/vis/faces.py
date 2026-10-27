"""Face detection (YuNet) and recognition (SFace) with OpenCV. Known faces live in a folder:

    known_faces/<name>/*.jpg      (several photos per person: better)
    known_faces/<name>.jpg        (one photo per person)

A face that matches nobody is ``face_unknown``; a match is ``face_known`` with the person's name.
"""
from __future__ import annotations

import logging
from pathlib import Path

import cv2
import numpy as np

from .types import Detection

log = logging.getLogger("vision.faces")
IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".bmp"}


class FaceRecognizer:
    def __init__(self, detector_model: Path, recognizer_model: Path, known_dir: Path,
                 min_conf: float = 0.8, match_threshold: float = 0.363) -> None:
        self.detector = cv2.FaceDetectorYN.create(
            str(detector_model), "", (320, 320), min_conf, 0.3)
        self.recognizer = cv2.FaceRecognizerSF.create(str(recognizer_model), "")
        self.match_threshold = match_threshold    # 0.363 = SFace's published cosine cut-off
        self.known: dict[str, list[np.ndarray]] = {}
        self.load_known(known_dir)

    def _faces(self, image: np.ndarray) -> np.ndarray:
        h, w = image.shape[:2]
        self.detector.setInputSize((w, h))
        _, faces = self.detector.detect(image)
        return faces if faces is not None else np.empty((0, 15), np.float32)

    def _embed(self, image: np.ndarray, face: np.ndarray) -> np.ndarray:
        return self.recognizer.feature(self.recognizer.alignCrop(image, face))

    def load_known(self, folder: Path) -> None:
        self.known.clear()
        if not folder.is_dir():
            log.warning("known-faces folder %s does not exist: every face will be unknown", folder)
            return
        photos: list[tuple[str, Path]] = []
        for entry in sorted(folder.iterdir()):
            if entry.is_dir():
                photos += [(entry.name, p) for p in sorted(entry.iterdir())
                           if p.suffix.lower() in IMAGE_SUFFIXES]
            elif entry.suffix.lower() in IMAGE_SUFFIXES:
                photos.append((entry.stem, entry))
        for name, path in photos:
            image = cv2.imread(str(path))
            faces = self._faces(image) if image is not None else []
            if len(faces) == 0:
                log.warning("no face found in %s: skipped", path)
                continue
            biggest = max(faces, key=lambda f: f[2] * f[3])
            self.known.setdefault(name, []).append(self._embed(image, biggest))
        log.info("known faces loaded: %s",
                 {n: len(v) for n, v in self.known.items()} or "none")

    def identify(self, embedding: np.ndarray) -> tuple[str | None, float]:
        best_name, best = None, -1.0
        for name, vectors in self.known.items():
            for vec in vectors:
                score = float(self.recognizer.match(embedding, vec, cv2.FaceRecognizerSF_FR_COSINE))
                if score > best:
                    best_name, best = name, score
        return (best_name, best) if best >= self.match_threshold else (None, best)

    def detect(self, frame: np.ndarray) -> list[Detection]:
        found: list[Detection] = []
        for face in self._faces(frame):
            box = tuple(int(v) for v in face[:4])
            name, _ = self.identify(self._embed(frame, face))
            conf = float(face[14])
            if name is None:
                found.append(Detection("face_unknown", conf, box))
            else:
                found.append(Detection("face_known", conf, box, name=name))
        return found
