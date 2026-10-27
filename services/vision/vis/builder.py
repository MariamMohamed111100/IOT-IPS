"""Wires real models into a Pipeline. A missing model disables that detector with a loud warning
instead of crashing the whole service (heartbeat and the other detectors keep running)."""
from __future__ import annotations

import logging

from .config import Settings
from .detectors import (
    FireHeuristic,
    MotionDetector,
    MotionGated,
    YoloOnnx,
    coco_kinds,
    fire_class_kinds,
    load_class_names,
    package_class_kinds,
)
from .faces import FaceRecognizer
from .pipeline import Pipeline, Sink
from .snapshots import SnapshotStore

log = logging.getLogger("vision.builder")


def build_pipeline(s: Settings, sink: Sink, snapshots: SnapshotStore) -> Pipeline:
    m = s.model_dir
    objects = faces = None
    fire: list = []
    package_kinds = _package_kinds(m)
    if (m / "yolov8n.onnx").exists():
        objects = YoloOnnx(m / "yolov8n.onnx", coco_kinds(bool(package_kinds)), s.min_conf)
    else:
        log.warning("models/yolov8n.onnx missing: person/vehicle/package detection is OFF "
                    "(run `make vision-models`)")
    if (m / "yunet.onnx").exists() and (m / "sface.onnx").exists():
        faces = FaceRecognizer(m / "yunet.onnx", m / "sface.onnx", s.known_faces_dir,
                               s.face_min_conf, s.face_match)
    else:
        log.warning("models/yunet.onnx or sface.onnx missing: face recognition is OFF")
    model, names = m / "fire.onnx", m / "fire.names"
    if model.exists() and names.exists():
        kinds = fire_class_kinds(load_class_names(names))
        if not s.smoke_from_model:
            kinds = {c: k for c, k in kinds.items() if k != "smoke"}
        if kinds:
            fire.append(MotionGated(
                YoloOnnx(model, kinds, s.min_conf, size=s.fire_size,
                         kind_conf={"fire": s.fire_min_conf, "smoke": s.smoke_min_conf}),
                kinds=("fire",), min_motion=s.fire_min_motion))
        else:
            log.warning("fire.names has no fire/smoke class: fire model OFF")
    elif s.fire_heuristic:
        log.warning("using the colour/flicker fire heuristic: demo-grade, expect false alarms")
        fire.append(FireHeuristic())
    else:
        log.warning("no fire model (models/fire.onnx + fire.names): fire/smoke detection is OFF")
    if package_kinds:      # `fire` is simply the list of extra detectors the pipeline runs
        fire.append(YoloOnnx(m / "package.onnx", package_kinds, s.package_min_conf,
                             size=s.package_size))
    return Pipeline(s, objects=objects, faces=faces, motion=MotionDetector(s.motion_area),
                    fire=fire, snapshots=snapshots, sink=sink)


def _package_kinds(model_dir) -> dict[int, str]:
    model, names = model_dir / "package.onnx", model_dir / "package.names"
    if not (model.exists() and names.exists()):
        log.warning("no parcel model (models/package.onnx + package.names): package.detected "
                    "falls back to COCO backpack/handbag/suitcase, which misses cardboard boxes")
        return {}
    kinds = package_class_kinds(load_class_names(names))
    if not kinds:
        log.warning("package.names has no package/parcel/box/carton class: parcel model OFF")
    return kinds
