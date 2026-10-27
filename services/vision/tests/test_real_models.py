"""Real YOLO + face models on real photos. Skipped unless the models are downloaded
(`make vision-models`) and VISION_TEST_IMAGES points at a folder with bus.jpg and zidane.jpg
(both ship inside the `ultralytics` package under ultralytics/assets/)."""
import os
import pathlib

import cv2
import pytest

from vis.detectors import COCO_KINDS, YoloOnnx
from vis.faces import FaceRecognizer

MODELS = pathlib.Path(__file__).resolve().parent.parent / "models"
DEFAULT_IMAGES = pathlib.Path(__file__).resolve().parent.parent / "media" / "test_images"
IMAGES = pathlib.Path(os.getenv("VISION_TEST_IMAGES", str(DEFAULT_IMAGES)))
need = pytest.mark.skipif(
    not ((MODELS / "yolov8n.onnx").exists() and (MODELS / "sface.onnx").exists()
         and (IMAGES / "zidane.jpg").exists()),
    reason="models or VISION_TEST_IMAGES not available")


@need
def test_yolo_finds_people_and_a_bus():
    yolo = YoloOnnx(MODELS / "yolov8n.onnx", COCO_KINDS, 0.45)
    kinds = [d.kind for d in yolo.detect(cv2.imread(str(IMAGES / "bus.jpg")))]
    assert kinds.count("person") >= 3 and "vehicle" in kinds


@need
def test_faces_known_vs_unknown(tmp_path):
    photo = cv2.imread(str(IMAGES / "zidane.jpg"))
    left = photo[181:581, 494:715]                       # one person, different scale and exposure
    left = cv2.convertScaleAbs(cv2.resize(left, None, fx=1.7, fy=1.7), alpha=0.85, beta=15)
    (tmp_path / "zidane").mkdir()
    cv2.imwrite(str(tmp_path / "zidane" / "1.jpg"), left)
    rec = FaceRecognizer(MODELS / "yunet.onnx", MODELS / "sface.onnx", tmp_path)
    found = sorted((d.kind, d.name) for d in rec.detect(photo))
    assert found == [("face_known", "zidane"), ("face_unknown", None)]
