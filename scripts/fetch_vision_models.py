#!/usr/bin/env python3
"""Download the free models the vision service needs into services/vision/models/.

  yunet.onnx    face detector     (OpenCV Zoo, MIT)
  sface.onnx    face recognizer   (OpenCV Zoo, Apache-2.0)
  yolov8n.onnx  object detector   (Ultralytics YOLOv8n, AGPL-3.0: fine for this project's own use,
                                   read the licence before selling a product that ships it)

Downloads are checked against pinned SHA-256 hashes. YOLO is exported from the official .pt with
Ultralytics (PyTorch is only needed for this one-off export, never inside the service image): uses
a local ``ultralytics`` if installed, else a throw-away Docker container.
"""
from __future__ import annotations

import hashlib
import pathlib
import shutil
import subprocess
import sys
import urllib.request

DEST = pathlib.Path(__file__).resolve().parent.parent / "services" / "vision" / "models"
ZOO = "https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models"
FILES = {
    "yunet.onnx": (f"{ZOO}/face_detection_yunet/face_detection_yunet_2023mar.onnx",
                   "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4"),
    "sface.onnx": (f"{ZOO}/face_recognition_sface/face_recognition_sface_2021dec.onnx",
                   "0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79"),
    "yolov8n.pt": ("https://github.com/ultralytics/assets/releases/download/v8.3.0/yolov8n.pt",
                   "f59b3d833e2ff32e194b5bb8e08d211dc7c5bdf144b90d2c8412c47ccfc83b36"),
}


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def download(name: str, url: str, digest: str) -> None:
    target = DEST / name
    if target.exists() and sha256(target) == digest:
        print(f"ok      {name}")
        return
    print(f"fetch   {name}")
    tmp = target.with_suffix(target.suffix + ".part")
    urllib.request.urlretrieve(url, tmp)       # noqa: S310 (fixed https URLs above)
    if sha256(tmp) != digest:
        tmp.unlink()
        sys.exit(f"ERROR: {name} does not match its pinned SHA-256: refusing to use it")
    tmp.replace(target)


def export_yolo() -> None:
    if (DEST / "yolov8n.onnx").exists():
        print("ok      yolov8n.onnx")
        return
    print("export  yolov8n.onnx")
    try:
        import ultralytics  # noqa: F401
        from ultralytics import YOLO
        YOLO(str(DEST / "yolov8n.pt")).export(format="onnx", opset=12, imgsz=640)
    except ImportError:
        if not shutil.which("docker"):
            sys.exit("ERROR: need `pip install ultralytics onnx` or Docker to export yolov8n.onnx")
        subprocess.run(
            ["docker", "run", "--rm", "-v", f"{DEST}:/m", "-w", "/m", "python:3.12-slim",
             "sh", "-c",
             "pip install -q ultralytics onnx && yolo export model=yolov8n.pt format=onnx "
             "opset=12 imgsz=640"], check=True)


def main() -> None:
    DEST.mkdir(parents=True, exist_ok=True)
    for name, (url, digest) in FILES.items():
        if name == "yolov8n.pt" and (DEST / "yolov8n.onnx").exists():
            continue                      # already exported, the .pt is only needed for the export
        download(name, url, digest)
    export_yolo()
    (DEST / "yolov8n.pt").unlink(missing_ok=True)
    print(f"models ready in {DEST}")


if __name__ == "__main__":
    main()
