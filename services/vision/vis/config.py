"""All vision settings come from environment variables (same code in Docker and on the Pi)."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

_TOKEN = re.compile(r"^[a-z0-9_]+$")


def _f(name: str, default: float) -> float:
    return float(os.getenv(name, default))


def _b(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _outdoor_zones() -> set[str]:
    """Outdoor zones come from config/zones.yaml when it is mounted (same file the engine reads)."""
    path = Path(os.getenv("ZONES_FILE", "/config/zones.yaml"))
    if path.exists():
        import yaml

        return set(yaml.safe_load(path.read_text()).get("outdoor_zones", []))
    return {"entrance", "backyard"}


@dataclass
class Settings:
    # --- camera -------------------------------------------------------------------
    source: str = field(
        default_factory=lambda: os.getenv("VISION_SOURCE", "/media/videos/demo.mp4"))
    camera_id: str = field(default_factory=lambda: os.getenv("CAMERA_ID", "cam_entrance"))
    zone: str = field(default_factory=lambda: os.getenv("CAMERA_ZONE", "entrance"))
    process_fps: float = field(default_factory=lambda: _f("VISION_FPS", 5.0))
    disconnect_after_s: float = field(default_factory=lambda: _f("CAMERA_DISCONNECT_AFTER_S", 10.0))
    # --- storage ------------------------------------------------------------------
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("DATA_DIR", "/data")))
    max_snapshots: int = field(default_factory=lambda: int(_f("MAX_SNAPSHOTS", 500)))
    # --- models -------------------------------------------------------------------
    model_dir: Path = field(default_factory=lambda: Path(os.getenv("MODEL_DIR", "/app/models")))
    known_faces_dir: Path = field(
        default_factory=lambda: Path(os.getenv("KNOWN_FACES_DIR", "/media/known_faces")))
    # --- thresholds ---------------------------------------------------------------
    min_conf: float = field(default_factory=lambda: _f("MIN_CONFIDENCE", 0.45))
    face_min_conf: float = field(default_factory=lambda: _f("FACE_MIN_CONFIDENCE", 0.8))
    face_match: float = field(default_factory=lambda: _f("FACE_MATCH_THRESHOLD", 0.363))
    confirm_frames: int = field(default_factory=lambda: int(_f("CONFIRM_FRAMES", 2)))
    motion_area: float = field(default_factory=lambda: _f("MOTION_MIN_AREA", 0.01))
    # A fire model trained on a small dataset is noisy: stricter floors, and smoke from the model
    # is OFF by default because `smoke.detected` scores 100 (it would trigger the siren).
    fire_min_conf: float = field(default_factory=lambda: _f("FIRE_MIN_CONF", 0.5))
    smoke_min_conf: float = field(default_factory=lambda: _f("SMOKE_MIN_CONF", 0.8))
    smoke_from_model: bool = field(default_factory=lambda: _b("SMOKE_FROM_MODEL", False))
    fire_min_motion: float = field(default_factory=lambda: _f("FIRE_MIN_MOTION", 0.25))
    package_min_conf: float = field(default_factory=lambda: _f("PACKAGE_MIN_CONF", 0.5))
    package_size: int = field(default_factory=lambda: int(_f("PACKAGE_IMGSZ", 640)))
    fire_size: int = field(default_factory=lambda: int(_f("FIRE_IMGSZ", 640)))
    fire_heuristic: bool = field(default_factory=lambda: _b("FIRE_HEURISTIC", False))
    # seconds before the same kind of alert may be sent again
    cooldown: dict[str, float] = field(default_factory=lambda: {
        "face.unknown": _f("COOLDOWN_FACE", 15),
        "person.detected": _f("COOLDOWN_PERSON", 10),
        "vehicle.detected": _f("COOLDOWN_VEHICLE", 30),
        "package.detected": _f("COOLDOWN_PACKAGE", 60),
        "motion.outdoor": _f("COOLDOWN_MOTION", 30),
        "fire.detected": _f("COOLDOWN_FIRE", 20),
        "smoke.detected": _f("COOLDOWN_FIRE", 20),
        "camera.disconnected": _f("COOLDOWN_CAMERA", 300),
    })
    outdoor_zones: set[str] = field(default_factory=_outdoor_zones)

    def validate(self) -> None:
        for label, value in (("CAMERA_ID", self.camera_id), ("CAMERA_ZONE", self.zone)):
            if not _TOKEN.match(value):
                raise ValueError(f"{label}={value!r}: use lowercase a-z, 0-9 and underscore")
        if self.process_fps <= 0:
            raise ValueError("VISION_FPS must be > 0")
        if self.confirm_frames < 1:
            raise ValueError("CONFIRM_FRAMES must be >= 1")
