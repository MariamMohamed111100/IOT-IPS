import json
import os
import time

import cv2
import numpy as np
import pytest

from smartsecure_common import Event
from vis.config import Settings
from vis.publisher import MqttSink
from vis.snapshots import SnapshotStore


def test_snapshot_written_atomically_and_relative(tmp_path):
    store = SnapshotStore(tmp_path)
    rel = store.save("abc", np.zeros((20, 30, 3), np.uint8))
    assert rel == "snapshots/abc.jpg"
    assert cv2.imread(str(tmp_path / rel)).shape == (20, 30, 3)
    assert [p.name for p in (tmp_path / "snapshots").iterdir()] == ["abc.jpg"]   # no temp left


def test_prune_keeps_newest(tmp_path):
    store = SnapshotStore(tmp_path, max_files=3)
    for i in range(6):
        store.save(f"e{i}", np.zeros((8, 8, 3), np.uint8))
        os.utime(tmp_path / "snapshots" / f"e{i}.jpg", (time.time() + i, time.time() + i))
    assert store.prune() == 3
    assert sorted(p.stem for p in (tmp_path / "snapshots").iterdir()) == ["e3", "e4", "e5"]


def test_settings_validation(monkeypatch):
    monkeypatch.setenv("CAMERA_ZONE", "Living Room")
    with pytest.raises(ValueError, match="CAMERA_ZONE"):
        Settings().validate()
    monkeypatch.setenv("CAMERA_ZONE", "garage")
    monkeypatch.setenv("VISION_FPS", "0")
    with pytest.raises(ValueError, match="VISION_FPS"):
        Settings().validate()


def test_env_overrides_cooldowns(monkeypatch):
    monkeypatch.setenv("COOLDOWN_PERSON", "3")
    assert Settings().cooldown["person.detected"] == 3


def test_publisher_uses_the_only_topic_vision_may_write():
    class Info:
        rc = 0

    class FakeClient:
        calls: list = []

        def publish(self, topic, payload, qos):
            self.calls.append((topic, payload, qos))
            return Info()

    client = FakeClient()
    MqttSink(client).publish(Event(source="vision", type="face.unknown", zone="garage",
                                   data={"confidence": 0.9, "snapshot": "snapshots/x.jpg"}))
    topic, payload, qos = client.calls[0]
    assert topic == "security/alerts/vision" and qos == 1
    assert json.loads(payload)["type"] == "face.unknown"


def test_fire_model_input_size_is_configurable(monkeypatch):
    from vis.config import Settings
    assert Settings().fire_size == 640
    monkeypatch.setenv("FIRE_IMGSZ", "800")
    assert Settings().fire_size == 800


def test_smoke_from_model_is_off_by_default(monkeypatch):
    from vis.config import Settings
    s = Settings()
    assert (s.fire_min_conf, s.smoke_min_conf, s.smoke_from_model) == (0.5, 0.8, False)
    monkeypatch.setenv("SMOKE_FROM_MODEL", "true")
    assert Settings().smoke_from_model is True


def test_fire_and_package_settings_defaults(monkeypatch):
    from vis.config import Settings
    s = Settings()
    assert (s.fire_min_motion, s.package_min_conf, s.package_size) == (0.25, 0.5, 640)
    monkeypatch.setenv("FIRE_MIN_MOTION", "0.4")
    assert Settings().fire_min_motion == 0.4
