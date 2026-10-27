"""Runs the real main() loop (real FrameSource, real MOG2, real files) with a fake MQTT client."""
import json
import threading
import time

import cv2
import main as vision_main
import numpy as np


class FakeMqtt:
    def __init__(self):
        self.sent = []
        self.disconnected = False

    def publish(self, topic, payload, qos=0):
        class Info:
            rc = 0
        self.sent.append((topic, json.loads(payload), qos))
        return Info()

    def disconnect(self):
        self.disconnected = True


def start(monkeypatch, tmp_path, source):
    client = FakeMqtt()
    monkeypatch.setattr(vision_main, "connect", lambda service: client)
    monkeypatch.setattr(vision_main, "start_heartbeat", lambda *a, **k: None)
    for k, v in {"VISION_SOURCE": source, "DATA_DIR": str(tmp_path / "data"),
                 "MODEL_DIR": str(tmp_path / "no-models"), "CAMERA_ZONE": "entrance",
                 "ZONES_FILE": str(tmp_path / "none.yaml"), "VISION_FPS": "25",
                 "CONFIRM_FRAMES": "1"}.items():
        monkeypatch.setenv(k, v)
    stop = threading.Event()
    t = threading.Thread(target=vision_main.main, args=(stop,), daemon=True)
    t.start()
    return client, stop, t


def wait_for(cond, seconds=15):
    end = time.time() + seconds
    while time.time() < end and not cond():
        time.sleep(0.05)
    return cond()


def test_clip_with_sudden_activity_publishes_motion_alert(monkeypatch, tmp_path):
    clip = tmp_path / "demo.avi"
    w = cv2.VideoWriter(str(clip), cv2.VideoWriter_fourcc(*"MJPG"), 25, (320, 180))
    quiet = np.full((180, 320, 3), 60, np.uint8)
    busy = quiet.copy()
    cv2.rectangle(busy, (40, 30), (260, 150), (255, 255, 255), -1)
    for _ in range(40):
        w.write(quiet)
    for _ in range(25):
        w.write(busy)
    w.release()
    client, stop, t = start(monkeypatch, tmp_path, str(clip))
    assert wait_for(lambda: client.sent)
    stop.set()
    t.join(5)
    topic, event, qos = client.sent[0]
    assert (topic, qos) == ("security/alerts/vision", 1)
    assert event["type"] == "motion.outdoor" and event["source"] == "vision"
    assert event["data"]["snapshot"] == f"snapshots/{event['id']}.jpg"
    assert (tmp_path / "data" / event["data"]["snapshot"]).is_file()
    assert client.disconnected


def test_missing_video_idles_quietly_without_alerts(monkeypatch, tmp_path):
    client, stop, t = start(monkeypatch, tmp_path, str(tmp_path / "absent.mp4"))
    time.sleep(0.5)
    assert client.sent == [] and t.is_alive()              # alive (heartbeat), but silent
    stop.set()
    t.join(5)
    assert not t.is_alive()
