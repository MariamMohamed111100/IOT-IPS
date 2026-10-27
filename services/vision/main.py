"""vision service: camera (looped video or RTSP) -> YOLO/face/motion -> alerts on MQTT."""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from pathlib import Path

from smartsecure_common import connect, start_heartbeat
from vis.builder import build_pipeline
from vis.config import Settings
from vis.publisher import MqttSink
from vis.snapshots import SnapshotStore
from vis.source import FrameSource

SERVICE = "vision"
log = logging.getLogger("vision")


def main(stop: threading.Event | None = None) -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = Settings()
    settings.validate()
    client = connect(SERVICE)
    start_heartbeat(client, SERVICE)
    pipeline = build_pipeline(settings, MqttSink(client), SnapshotStore(
        settings.data_dir, settings.max_snapshots))
    if stop is None:
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
    if "://" in settings.source:      # fail fast on a dead RTSP stream instead of hanging 30 s
        os.environ.setdefault("OPENCV_FFMPEG_CAPTURE_OPTIONS", "rtsp_transport;tcp|timeout;5000000")
    if "://" not in settings.source and not Path(settings.source).is_file():
        # Default `docker compose up` has no demo clip yet: stay healthy (heartbeat) and say why,
        # instead of raising camera.disconnected alerts that would pollute the risk score.
        log.error("video %s not found: put a clip at services/vision/media/videos/demo.mp4 "
                  "(or set VISION_SOURCE) and restart. Idling.", settings.source)
        stop.wait()
        return 0
    source = FrameSource(settings.source, settings.process_fps)
    log.info("vision started: source=%s zone=%s camera=%s", settings.source, settings.zone,
             settings.camera_id)
    try:
        for captured_at, frame in source.frames():
            if stop.is_set():
                break
            try:
                if frame is None:
                    if source.down_since is not None and \
                            captured_at - source.down_since >= settings.disconnect_after_s:
                        pipeline.camera_down()
                else:
                    pipeline.process(captured_at, frame)
            except Exception:                    # never let one bad frame stop the camera
                log.exception("frame processing failed")
    finally:
        source.close()
        client.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main())
