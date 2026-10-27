import json
import pathlib
import sys

import numpy as np
import pytest

SERVICE = pathlib.Path(__file__).resolve().parent.parent
REPO = SERVICE.parent.parent
sys.path.insert(0, str(SERVICE))

from vis.config import Settings  # noqa: E402
from vis.pipeline import Pipeline  # noqa: E402
from vis.snapshots import SnapshotStore  # noqa: E402
from vis.types import Detection  # noqa: E402


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class FakeSink:
    def __init__(self) -> None:
        self.events = []

    def publish(self, event) -> None:
        self.events.append(event)


class Scripted:
    """Detector that returns a prepared list for each successive frame (last one repeats)."""

    def __init__(self, *frames: list[Detection]) -> None:
        self.frames, self.i = list(frames), 0

    def detect(self, frame):
        out = self.frames[min(self.i, len(self.frames) - 1)]
        self.i += 1
        return out


class Boom:
    def detect(self, frame):
        raise RuntimeError("model exploded")


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def sink():
    return FakeSink()


@pytest.fixture
def frame():
    return np.full((120, 160, 3), 90, np.uint8)


@pytest.fixture
def settings(tmp_path):
    s = Settings(data_dir=tmp_path, zone="entrance", camera_id="cam_entrance")
    s.confirm_frames = 2
    s.outdoor_zones = {"entrance", "backyard"}
    return s


@pytest.fixture
def make_pipeline(settings, sink, clock):
    def build(*, objects=None, faces=None, motion=None, fire=(), **overrides):
        for k, v in overrides.items():
            setattr(settings, k, v)
        return Pipeline(settings, objects=objects, faces=faces, motion=motion, fire=fire,
                        snapshots=SnapshotStore(settings.data_dir), sink=sink, clock=clock)
    return build


@pytest.fixture
def event_schema():
    return json.loads((REPO / "contract" / "event.schema.json").read_text())
