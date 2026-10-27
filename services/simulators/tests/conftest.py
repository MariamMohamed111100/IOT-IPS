import json
import pathlib
import re
import sys

import pytest
import yaml

SERVICE = pathlib.Path(__file__).resolve().parent.parent
REPO = SERVICE.parent.parent
sys.path.insert(0, str(SERVICE))

from sim.bus import LoopbackBus  # noqa: E402
from sim.devices import build_devices, load_config  # noqa: E402
from sim.runtime import SimulatorRuntime  # noqa: E402


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def cfg():
    return load_config()


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def devices(cfg, clock):
    return build_devices(cfg, "sim", clock=clock, temp_interval=10.0)


@pytest.fixture
def bus():
    return LoopbackBus()


@pytest.fixture
def runtime(devices, bus):
    rt = SimulatorRuntime(devices, bus)
    rt.start()
    return rt


@pytest.fixture(scope="session")
def event_schema():
    return json.loads((REPO / "contract/event.schema.json").read_text())


@pytest.fixture(scope="session")
def contract_types():
    """Event types listed in section 3 of docs/CONTRACT.md."""
    text = (REPO / "docs/CONTRACT.md").read_text(encoding="utf-8")
    section = text.split("## 3. Event type registry")[1].split("\n## ")[0]
    return set(re.findall(r"^\| `([a-z0-9_]+\.[a-z0-9_]+)` \|", section, re.M))


@pytest.fixture(scope="session")
def zones_cfg():
    return yaml.safe_load((REPO / "config/zones.yaml").read_text())
