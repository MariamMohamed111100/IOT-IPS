import json
import pathlib
import sys

import pytest

SERVICE = pathlib.Path(__file__).resolve().parent.parent
REPO = SERVICE.parent.parent
sys.path.insert(0, str(SERVICE))

from eng.core import Engine  # noqa: E402
from eng.notify import Notifier  # noqa: E402
from eng.policy import load_policy  # noqa: E402
from smartsecure_common import make_event  # noqa: E402

DEVICES = [("living_room", "siren", "siren_main"), ("garage", "bulb", "bulb_garage"),
           ("kitchen", "bulb", "bulb_kitchen"), ("entrance", "lock", "lock_front"),
           ("kitchen", "valve", "valve_main")]


class Rig:
    def __init__(self) -> None:
        self.t = 1000.0
        self.out: list[tuple[str, dict, bool]] = []
        self.engine = Engine(load_policy(REPO / "config" / "risk_scores.yaml"),
                             lambda tp, p, r: self.out.append((tp, p, r)),
                             notifier=Notifier(background=False), clock=lambda: self.t)
        for zone, dtype, did in DEVICES:
            self.engine.on_message(f"home/{zone}/{dtype}/{did}/status",
                                   json.dumps({"online": True, "state": {}}))

    def send(self, source, etype, zone, **data):
        ev = make_event(source, etype, zone, **data)
        topic = (f"security/alerts/{source}" if source in ("vision", "cyber")
                 else f"home/{zone}/sensor/{source}/event")
        self.engine.on_message(topic, ev.model_dump_json())
        return ev

    def topic(self, prefix):
        return [(t, p) for t, p, _ in self.out if t.startswith(prefix)]

    def last(self, topic):
        found = [p for t, p, _ in self.out if t == topic]
        return found[-1] if found else None

    def risk(self, zone):
        found = [p for t, p, _ in self.out if t == "security/risk" and p["zone"] == zone]
        return found[-1] if found else None

    def advance(self, seconds):
        self.t += seconds
        self.engine.tick()


@pytest.fixture
def rig():
    return Rig()
