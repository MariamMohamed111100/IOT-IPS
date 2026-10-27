"""`make demo-incident` against the real API code, the real simulators and the REAL engine
(all in-process): the script stages vision + cyber, the engine decides, the API stores."""
import json
import pathlib
import sys
import time
from datetime import datetime

import pytest

REPO = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "services" / "engine"))
import demo_incident  # noqa: E402

from eng.core import Engine  # noqa: E402
from eng.notify import Notifier  # noqa: E402
from eng.policy import load_policy  # noqa: E402


class World:
    """Wires the engine between the broker's two sides (API feed and the house's bus)."""

    def __init__(self, api_feed):
        self.api_feed, self.house, self.running = api_feed, None, True
        self.now = time.time()
        self.blocks, self.commands = [], []
        self.engine = Engine(load_policy(REPO / "config" / "risk_scores.yaml"), self.publish,
                             notifier=Notifier(background=False), clock=lambda: self.now)

    def publish(self, topic, payload, retain):
        if topic.startswith("home/"):                       # command -> device -> status back
            self.commands.append((topic, payload))
            start = len(self.house.bus.published)
            self.house.bus.publish(topic, json.dumps(payload))
            self.house.deliver(start)
        else:
            if topic == "system/block":
                self.blocks.append(payload)
            self.api_feed(topic, payload)

    def deliver(self, topic, payload):
        self.api_feed(topic, payload)
        if self.running:
            body = payload if isinstance(payload, (bytes, str)) else json.dumps(payload)
            self.engine.on_message(topic, body)


@pytest.fixture
def world():
    import types

    import mqtt_handler

    def api_feed(topic, payload):                           # the API, exactly like paho calls it
        if not isinstance(payload, (bytes, str)):
            payload = json.dumps(payload)
        body = payload if isinstance(payload, bytes) else payload.encode()
        mqtt_handler.on_message(None, None, types.SimpleNamespace(topic=topic, payload=body))

    return World(api_feed)


@pytest.fixture
def feed(world):                                            # override: everyone talks via World
    return world.deliver


@pytest.fixture
def house(house, world):
    world.house = house
    return house


class InProcessTransport:
    """Same interface as DockerTransport, wired to the app under test instead of Docker."""

    def __init__(self, client, auth, world, house, drop=()):
        self.client, self.auth, self.world, self.house = client, auth, world, house
        self.drop = set(drop)
        self.published, self.slept = [], []

    def trigger_scenario(self, name):
        self.house.play(name)

    def publish(self, topic, payload):
        self.published.append(topic)
        if topic not in self.drop:
            self.world.deliver(topic, payload)

    def api(self, method, path, body=None, params=None):
        response = self.client.request(method, path, json=body, params=params, headers=self.auth)
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, None

    def sleep(self, seconds):
        self.slept.append(seconds)


@pytest.fixture
def transport(client, auth, world, house):
    return InProcessTransport(client, auth, world, house)


def test_the_demo_incident_passes_end_to_end(transport):
    lines = []
    failures = demo_incident.play(transport, out=lines.append)
    assert failures == [], "\n".join(lines)
    # the script stages ONLY the detections; scoring and responses come from the engine
    assert transport.published == ["security/alerts/vision", "security/alerts/cyber"]
    assert "DEMO OK" in lines[-1]


def test_engine_made_the_commands_and_the_block(transport, world):
    demo_incident.play(transport, out=lambda _: None)
    assert {(t, p["action"], p["requested_by"]) for t, p in world.commands} == {
        ("home/garage/bulb/bulb_garage/cmd", "on", "engine"),
        ("home/living_room/siren/siren_main/cmd", "on", "engine")}
    assert [b["ip"] for b in world.blocks] == ["192.168.1.15"]


def test_timeline_matches_the_proposal_offsets(transport, client, auth):
    demo_incident.play(transport, out=lambda _: None)
    incident = client.get("/incidents", headers=auth).json()[0]
    events = client.get(f"/incidents/{incident['id']}/events", headers=auth).json()
    first = datetime.fromisoformat(events[0]["ts"])
    offsets = [(datetime.fromisoformat(e["ts"]) - first).total_seconds() for e in events]
    assert offsets == [0.0, 3.0, 5.0]                           # 10:30:21 -> :24 -> :26
    assert [e["source"] for e in events] == ["sim.pir", "vision", "cyber"]


def test_speed_shortens_the_pauses(client, auth, world, house):
    fast = InProcessTransport(client, auth, world, house)
    demo_incident.play(fast, speed=2.0, out=lambda _: None)
    assert [s for s in fast.slept if s >= 0.5][:2] == [1.5, 1.0]


def test_can_run_twice_and_both_incidents_are_kept(transport, client, auth, world):
    assert demo_incident.play(transport, out=lambda _: None) == []
    world.now += 11 * 60                                        # the first risk decays to 0
    world.engine.tick()
    assert demo_incident.play(transport, out=lambda _: None) == []
    assert len(client.get("/incidents", headers=auth).json()) == 2


def test_the_demo_notices_when_the_engine_is_not_running(client, auth, world, house):
    world.running = False
    failures = demo_incident.play(InProcessTransport(client, auth, world, house),
                                  out=lambda _: None)
    assert any("engine" in f for f in failures)


def test_the_demo_notices_when_a_detection_never_arrives(client, auth, world, house):
    broken = InProcessTransport(client, auth, world, house, drop={"security/alerts/vision"})
    failures = demo_incident.play(broken, out=lambda _: None)
    assert any("incident" in f for f in failures)


def test_the_demo_refuses_to_run_on_top_of_live_garage_risk(transport):
    transport.world.engine.on_message("security/alerts/vision", json.dumps({
        "id": "e1", "ts": "2026-01-01T00:00:00+00:00", "source": "vision", "type": "face.unknown",
        "zone": "garage", "severity_hint": "high", "data": {}}))
    failures = demo_incident.play(transport, out=lambda _: None)
    assert failures and "live garage risk" in failures[0]
