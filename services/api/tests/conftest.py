"""API test harness: real FastAPI app + SQLite + fake MQTT, fed with real simulator traffic.

Run with:  pytest services/api/tests   (separate from the other suites: the service modules
use top-level names such as `main`, which collide across services in one pytest session).
"""
import json
import os
import pathlib
import sys
import tempfile
import types
import warnings

import pytest

# Starlette 1.x emits a DeprecationWarning on every TestClient import ("Using `httpx` with
# `starlette.testclient` is deprecated; install `httpx2`"). We pin the tested pair in
# requirements, so silence it here to keep a green run warning-free.
warnings.filterwarnings("ignore", message=r"Using .*starlette\.testclient.*is deprecated.*")

REPO = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "services/api"))
sys.path.append(str(REPO / "services/simulators"))      # only for the realistic traffic fixture

_tmp = tempfile.mkdtemp(prefix="api-tests-")
os.environ.update(
    DATABASE_URL=f"sqlite:///{_tmp}/test.db",
    JWT_SECRET="j" * 48,
    API_USERS="admin:correct-horse,viewer:other-pass",
    STORAGE_KEY="s" * 48,
    API_DOCS_ENABLED="false",
    ZONES_FILE=str(REPO / "config/zones.yaml"),
    MQTT_PASSWORD="unused",
)

import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import mqtt_handler  # noqa: E402
from database import Base, engine  # noqa: E402
from security import LoginRateLimiter  # noqa: E402
from websocket_manager import manager  # noqa: E402


class _Info:
    rc = 0


class FakeMqtt:
    """Just enough of paho's Client for the API: records publishes and subscriptions."""

    def __init__(self) -> None:
        self.connected = True
        self.published: list[tuple[str, dict]] = []
        self.subscriptions: list[str] = []
        self.on_connect = None
        self.on_message = None

    def subscribe(self, topic, qos=0):
        self.subscriptions.append(topic)
        return (0, 1)

    def publish(self, topic, payload, qos=0, retain=False):
        self.published.append((topic, json.loads(payload)))
        return _Info()

    def is_connected(self):
        return self.connected

    def loop_stop(self):
        pass

    def disconnect(self):
        pass


@pytest.fixture
def fake_mqtt():
    return FakeMqtt()


@pytest.fixture
def client(monkeypatch, fake_mqtt):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(main, "connect", lambda service: fake_mqtt)
    monkeypatch.setattr(main, "start_heartbeat", lambda c, s: None)
    monkeypatch.setattr(main, "limiter", LoginRateLimiter())
    manager.connections.clear()
    with TestClient(main.app) as c:
        yield c


@pytest.fixture
def auth(client):
    r = client.post("/auth/login", json={"username": "admin", "password": "correct-horse"})
    assert r.status_code == 200
    return {"Authorization": "Bearer " + r.json()["access_token"]}


@pytest.fixture
def feed():
    """Deliver an MQTT message to the API exactly like paho would."""
    def _feed(topic, payload):
        if not isinstance(payload, (bytes, str)):
            payload = json.dumps(payload)
        body = payload if isinstance(payload, bytes) else payload.encode()
        mqtt_handler.on_message(None, None, types.SimpleNamespace(topic=topic, payload=body))
    return _feed


@pytest.fixture
def house(feed):
    """The simulated house: 20 devices publishing through an in-memory bus, wired to the API."""
    from sim import scenario
    from sim.bus import LoopbackBus
    from sim.devices import build_devices, load_config
    from sim.runtime import SimulatorRuntime

    bus = LoopbackBus()
    runtime = SimulatorRuntime(build_devices(load_config(), "sim"), bus)
    runtime.start()

    def deliver(start: int = 0) -> int:
        for topic, payload, _ in bus.published[start:]:
            feed(topic, payload)
        return len(bus.published)

    def play(name: str) -> None:
        before = len(bus.published)
        scenario.run(scenario.load_scenario(name), bus, sleep=lambda s: None, out=lambda s: None)
        deliver(before)

    deliver()
    return types.SimpleNamespace(bus=bus, runtime=runtime, play=play, deliver=deliver)


@pytest.fixture
def sql():
    """Run raw SQL against the test database (to tamper with stored rows)."""
    from sqlalchemy import text

    def _run(statement, **params):
        with engine.begin() as conn:
            return conn.execute(text(statement), params)
    return _run


def make_event(event_id="evt-00000001", **overrides):
    event = {"id": event_id, "ts": "2026-10-08T10:30:21.000+00:00", "source": "vision",
             "type": "face.unknown", "zone": "garage", "severity_hint": "high",
             "data": {"confidence": 0.93, "snapshot": "snapshots/a.jpg"}}
    event.update(overrides)
    return event
