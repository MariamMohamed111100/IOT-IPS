import json

import pytest
from conftest import make_event


def test_simulator_traffic_registers_all_devices(client, auth, house):
    devices = client.get("/devices", headers=auth).json()
    assert len(devices) == 20
    siren = next(d for d in devices if d["device_id"] == "siren_main")
    assert (siren["device_type"], siren["zone"], siren["online"]) == ("siren", "living_room", True)
    assert siren["state"] == {"power": "off"}


def test_scenario_events_are_stored_and_readable(client, auth, house):
    house.play("night_intruder")
    events = client.get("/events", headers=auth).json()
    assert sorted(e["type"] for e in events) == ["door.open", "motion.night", "motion.night"]
    door = next(e for e in events if e["type"] == "door.open")
    assert door["data"] == {"door_id": "door_garage"} and door["integrity_ok"] is True
    assert door["source"] == "sim.door" and door["zone"] == "garage"


def test_event_data_is_encrypted_in_the_database(client, house, sql):
    house.play("kitchen_fire")
    blobs = [row[0] for row in sql("SELECT data_encrypted FROM events")]
    assert blobs and all(b"sensor_id" not in b and b"ppm" not in b for b in blobs)


def test_duplicate_event_is_ignored(client, auth, feed):
    for _ in range(3):
        feed("home/garage/pir/pir_garage/event", make_event())
    assert len(client.get("/events", headers=auth).json()) == 1


def test_device_status_updates_and_offline(client, auth, feed):
    topic = "home/kitchen/valve/valve_main/status"
    feed(topic, {"online": True, "state": {"open": False}})
    feed(topic, {"online": False, "state": {"open": False}})
    (device,) = client.get("/devices", headers=auth).json()
    assert device["online"] is False and device["state"] == {"open": False}


# ------------------------------------------------------------------ untrusted input
BAD_EVENTS = {
    "bad severity": make_event("bad-sev-0001", severity_hint="EXTREME"),
    "bad zone": make_event("bad-zone-001", zone="../../etc"),
    "zone differs from topic": make_event("bad-topic-01", zone="kitchen"),
    "bad type": make_event("bad-type-001", type="NotAType"),
    "id too short": make_event("x"),
    "bad timestamp": make_event("bad-ts-0001", ts="yesterday"),
    "data too large": make_event("big-data-01", data={"blob": "A" * 40_000}),
    "missing field": {k: v for k, v in make_event("missing-001").items() if k != "source"},
}


@pytest.mark.parametrize("name", BAD_EVENTS)
def test_malformed_events_are_rejected_and_do_not_break_listing(client, auth, feed, name):
    feed("home/garage/pir/pir_garage/event", BAD_EVENTS[name])
    feed("home/garage/pir/pir_garage/event", make_event("good-event-01"))
    ids = [e["id"] for e in client.get("/events", headers=auth).json()]
    assert ids == ["good-event-01"]


@pytest.mark.parametrize("payload", [b"not json", b"[]", b"42", b"\xff\xfe", b"x" * 70_000],
                         ids=["not-json", "list", "int", "invalid-utf8", "oversized"])
def test_garbage_payloads_are_ignored(client, auth, feed, payload):
    feed("home/garage/pir/pir_garage/event", payload)
    assert client.get("/events", headers=auth).json() == []


@pytest.mark.parametrize("topic,payload", [
    ("home/garage/pir/pir_garage/status", {"online": "yes", "state": {}}),
    ("home/garage/pir/pir_garage/status", {"online": True}),
    ("home/GARAGE/pir/pir_garage/status", {"online": True, "state": {}}),
    ("home/garage/pir/../status", {"online": True, "state": {}}),
])
def test_bad_status_messages_are_ignored(client, auth, feed, topic, payload):
    feed(topic, payload)
    assert client.get("/devices", headers=auth).json() == []


# ------------------------------------------------------------------ alerts
@pytest.mark.parametrize("source", ["vision", "cyber", "engine"])
def test_security_alerts_are_persisted(client, auth, feed, source):
    feed(f"security/alerts/{source}", make_event(f"alert-{source}-01", source=source))
    (event,) = client.get("/events", headers=auth).json()
    assert event["source"] == source


# ------------------------------------------------------------------ incidents and risk
INCIDENT = {"id": "incident-42", "ts": "2026-10-08T10:30:28+00:00", "zone": "garage",
            "level": "critical", "score": 120, "trigger": "smoke.detected",
            "events": ["evt-00000001", "evt-00000002"], "actions": ["siren"], "summary": "Fire"}


def test_incident_with_score_above_100_is_stored(client, auth, feed):
    feed("security/incidents", INCIDENT)
    (inc,) = client.get("/incidents", headers=auth).json()
    assert (inc["score"], inc["summary"], inc["integrity_ok"]) == (120, "Fire", True)


def test_incident_update_does_not_duplicate(client, auth, feed):
    feed("security/incidents", INCIDENT)
    feed("security/incidents", {**INCIDENT, "actions": ["siren", "block_ip"], "summary": "Fire!"})
    (inc,) = client.get("/incidents", headers=auth).json()
    assert inc["actions"] == ["siren", "block_ip"] and inc["summary"] == "Fire!"


@pytest.mark.parametrize("patch", [{"level": "apocalyptic"}, {"score": -5}, {"zone": "A/B"},
                                   {"events": "nope"}, {"summary": "x" * 5000}])
def test_bad_incidents_are_rejected(client, auth, feed, patch):
    feed("security/incidents", {**INCIDENT, **patch})
    assert client.get("/incidents", headers=auth).json() == []


def test_incident_timeline_is_chronological(client, auth, feed):
    feed("security/alerts/cyber", make_event("evt-00000002", ts="2026-10-08T10:30:26+00:00"))
    feed("security/alerts/vision", make_event("evt-00000001", ts="2026-10-08T10:30:24+00:00"))
    feed("security/alerts/vision", make_event("evt-unrelated", ts="2026-10-08T10:00:00+00:00"))
    feed("security/incidents", INCIDENT)
    timeline = client.get("/incidents/incident-42/events", headers=auth).json()
    assert [e["id"] for e in timeline] == ["evt-00000001", "evt-00000002"]
    assert client.get("/incidents/ghost/events", headers=auth).status_code == 404


def test_risk_snapshot_per_zone(client, auth, feed):
    risk = {"ts": "2026-10-08T10:30:28Z", "zone": "garage", "level": "high", "score": 85,
            "factors": [{"type": "cyber.port_scan", "weight": 25}], "actions": ["log", "siren"]}
    feed("security/risk", risk)
    feed("security/risk", {**risk, "score": 95, "level": "critical"})
    (state,) = client.get("/risk", headers=auth).json()
    assert (state["score"], state["level"], state["actions"]) == (95, "critical", ["log", "siren"])


def test_ingestion_survives_a_database_error(client, auth, feed, monkeypatch):
    import mqtt_handler

    def boom():
        raise RuntimeError("database down")
    monkeypatch.setattr(mqtt_handler, "SessionLocal", boom)
    feed("home/garage/pir/pir_garage/event", make_event())        # must not raise
    monkeypatch.undo()
    assert json.dumps(client.get("/events", headers=auth).json()) == "[]"


def test_vision_alert_with_its_extra_fields_is_stored_and_served(client, auth, feed):
    """Shape produced by services/vision (confidence, snapshot, camera_id, latency_ms)."""
    from smartsecure_common import Event
    event = Event(source="vision", type="face.unknown", zone="entrance", severity_hint="high",
                  data={"confidence": 0.94, "camera_id": "cam_entrance", "latency_ms": 183,
                        "snapshot": "snapshots/abc.jpg"})
    feed("security/alerts/vision", event.model_dump_json())
    (stored,) = client.get("/events?type=face.unknown", headers=auth).json()
    assert stored["data"]["snapshot"] == "snapshots/abc.jpg" and stored["integrity_ok"] is True
    assert stored["source"] == "vision" and stored["zone"] == "entrance"
