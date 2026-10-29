"""The real path, with no Docker: services/ips_cyber -> engine -> what the API stores and Warden reads.

Warden reads the MITRE tag, the IPS score and the two reports from `data.details` of the STORED EVENTS of an incident
(services/frontend/index.html, renderIncidentEvents). The API stores an alert's data as it arrives, so the sensor
has to put `details` there; the engine's incident `details` is not stored by the API. This test fails if either
side stops doing its part.
"""
import json
import sys

import pytest
from conftest import REPO, Rig

pytest.importorskip("iot_ips")
sys.path.insert(0, str(REPO / "services" / "ips_cyber"))
from ips_cyber import publisher as pub  # noqa: E402
from ips_cyber import service as sensor  # noqa: E402
from ips_cyber import sources  # noqa: E402

from eng.ips import IpsEnricher  # noqa: E402


@pytest.fixture
def alerts():
    devices = sensor.load_devices(str(REPO / "config" / "ips_devices.json"))
    memory = pub.MemoryPublisher()
    service = sensor.IpsCyberService(devices, memory, sensor.load_service_config())
    service.run(sources.csv_source(str(REPO / "ips" / "data" / "sample_events.csv")), "sample")
    return [m[1] for m in memory.messages]


def test_the_stored_events_have_what_warden_reads(alerts):
    assert len(alerts) == 7
    for a in alerts:                                   # the API stores `data` as it arrives
        d = a["data"]["details"]
        assert d["mitre_technique"] and d["ips_level"] and d["reports"]["technical"] and d["reports"]["executive"]


def test_one_incident_with_the_sensors_details(alerts):
    rig = Rig()
    rig.engine.ips = IpsEnricher.load(REPO / "config" / "ips_devices.json")
    for a in alerts:
        rig.engine.on_message("security/alerts/cyber", json.dumps(a))
    sent = [p for _, p in rig.topic("security/incidents")]
    assert len({i["id"] for i in sent}) == 1
    inc = sent[-1]
    assert inc["zone"] == "network" and len(inc["events"]) == 7 and inc["level"] == "critical"
    strongest = max((a["data"]["details"] for a in alerts), key=lambda d: d["ips_score"])
    assert inc["details"] == strongest                 # the sensor's details pass through unchanged
    assert rig.topic("home/") == []                    # a network attack switches on no light or siren


def test_the_engine_fallback_agrees_with_the_sensor(alerts):
    """For an alert WITHOUT details the engine builds them itself; the two must never drift apart."""
    from smartsecure_common import Event
    enricher = IpsEnricher.load(REPO / "config" / "ips_devices.json")
    for a in alerts:
        bare = json.loads(json.dumps(a))
        del bare["data"]["details"]
        assert enricher.enrich(Event.model_validate(bare)) == a["data"]["details"]

