"""iot_ips.enrich: the `details` object of a detection alert."""
import json

import pytest

from iot_ips.enrich import IPS_TYPES, build_details, to_published
from iot_ips.paths import DEFAULT_DEVICES_PATH

CAM = {d["device_id"]: d for d in json.loads(DEFAULT_DEVICES_PATH.read_text())["devices"]}["CAM-001"]


def alert(etype="cyber.brute_force", **over):
    data = {"src_ip": "203.0.113.45", "dst_ip": "192.168.1.50", "dst_port": 22, "protocol": "TCP",
            "direction": "inbound", "device_id": "cam_001", "confidence": 0.98, "mitre_technique": "T1110",
            "failed_attempts": 300, "connection_attempts": 300, "duration": 240}
    data.update(over)
    return {"id": "6f1c2d9a-52b1-4a0e-9c3e-0d6c5e7a11f2", "ts": "2026-10-21T09:05:15.000+00:00", "source": "cyber",
            "type": etype, "zone": "network", "severity_hint": "critical", "data": data}


def test_published_scale_examples_of_the_integration_file():
    assert [to_published(s) for s in (29, 54, 67, 77, 81, 85, 86)] == [30, 55, 72, 87, 91, 93, 94]
    assert all(to_published(a) <= to_published(a + 1) for a in range(100))
    assert to_published("junk") == 0 and to_published(float("nan")) == 0 and to_published(float("inf")) == 0
    assert to_published(250) == 100 and to_published(-3) == 0


def test_details_of_a_brute_force_have_every_part():
    d = build_details(alert(), CAM)
    assert d["mitre_technique"] == "T1110" and d["ips_level"] == "critical"
    assert d["ips_score"] == to_published(d["ips_score_raw"]) >= 91
    assert set(d["reports"]) == {"technical", "executive"} and "Security Incident Report" in d["reports"]["technical"]
    assert set(d) <= {"mitre_technique", "ips_score", "ips_level", "ips_score_raw", "reports"}      # the schema's keys


@pytest.mark.parametrize("etype", sorted(IPS_TYPES))
def test_every_ips_event_type_gets_details(etype):
    assert build_details(alert(etype), CAM)["ips_level"] in ("low", "medium", "high", "critical")


def test_other_types_and_junk_give_none_and_never_raise():
    assert build_details(alert("cyber.rogue_device"), CAM) is None
    assert build_details(alert("cyber.block_applied"), CAM) is None
    for junk in (None, [], "x", {}, {"type": "cyber.dos"}, {"type": "cyber.dos", "data": "x"}):
        assert build_details(junk, CAM) is None


def test_an_unknown_device_or_odd_values_still_work():
    assert build_details(alert(), None) is not None
    assert build_details(alert(duration=-5, dst_port="x", confidence="high", failed_attempts=None), CAM) is not None


def test_a_bad_mitre_tag_is_left_out_not_trusted():
    assert "mitre_technique" not in build_details(alert(mitre_technique="<script>"), CAM)


def test_the_event_stays_under_the_api_size_limit():
    d = build_details(alert(), CAM)
    assert len(json.dumps(alert()["data"] | {"details": d})) < 32 * 1024
