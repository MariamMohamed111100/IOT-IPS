"""IPS integration in the engine (docs/IPS_INTEGRATION.md section 7)."""
import json

import pytest
from conftest import REPO, Rig

from eng.ips import IpsEnricher, clean_details, to_published

ATTACK = dict(src_ip="203.0.113.45", dst_ip="192.168.1.50", dst_port=22, protocol="TCP", direction="inbound",
              device_id="cam_001", confidence=0.98, mitre_technique="T1110", failed_attempts=300,
              connection_attempts=300, duration=240, target="ssh", attempts=300, window_s=240)
DETAILS = {"mitre_technique": "T1110", "ips_score": 93, "ips_level": "critical", "ips_score_raw": 85,
           "reports": {"technical": "# Technical", "executive": "# Executive"}}


def incidents(rig):
    return [p for t, p in rig.topic("security/incidents")]


def test_adapter_details_are_copied_into_the_incident(rig):
    rig.send("cyber", "cyber.brute_force", "network", **ATTACK, details=DETAILS)
    inc = rig.last("security/incidents")
    assert inc["details"] == DETAILS
    assert inc["level"] == "medium" and inc["score"] == 35          # the level still comes from the points


def test_no_details_without_ips_data(rig):
    rig.send("cyber", "cyber.brute_force", "network", **ATTACK)
    assert "details" not in rig.last("security/incidents")


def test_invalid_details_are_dropped_not_trusted(rig):
    bad = dict(DETAILS, ips_level="apocalypse", ips_score=1000, extra="<script>")
    rig.send("cyber", "cyber.brute_force", "network", **ATTACK, details=bad)
    assert "details" not in rig.last("security/incidents")
    assert clean_details(dict(DETAILS, extra="x", ips_score_raw=-4)) == {k: v for k, v in DETAILS.items() if k != "ips_score_raw"}
    big = clean_details(dict(DETAILS, reports={"technical": "x" * 50000}))
    assert len(big["reports"]["technical"]) <= 12 * 1024 and "executive" not in big["reports"]


def test_details_follow_the_contract_schema(rig):
    jsonschema = pytest.importorskip("jsonschema")
    rig.send("cyber", "cyber.brute_force", "network", **ATTACK, details=DETAILS)
    schema = json.loads((REPO / "contract" / "incident_details.schema.json").read_text())
    jsonschema.validate(rig.last("security/incidents")["details"], schema)


def test_repeat_updates_one_incident_and_keeps_the_strongest_details(rig):
    rig.send("cyber", "cyber.brute_force", "network", **ATTACK, details=dict(DETAILS, ips_score=60, ips_level="high"))
    rig.send("cyber", "cyber.dos", "network", **dict(ATTACK, dst_port=80, target=None), details=DETAILS)
    sent = incidents(rig)
    assert len({i["id"] for i in sent}) == 1
    assert len(sent[-1]["events"]) == 2 and sent[-1]["details"]["ips_score"] == 93


def test_outbound_attack_is_never_blocked(rig):
    rig.send("cyber", "cyber.dos", "network", **dict(ATTACK, direction="outbound", src_ip="192.168.1.50"))
    rig.send("cyber", "cyber.brute_force", "network", **dict(ATTACK, direction="outbound", src_ip="192.168.1.50"))
    assert rig.topic("system/block") == []


def test_inbound_attack_still_blocks_at_high(rig):
    for kind in ("cyber.dos", "cyber.brute_force"):
        rig.send("cyber", kind, "network", **ATTACK)
    rig.send("cyber", "cyber.port_scan", "network", **ATTACK)
    assert [p["ip"] for _, p in rig.topic("system/block")] == ["203.0.113.45"]


def test_block_results_are_not_scored_and_not_blocked(rig):
    for kind in ("cyber.block_applied", "cyber.block_refused"):
        rig.send("cyber", kind, "network", ip="203.0.113.45", action="block_source", device_id="cam_001",
                 reason="source_allow_listed", dry_run=True)
    assert rig.topic("security/incidents") == [] and rig.topic("system/block") == []
    assert rig.risk("network")["score"] == 0


@pytest.fixture
def ips_rig():
    pytest.importorskip("iot_ips")
    rig = Rig()
    rig.engine.ips = IpsEnricher.load(REPO / "config" / "ips_devices.json")
    assert rig.engine.ips is not None
    return rig


def test_engine_builds_details_with_the_ips_chain(ips_rig):
    ips_rig.send("cyber", "cyber.brute_force", "network", **ATTACK)
    d = ips_rig.last("security/incidents")["details"]
    assert d["ips_level"] == "critical" and d["ips_score"] == to_published(d["ips_score_raw"]) >= 91
    assert d["mitre_technique"] == "T1110"
    assert "Security Incident Report" in d["reports"]["technical"] and d["reports"]["executive"]


def test_adapter_details_win_over_the_engine_chain(ips_rig):
    ips_rig.send("cyber", "cyber.brute_force", "network", **ATTACK, details=dict(DETAILS, ips_score=50, ips_level="medium"))
    assert ips_rig.last("security/incidents")["details"]["ips_score"] == 50


def test_unknown_device_and_junk_do_not_break_the_engine(ips_rig):
    ips_rig.send("cyber", "cyber.brute_force", "network", **dict(ATTACK, device_id="nope_9", dst_port="x"))
    assert ips_rig.last("security/incidents") is not None


def test_engine_works_without_the_ips_package():
    assert IpsEnricher.load("/nonexistent/ips_devices.json") is None


def test_to_published_matches_the_contract_examples():
    assert [to_published(s) for s in (29, 54, 67, 77, 81, 85, 86)] == [30, 55, 72, 87, 91, 93, 94]
    assert all(to_published(a) <= to_published(a + 1) for a in range(100))


def test_alerts_recorded_from_the_ips_cyber_service(ips_rig):
    """The 14 sample events replayed through services/ips_cyber (7 alerts) give ONE network incident with details."""
    jsonschema = pytest.importorskip("jsonschema")
    lines = (REPO / "services" / "engine" / "tests" / "data" / "ips_cyber_alerts.jsonl").read_text().splitlines()
    assert len(lines) == 7
    for line in lines:
        ips_rig.engine.on_message("security/alerts/cyber", line)
    sent = incidents(ips_rig)
    assert len({i["id"] for i in sent}) == 1
    inc = sent[-1]
    assert inc["zone"] == "network" and len(inc["events"]) == 7 and inc["level"] == "critical"
    jsonschema.validate(inc["details"], json.loads((REPO / "contract" / "incident_details.schema.json").read_text()))
    assert ips_rig.topic("home/") == []                      # a network attack switches on no light or siren
    assert {p["ip"] for _, p in ips_rig.topic("system/block")} == {"192.168.1.66", "203.0.113.45"}
