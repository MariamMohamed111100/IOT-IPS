"""The decision logic of scripts/ips/ips_e2e.py, run against a fake API (no Docker needed).

The real lab run needs Docker (docker-compose.lab.yml); here we prove the checker passes on a good
run and FAILS on each kind of bad run, so a green lab run means something.
"""
import copy
import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ips_e2e", ROOT / "scripts" / "ips" / "ips_e2e.py")
e2e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e2e)

DETAILS = {"mitre_technique": "T1046", "ips_score": 80, "ips_level": "high", "ips_score_raw": 70,
           "reports": {"technical": "tech", "executive": "exec"}}


def alert(i, kind, src=e2e.ATTACKER, details=DETAILS, zone="network"):
    return {"id": "e%d" % i, "type": kind, "zone": zone, "source": "cyber",
            "data": {"src_ip": src, "details": copy.deepcopy(details) if details is not None else None}}


class FakeApi:
    def __init__(self, events, incidents, timeline=None):
        self.events, self.incidents = events, incidents
        self.timeline = timeline if timeline is not None else events

    def api(self, method, path, body=None, params=None):
        if path == "/events":
            return 200, self.events
        if path == "/incidents":
            return 200, self.incidents
        if path.endswith("/events"):
            return 200, self.timeline
        return 404, None



class Ws:
    def __init__(self, incidents, ok=True):
        self.incidents, self.ready, self.error = incidents, type("R", (), {"is_set": lambda s: True})(), None if ok else "down"


GOOD = [alert(1, "cyber.port_scan"), alert(2, "cyber.brute_force"), alert(3, "cyber.dos")]
INC = {"id": "inc1", "zone": "network", "level": "critical", "score": 100, "events": ["e1", "e2", "e3"]}


def run(events, incidents, ws_incidents, timeline=None, ws_ok=True):
    api = FakeApi([], incidents, timeline)

    def attack(name):                       # the alerts only exist after the attack
        api.events[:] = events
    out = []
    fails = e2e.play(api, Ws(ws_incidents, ws_ok), attack, wait_s=0.01, out=out.append, sleep=lambda s: None)
    return fails


def test_a_good_run_passes():
    assert run(GOOD, [INC], [INC]) == []


def test_missing_alert_type_fails():
    assert run(GOOD[:2], [INC], [INC])


def test_alert_without_reports_fails():
    bad = [alert(1, "cyber.port_scan", details={**DETAILS, "reports": {"technical": "t"}})] + GOOD[1:]
    assert any("both reports" in f for f in run(bad, [INC], [INC]))


def test_alert_without_details_fails():
    assert run([alert(1, "cyber.port_scan", details=None)] + GOOD[1:], [INC], [INC])


def test_false_alarm_on_the_normal_client_fails():
    extra = GOOD + [alert(9, "cyber.port_scan", src=e2e.CLIENT)]
    assert any("normal client" in f for f in run(extra, [INC], [INC]))


def test_no_incident_fails():
    assert run(GOOD, [], [INC])


def test_low_incident_fails():
    assert any("high or critical" in f for f in run(GOOD, [{**INC, "level": "medium"}], [INC]))


def test_incident_in_a_room_zone_fails():
    assert run(GOOD, [{**INC, "zone": "garage"}], [INC])


def test_websocket_silence_fails():
    assert any("WebSocket pushed" in f for f in run(GOOD, [INC], []))


def test_websocket_down_fails():
    assert any("connected" in f for f in run(GOOD, [INC], [INC], ws_ok=False))


def test_timeline_missing_events_fails():
    assert any("timeline" in f for f in run(GOOD, [INC], [INC], timeline=GOOD[:1]))


def test_attack_refuses_targets_outside_the_lab():
    import subprocess
    r = subprocess.run(["bash", str(ROOT / "lab" / "attacker" / "attack.sh"), "scan"],
                       env={"TARGET": "192.168.1.50", "PATH": "/usr/bin:/bin"}, capture_output=True, text=True)
    assert r.returncode == 2 and "refusing" in r.stdout


def test_lab_compose_is_internal_and_isolated():
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load((ROOT / "docker-compose.lab.yml").read_text())
    assert doc["networks"]["lab"]["internal"] is True
    for name in ("lab_client", "lab_attacker"):
        assert list(doc["services"][name]["networks"]) == ["lab"]       # no route to anything else
