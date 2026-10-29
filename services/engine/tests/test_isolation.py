"""Device isolation is opt-in: off by default, shadow only logs, on sends `direction: both` at Critical."""
import pytest
from conftest import REPO, Rig
from test_block_guards import ATTACK, CAMERA, protected

from eng.core import Engine
from eng.notify import Notifier
from eng.policy import load_policy

TYPES = ("cyber.dos", "cyber.brute_force", "cyber.port_scan", "cyber.unexpected_traffic")


def make(mode):
    rig = Rig()
    rig.engine = Engine(load_policy(REPO / "config" / "risk_scores.yaml"),
                        lambda tp, p, r: rig.out.append((tp, p, r)),
                        notifier=Notifier(background=False), clock=lambda: rig.t,
                        protected_ips=protected(), isolation=mode)
    return rig


def flood(rig, src=CAMERA, direction="outbound", types=TYPES):
    for _ in range(4 if len(types) == 4 else 1):
        for kind in types:
            rig.t += 1
            rig.send("cyber", kind, "network", **dict(ATTACK, src_ip=src, dst_ip="203.0.113.99", direction=direction))


def commands(rig):
    return [p for t, p, _ in rig.out if t == "system/block"]


def test_default_is_off_and_sends_nothing():
    rig = make("off")
    flood(rig)
    assert rig.risk("network")["level"] == "critical"
    assert commands(rig) == []


def test_shadow_only_says_it_would():
    rig = make("shadow")
    flood(rig)
    assert commands(rig) == []
    texts = [p["summary"] for t, p, _ in rig.out if t == "security/incidents"]
    assert any("would isolate -> " + CAMERA in x for x in texts)


def test_on_isolates_the_compromised_device_once_with_direction_both():
    rig = make("on")
    flood(rig)
    cmds = commands(rig)
    assert [c["ip"] for c in cmds] == [CAMERA]
    assert cmds[0]["direction"] == "both" and cmds[0]["device_id"] == "cam_001"
    assert cmds[0]["window_seconds"] > 0


def test_not_below_critical():
    rig = make("on")
    flood(rig, types=TYPES[:2])                         # two events: High, not Critical
    assert rig.risk("network")["level"] != "critical"
    assert commands(rig) == []


def test_an_unknown_source_is_never_isolated():
    """Outbound from an address that is not one of our devices cannot name a victim (spoofing)."""
    rig = make("on")
    flood(rig, src="192.168.1.15")
    assert all(c.get("direction") != "both" for c in commands(rig))


def test_inbound_attack_still_blocks_the_attacker_not_the_device():
    rig = make("on")
    flood(rig, src="203.0.113.45", direction="inbound")
    assert all(c.get("direction") != "both" for c in commands(rig))
    assert "203.0.113.45" in [c["ip"] for c in commands(rig)]


def test_bad_mode_is_refused():
    with pytest.raises(ValueError):
        make("yes")
