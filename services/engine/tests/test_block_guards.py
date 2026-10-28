"""The engine must never be talked into blocking a device it is defending.

A packet's source address is chosen by the sender, so the block path is an actuator driven by
attacker-controlled data. These tests pin the guards: our devices, self-addressed flows and
special-purpose ranges are refused, and only the incident's own zone may name an attacker.
"""
import ipaddress
import json

import pytest
from conftest import REPO, Rig

from eng.core import Engine
from eng.policy import attacker_ip
from eng.service import device_ips

CAMERA = "192.168.1.50"          # cam_001, from config/ips_devices.json
OTHER = "192.168.1.15"           # not a device in that file
ATTACK = dict(src_ip="203.0.113.45", dst_ip=CAMERA, dst_port=22, protocol="TCP", direction="inbound",
              device_id="cam_001", confidence=0.98, mitre_technique="T1110", failed_attempts=300,
              connection_attempts=300, duration=240, target="ssh", attempts=300, window_s=240)


def protected():
    return device_ips(REPO / "config" / "ips_devices.json")


@pytest.fixture
def rig():
    """A Rig whose engine protects the real device IPs, like `eng.service.build()` does."""
    out = []

    def publish(topic, payload, retain):
        out.append((topic, payload, retain))

    from eng.notify import Notifier
    from eng.policy import load_policy

    engine = Engine(load_policy(REPO / "config" / "risk_scores.yaml"), publish,
                    notifier=Notifier(background=False), clock=lambda: 1000.0,
                    protected_ips=protected())
    rig = Rig()
    rig.engine, rig.out = engine, out
    return rig


def blocks(rig):
    return [p["ip"] for t, p, _ in rig.out if t == "system/block"]


def burst(rig, src, direction="inbound", dst=CAMERA):
    """The three cyber events the project's own test uses to reach High risk."""
    for kind in ("cyber.dos", "cyber.brute_force", "cyber.port_scan"):
        data = dict(ATTACK, src_ip=src, dst_ip=dst)
        if direction is None:
            data.pop("direction")
        else:
            data["direction"] = direction
        rig.send("cyber", kind, "network", **data)


# ------------------------------------------------------------------ attacker_ip() itself
@pytest.mark.parametrize("value", [
    "0.0.0.0", "0.1.2.3",            # 0.0.0.0/8 - only 0.0.0.0 is is_unspecified
    "100.64.0.1",                    # carrier-grade NAT
    "198.18.0.1", "240.0.0.1",       # benchmarking / class E
    "127.0.0.1", "169.254.1.1", "224.0.0.1",
    "fe80::1%eth0", "1.2.3.4/24", "not-an-ip", "", None,
])
def test_special_and_malformed_sources_are_never_blockable(value):
    assert attacker_ip(value) is None


def test_our_devices_are_never_blockable_even_in_ipv4_mapped_form():
    for value in (CAMERA, "::ffff:" + CAMERA):
        assert attacker_ip(value, (), protected()) is None
    assert attacker_ip(OTHER, (), protected()) == OTHER


def test_an_operator_never_block_network_still_wins():
    home = (ipaddress.ip_network("192.168.1.0/24"),)
    assert attacker_ip(OTHER, home) is None
    assert attacker_ip("203.0.113.45", home) == "203.0.113.45"


# ------------------------------------------------------------------ the block path
def test_a_normal_external_attacker_is_still_blocked(rig):
    burst(rig, "203.0.113.45")
    assert blocks(rig) == ["203.0.113.45"]


def test_spoofing_a_devices_own_address_never_blocks_that_device(rig):
    """The whole point: the IPS must not be turned against the camera it defends."""
    burst(rig, CAMERA)
    assert blocks(rig) == []


def test_spoofed_address_in_ipv4_mapped_form_is_refused(rig):
    burst(rig, "::ffff:" + CAMERA)
    assert blocks(rig) == []


def test_a_flow_addressed_to_itself_names_no_source(rig):
    burst(rig, CAMERA, dst=CAMERA)
    assert blocks(rig) == []


def test_the_own_device_ip_is_not_blocked_by_another_devices_alert(rig):
    """dst is the thermostat, src is spoofed as the lock: still a protected address."""
    burst(rig, "192.168.1.60", dst="192.168.1.70")
    assert blocks(rig) == []


@pytest.mark.parametrize("direction", ["outbound", "Outbound", "OUTBOUND", "outbound "])
def test_outbound_flows_never_block_their_source(rig, direction):
    """`direction` is data, so the guard must not depend on the exact spelling."""
    burst(rig, OTHER, direction=direction)
    assert blocks(rig) == []


def test_missing_direction_keeps_the_cautious_inbound_reading(rig):
    burst(rig, OTHER, direction=None)
    assert blocks(rig) == [OTHER]


def test_a_physical_incident_never_names_an_attacker(rig):
    """A water leak's src_ip is the sensor, not a source to drop."""
    rig.send("water", "water.leak", "kitchen", src_ip="192.168.1.222")
    burst(rig, "203.0.113.45")
    assert "192.168.1.222" not in blocks(rig)


def test_a_physical_incident_cannot_leak_another_zones_ip_into_a_block(rig):
    rig.send("water", "water.leak", "kitchen", src_ip="192.168.1.222")
    for kind in ("cyber.dos", "cyber.brute_force", "cyber.port_scan"):
        rig.send("cyber", kind, "network", **ATTACK)
    assert blocks(rig) == ["203.0.113.45"]


def test_device_ips_come_from_the_ips_profiles():
    found = protected()
    assert CAMERA in found and len(found) == 6
    assert all(ip.startswith("192.168.1.") for ip in found)


def test_a_missing_device_config_protects_nothing_but_does_not_crash(tmp_path):
    assert device_ips(tmp_path / "nope.json") == set()


def test_the_enricher_itself_also_protects_its_device_ips(tmp_path):
    """Setting `engine.ips` after construction (as the integration fixture does) still protects."""
    from eng.ips import IpsEnricher
    from eng.notify import Notifier
    from eng.policy import load_policy

    enricher = IpsEnricher.__new__(IpsEnricher)
    enricher.m, enricher.profiles = None, {"cam_001": {"ip": CAMERA}}
    engine = Engine(load_policy(REPO / "config" / "risk_scores.yaml"),
                    lambda *a: None, notifier=Notifier(background=False), clock=lambda: 1000.0)
    assert engine.protected_ips == set()
    engine.ips = enricher
    assert engine.protected_ips == {CAMERA}
    engine.ips = None
    assert engine.protected_ips == {CAMERA}          # never un-protected


def test_the_json_device_file_is_the_source_of_truth_for_ips():
    devices = json.loads((REPO / "config" / "ips_devices.json").read_text())["devices"]
    assert protected() == {d["ip"] for d in devices}