from conftest import FakeClock

from cyb.allowlist import Allowlist
from cyb.detectors import (
    MAX_REPORTED_PORTS,
    BruteForceDetector,
    PortScanDetector,
    RogueDeviceDetector,
)


def scanner(**kw):
    args = {"min_targets": 15, "window_s": 10, "settle_s": 2, "cooldown_s": 60}
    args.update(kw)
    return PortScanDetector(**args)


def probe(det, src="192.168.1.15", dst="192.168.1.10", ports=range(1, 21), t=0.0, step=0.01):
    for i, port in enumerate(ports):
        det.observe(src, dst, port, t + i * step)


def test_a_scan_is_reported_once_with_totals():
    det = scanner()
    probe(det, ports=range(1, 400))                  # ~400 packet alerts
    assert det.flush(1.0) == []                      # still settling
    (found,) = det.flush(3.0)
    assert found.type == "cyber.port_scan" and found.severity == "medium"
    d = found.data
    assert d["src_ip"] == "192.168.1.15" and d["dst_ip"] == "192.168.1.10"
    assert d["port_count"] == 399 and len(d["ports"]) == MAX_REPORTED_PORTS
    assert d["ports"][:3] == [1, 2, 3] and d["hosts_probed"] == 1
    assert det.flush(4.0) == []


def test_few_probes_are_not_a_scan_and_state_is_freed():
    det = scanner()
    probe(det, ports=range(1, 10))
    assert det.flush(3.0) == []
    assert det.flush(60.0) == [] and not det._scans


def test_slow_probing_never_reaches_the_threshold():
    det = scanner()
    for i in range(40):                              # one new port every 2 s, window is 10 s
        det.observe("192.168.1.15", "192.168.1.10", 1000 + i, i * 2.0)
        det.flush(i * 2.0)
    assert det.flush(500.0) == []


def test_cooldown_then_a_second_scan_is_reported_again():
    det = scanner()
    probe(det)
    assert len(det.flush(3.0)) == 1
    probe(det, t=10.0)
    assert det.flush(20.0) == []                     # inside the 60 s cooldown
    probe(det, t=100.0)
    assert len(det.flush(110.0)) == 1


def test_two_sources_are_independent_and_host_sweeps_count():
    det = scanner()
    probe(det, src="10.0.0.1")
    for i in range(20):                              # one port across 20 hosts
        det.observe("10.0.0.2", f"10.0.1.{i}", 22, i * 0.01)
    found = {d.data["src_ip"]: d for d in det.flush(5.0)}
    assert set(found) == {"10.0.0.1", "10.0.0.2"}
    assert found["10.0.0.2"].data["hosts_probed"] == 20


def test_state_is_bounded_under_a_spoofed_flood():
    det = scanner(max_sources=50)
    for i in range(5000):
        det.observe(f"10.{i // 250}.{i % 250}.1", "192.168.1.10", 80, 0.0)
    assert len(det._scans) <= 50
    det2 = scanner()
    for i in range(20000):                           # one source, endless distinct ports
        det2.observe("1.2.3.4", "192.168.1.10", (i % 60000) + 1, 0.0)
    assert len(det2._scans["1.2.3.4"].targets) <= 2048


def brute(**kw):
    args = {"min_attempts": 5, "window_s": 60, "settle_s": 2, "cooldown_s": 120}
    args.update(kw)
    return BruteForceDetector(**args)


def test_brute_force_event_content():
    det = brute()
    for i in range(30):
        det.observe("192.168.1.15", "192.168.1.20", 8080, "http", 10.0 + i * 0.01)
    (found,) = det.flush(13.0)
    assert found.type == "cyber.brute_force" and found.severity == "high"
    d = found.data
    assert d["src_ip"] == "192.168.1.15" and d["target"] == "192.168.1.20:8080"
    assert d["protocol"] == "http" and d["attempts"] == 30
    assert det.flush(14.0) == []


def test_a_mistyped_pin_is_not_brute_force():
    det = brute()
    for i in range(3):
        det.observe("192.168.1.15", "192.168.1.20", 8080, "http", float(i))
    assert det.flush(10.0) == []
    for i in range(10):                              # spread over minutes: never 5 in 60 s
        det.observe("192.168.1.15", "192.168.1.20", 8080, "http", 100.0 + i * 30)
        assert det.flush(100.0 + i * 30) == []


def test_brute_force_keeps_services_and_sources_apart():
    det = brute()
    for i in range(6):
        det.observe("10.0.0.1", "10.0.0.9", 8080, "http", i * 0.1)
        det.observe("10.0.0.1", "10.0.0.9", 22, "ssh", i * 0.1)
        det.observe("10.0.0.2", "10.0.0.9", 8080, "http", i * 0.1)
    found = det.flush(5.0)
    assert {(d.data["src_ip"], d.data["protocol"]) for d in found} == {
        ("10.0.0.1", "http"), ("10.0.0.1", "ssh"), ("10.0.0.2", "http")}


def rogue(tmp_path, devices='  - mac: "aa:bb:cc:00:00:01"\n'):
    f = tmp_path / "k.yaml"
    f.write_text("devices:\n" + devices if devices else "", encoding="utf-8")
    return RogueDeviceDetector(Allowlist(f, clock=FakeClock()), cooldown_s=300)


def test_unknown_mac_is_rogue_and_known_mac_is_not(tmp_path):
    det = rogue(tmp_path)
    assert det.observe("AA:BB:CC:00:00:01", "0.0.0.0", "dhcp", None, 0.0) is None
    found = det.observe("de:ad:be:ef:00:01", "0.0.0.0", "dhcp", "evil\nhost", 0.0)
    assert found.type == "cyber.rogue_device"
    assert found.data == {"mac": "de:ad:be:ef:00:01", "ip": "0.0.0.0", "seen_via": "dhcp",
                          "hostname": "evil_host"}


def test_rogue_with_a_lease_carries_src_ip_so_it_can_be_blocked(tmp_path):
    found = rogue(tmp_path).observe("de:ad:be:ef:00:02", "192.168.1.77", "arp", None, 0.0)
    assert found.data["ip"] == "192.168.1.77" and found.data["src_ip"] == "192.168.1.77"


def test_rogue_is_reported_once_per_cooldown(tmp_path):
    det = rogue(tmp_path)
    assert det.observe("de:ad:be:ef:00:03", "0.0.0.0", "dhcp", None, 0.0)
    assert det.observe("de:ad:be:ef:00:03", "0.0.0.0", "dhcp", None, 100.0) is None
    assert det.observe("de:ad:be:ef:00:03", "0.0.0.0", "dhcp", None, 400.0)


def test_empty_allowlist_switches_detection_off(tmp_path):
    det = rogue(tmp_path, devices="")
    assert det.observe("de:ad:be:ef:00:04", "0.0.0.0", "dhcp", None, 0.0) is None


def test_garbage_macs_are_ignored(tmp_path):
    det = rogue(tmp_path)
    for bad in (None, "", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "xx", 5, ["a"]):
        assert det.observe(bad, "0.0.0.0", "dhcp", None, 0.0) is None
