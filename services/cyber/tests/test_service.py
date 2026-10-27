import json
import re
import threading
import time
from dataclasses import replace

from conftest import REPO, FakeSink, alert, dhcp, feed_scan, write_lines

from cyb.config import SID_HTTP_LOGIN, SID_PORT_SCAN, SID_SSH_CONNECT, Settings
from cyb.service import CyberService

ENVELOPE = {"id", "ts", "source", "type", "zone", "severity_hint", "data"}


def registry_required():
    """{event type: required data keys} parsed from the contract table, so drift fails a test."""
    out = {}
    for row in (REPO / "docs/CONTRACT.md").read_text(encoding="utf-8").splitlines():
        m = re.match(r"\|\s*`(cyber\.[a-z_]+)`\s*\|\s*cyber\s*\|\s*([^|]*)\|", row)
        if m:
            out[m.group(1)] = re.findall(r"`([a-z_]+)`", m.group(2))
    return out


def test_port_scan_end_to_end_is_one_network_event(service, sink, clock):
    feed_scan(service, clock)
    scans = [e for e in sink.events if e.type == "cyber.port_scan"]
    assert len(scans) == 1
    ev = scans[0]
    assert ev.zone == "network" and ev.source == "cyber" and ev.severity_hint == "medium"
    assert ev.data["src_ip"] == "192.168.1.15" and ev.data["dst_ip"] == "192.168.1.10"
    assert ev.data["ports"][:3] == [1, 2, 3]


def test_a_confirmed_scan_is_blocked_and_confirmed_in_the_same_flow(service, sink, clock):
    feed_scan(service, clock)
    assert sink.types() == ["cyber.port_scan", "cyber.ip_blocked"]
    blocked = sink.events[1].data
    assert blocked["ip"] == "192.168.1.15" and blocked["blocked_by"] == "cyber"
    assert blocked["reason"] == "cyber.port_scan" and blocked["window_s"] == 600
    assert "192.168.1.15" in service.blocks.blocks


def test_the_engines_block_command_for_an_already_blocked_ip_adds_no_noise(service, sink, clock):
    feed_scan(service, clock)
    before = len(sink.events)
    cmd = {"id": "9f" * 16, "ts": "2026-10-11T10:00:00Z", "ip": "192.168.1.15",
           "reason": "cyber.port_scan", "window_seconds": 3600}
    assert service.handle_block(json.dumps(cmd))
    assert len(sink.events) == before
    assert service.blocks.blocks["192.168.1.15"].expires_at > clock() + 3000   # extended


def test_the_engines_block_command_for_a_fresh_ip_is_executed(service, sink):
    cmd = {"id": "9f" * 16, "ip": "203.0.113.9", "reason": "cyber.rogue_device"}
    assert service.handle_block(json.dumps(cmd))
    assert sink.types() == ["cyber.ip_blocked"] and sink.events[0].data["blocked_by"] == "engine"


def test_http_brute_force_end_to_end(service, sink, clock):
    for _ in range(25):
        service.process_record(alert(SID_HTTP_LOGIN, dst="192.168.1.20", port=8080), clock())
        clock.advance(0.05)
    clock.advance(3)
    service.tick(clock())
    ev = sink.events[0]
    assert ev.type == "cyber.brute_force" and ev.severity_hint == "high"
    assert ev.data["target"] == "192.168.1.20:8080" and ev.data["attempts"] == 25
    assert sink.types()[1] == "cyber.ip_blocked"


def test_ssh_attempts_are_counted_as_brute_force(service, sink, clock):
    for _ in range(8):
        service.process_record(alert(SID_SSH_CONNECT, dst="192.168.1.20", port=22), clock())
    clock.advance(3)
    service.tick(clock())
    data = sink.events[0].data
    assert data["protocol"] == "ssh" and data["target"].endswith(":22")


def test_unknown_dhcp_client_is_a_rogue_device_and_is_not_auto_blocked(service, sink, clock):
    service.process_record(dhcp("de:ad:be:ef:00:01", hostname="kali"), clock())
    service.process_record(dhcp("aa:bb:cc:00:00:01"), clock())          # known: the smart lock
    (ev,) = sink.events
    assert ev.type == "cyber.rogue_device" and ev.data["mac"] == "de:ad:be:ef:00:01"
    assert ev.data["ip"] == "0.0.0.0" and "src_ip" not in ev.data and ev.data["hostname"] == "kali"
    assert service.blocks.blocks == {}


def test_rogue_device_with_a_lease_exposes_src_ip_for_the_engine(service, sink, clock):
    service.process_record(dhcp("de:ad:be:ef:00:02", assigned_ip="192.168.1.77"), clock())
    assert sink.events[0].data["src_ip"] == "192.168.1.77"


def test_arp_is_only_read_when_enabled(settings, sink, clock):
    table = [("192.168.1.99", "de:ad:be:ef:00:09"), ("192.168.1.5", "aa:bb:cc:00:00:01")]
    off = CyberService(settings, sink, clock=clock, arp_reader=lambda: table)
    off.tick(clock())
    assert sink.events == []
    on = CyberService(replace(settings, rogue_arp=True), sink, clock=clock,
                      arp_reader=lambda: table)
    on.restore()
    on.tick(clock())
    (ev,) = sink.events
    assert ev.data["mac"] == "de:ad:be:ef:00:09" and ev.data["seen_via"] == "arp"


def test_never_block_networks_are_reported_but_not_blocked(settings, sink, clock):
    never = Settings.from_env({"CYBER_NEVER_BLOCK": "192.168.1.0/24"}).never_block
    svc = CyberService(replace(settings, never_block=never), sink, clock=clock)
    svc.restore()
    feed_scan(svc, clock)
    assert sink.types() == ["cyber.port_scan"] and svc.blocks.blocks == {}


def test_autoblock_can_be_switched_off(settings, sink, clock):
    svc = CyberService(replace(settings, autoblock=()), sink, clock=clock)
    svc.restore()
    feed_scan(svc, clock)
    assert sink.types() == ["cyber.port_scan"]


def test_bad_records_are_dropped_without_raising(service, sink, clock):
    for rec in [{}, {"event_type": "alert"}, {"event_type": "alert", "alert": "x"},
                {"event_type": "alert", "alert": {"signature_id": SID_PORT_SCAN}},
                alert(SID_PORT_SCAN, src="not-an-ip"), alert(SID_PORT_SCAN, port=0),
                alert(SID_PORT_SCAN, dst="1.2.3.4/8"), alert(9999999),
                {"event_type": "dhcp"}, {"event_type": "dhcp", "dhcp": []},
                dhcp("garbage"), {"event_type": "flow"}, {"event_type": 5}]:
        service.process_record(rec, clock())
    service.tick(clock())
    assert sink.events == []


def test_the_event_rate_is_capped(settings, sink, clock):
    svc = CyberService(replace(settings, max_events_per_min=5, autoblock=()), sink, clock=clock)
    svc.restore()
    for i in range(20):
        svc.process_record(dhcp(f"de:ad:be:ef:01:{i:02x}"), clock())
    assert len(sink.events) == 5 and svc.stats["dropped"] == 15
    clock.advance(61)
    svc.process_record(dhcp("de:ad:be:ef:02:00"), clock())
    assert len(sink.events) == 6


def test_a_failing_sink_does_not_stop_the_service(settings, clock):
    class Broken(FakeSink):
        def publish(self, event):
            raise RuntimeError("broker down")

    svc = CyberService(settings, Broken(), clock=clock)
    svc.restore()
    feed_scan(svc, clock)                      # must not raise
    svc.process_record(dhcp("de:ad:be:ef:00:03"), clock())


def test_records_flow_from_a_real_eve_file_through_the_threads(settings, sink):
    svc = CyberService(replace(settings, brute_settle_s=0), sink)     # real clock, real threads
    svc.restore()
    write_lines(settings.eve_path, mode="w")
    svc.tailer.poll()
    stop = threading.Event()
    svc.start(stop)
    try:
        write_lines(settings.eve_path, *[alert(SID_HTTP_LOGIN, dst="192.168.1.20", port=8080)
                                         for _ in range(8)])
        deadline = time.time() + 5
        while time.time() < deadline and "cyber.brute_force" not in sink.types():
            time.sleep(0.05)
    finally:
        stop.set()
    assert "cyber.brute_force" in sink.types()


def test_every_event_matches_the_envelope_and_the_contract_registry(service, sink, clock):
    required = registry_required()
    assert set(required) >= {"cyber.port_scan", "cyber.ip_blocked", "cyber.ip_unblocked"}
    feed_scan(service, clock)
    for _ in range(10):
        service.process_record(alert(SID_HTTP_LOGIN, src="192.168.1.16", port=8080), clock())
    service.process_record(dhcp("de:ad:be:ef:00:01", assigned_ip="192.168.1.77"), clock())
    service.handle_block(json.dumps({"id": "cmd-12345", "ip": "203.0.113.9"}))
    clock.advance(10**5)
    service.tick(clock())
    assert set(sink.types()) == {"cyber.port_scan", "cyber.brute_force", "cyber.rogue_device",
                                 "cyber.ip_blocked", "cyber.ip_unblocked"}
    for ev in sink.events:
        doc = json.loads(ev.model_dump_json())
        assert set(doc) == ENVELOPE and doc["zone"] == "network" and doc["data"]
        assert re.match(r"^[a-z0-9_]+\.[a-z0-9_]+$", doc["type"])
        for key in required[ev.type]:
            assert key in doc["data"], f"{ev.type} is missing required data.{key}"
        # the engine reads data.src_ip to pick the IP to block: only attackers may carry it
        names_attacker = ev.type in ("cyber.port_scan", "cyber.brute_force") or (
            ev.type == "cyber.rogue_device" and doc["data"]["ip"] != "0.0.0.0")
        assert ("src_ip" in doc["data"]) == names_attacker
    try:
        import jsonschema
    except ImportError:
        return
    schema = json.loads((REPO / "contract/event.schema.json").read_text(encoding="utf-8"))
    for ev in sink.events:
        jsonschema.validate(json.loads(ev.model_dump_json()), schema)


def test_the_rules_file_defines_exactly_the_sids_the_service_reads():
    rules = (REPO / "services/cyber/suricata/smartsecure.rules").read_text(encoding="utf-8")
    assert {int(m) for m in re.findall(r"sid:(\d+);", rules)} == {
        SID_PORT_SCAN, SID_HTTP_LOGIN, SID_SSH_CONNECT}
    for line in rules.splitlines():
        if line.startswith("alert"):
            assert line.count("(") == 1 and line.rstrip().endswith(";)")
