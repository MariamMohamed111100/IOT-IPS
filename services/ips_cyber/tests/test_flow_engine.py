"""Tests for flow_engine.py on small generated PCAPs, plus the hand-off to the IPS detector.
Run from services/ips_cyber:  python -m pytest tests
"""
import json
import os
import tempfile
import unittest

import pcap_helpers as H
from iot_ips.detector import detect
from iot_ips.paths import DEFAULT_DEVICES_PATH
from ips_cyber.flow_engine import FlowEngine, FlowEngineError

with open(DEFAULT_DEVICES_PATH, encoding="utf-8") as f:       # the devices of the whole project
    DEVICES = json.load(f)["devices"]
PROFILES = {d["device_id"]: d for d in DEVICES}


class PcapCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.engine = FlowEngine(DEVICES)

    def events(self, packets, name="t.pcap", engine=None):
        path = H.write(os.path.join(self.tmp.name, name), packets)
        return (engine or self.engine).events_from_pcap(path)

    def only(self, events, **match):
        got = [e for e in events if all(e.get(k) == v for k, v in match.items())]
        self.assertTrue(got, "no event matching %s in %s" % (match, [(e["direction"], e["device_id"], e["src_ip"]) for e in events]))
        return got[-1]            # the latest snapshot has the biggest window


class FlowAssemblyTests(PcapCase):
    def test_one_tcp_connection_is_one_flow(self):
        path = H.write(os.path.join(self.tmp.name, "a.pcap"), H.long_session(100.0, H.CLIENT, H.CAMERA, 40000, 554))
        flows = self.engine.flows_from_pcap(path)
        self.assertEqual(len(flows), 1)
        f = flows[0]
        self.assertEqual((f.src_ip, f.dst_ip, f.dst_port, f.proto), (H.CLIENT, H.CAMERA, 554, "TCP"))
        self.assertEqual((f.fin_fwd, f.fin_rev, f.syn), (1, 1, 1))
        self.assertGreater(f.duration, 4.0)

    def test_initiator_is_the_syn_sender_even_if_reply_comes_first_in_capture(self):
        pk = H.long_session(100.0, H.CLIENT, H.CAMERA, 40000, 554)
        path = H.write(os.path.join(self.tmp.name, "b.pcap"), pk[1:])   # capture starts at the SYN-ACK
        f = self.engine.flows_from_pcap(path)[0]
        self.assertEqual((f.src_ip, f.dst_ip), (H.CLIENT, H.CAMERA))

    def test_same_ports_reused_after_close_make_two_flows(self):
        pk = H.refused(100.0, H.ATTACKER, H.CAMERA, 5555, 22) + H.refused(101.0, H.ATTACKER, H.CAMERA, 5555, 22)
        path = H.write(os.path.join(self.tmp.name, "c.pcap"), pk)
        self.assertEqual(len(self.engine.flows_from_pcap(path)), 2)

    def test_udp_and_icmp_flows(self):
        pk = H.udp_exchange(100.0, H.CAMERA, H.NTP, 50000, 123) + H.icmp_ping(100.5, H.ATTACKER, H.CAMERA)
        path = H.write(os.path.join(self.tmp.name, "d.pcap"), pk)
        protos = sorted(f.proto for f in self.engine.flows_from_pcap(path))
        self.assertEqual(protos, ["ICMP", "UDP"])

    def test_failed_login_heuristic(self):
        path = H.write(os.path.join(self.tmp.name, "e.pcap"),
                       H.failed_login(100.0, H.ATTACKER, H.CAMERA, 1111, 22)
                       + H.refused(101.0, H.ATTACKER, H.CAMERA, 1112, 22)
                       + H.syn_only(102.0, H.ATTACKER, H.CAMERA, 1113, 22)
                       + H.long_session(103.0, H.CLIENT, H.CAMERA, 2222, 554))
        failed = {(f.src_ip, f.src_port): self.engine.is_failed(f) for f in self.engine.flows_from_pcap(path)}
        self.assertTrue(failed[(H.ATTACKER, 1111)])      # short, few packets
        self.assertTrue(failed[(H.ATTACKER, 1112)])      # reset
        self.assertTrue(failed[(H.ATTACKER, 1113)])      # never answered
        self.assertFalse(failed[(H.CLIENT, 2222)])       # long normal session


class ScenarioTests(PcapCase):
    def test_ssh_brute_force(self):
        pk = []
        for i in range(70):
            pk += H.failed_login(100.0 + i * 0.3, H.ATTACKER, H.CAMERA, 30000 + i, 22)
        ev = self.only(self.events(pk), direction="inbound", device_id="CAM-001", src_ip=H.ATTACKER)
        self.assertGreaterEqual(ev["failed_attempts"], 50)
        self.assertEqual((ev["dst_port"], ev["SSH"], ev["protocol"]), (22, 1, "TCP"))
        d = detect(ev, PROFILES["CAM-001"])
        self.assertEqual((d["label"], d["attack_type"]), ("ATTACK", "Brute Force"))

    def test_many_normal_camera_viewing_sessions_are_not_brute_force(self):
        # review finding: 150 connections to port 554 with 0 failed logins
        pk = []
        for i in range(150):
            pk += H.long_session(100.0 + i * 0.1, H.CLIENT, H.CAMERA, 20000 + i, 554, seconds=3.0)
        ev = self.only(self.events(pk), direction="inbound", device_id="CAM-001", src_ip=H.CLIENT)
        self.assertEqual(ev["failed_attempts"], 0)
        self.assertGreaterEqual(ev["connection_attempts"], 100)
        self.assertEqual(detect(ev, PROFILES["CAM-001"])["label"], "BENIGN")

    def test_port_scan_vertical(self):
        pk = []
        for i, port in enumerate(range(1000, 1040)):
            pk += H.refused(100.0 + i * 0.05, H.ATTACKER, H.BULB, 40000 + i, port)
        ev = self.only(self.events(pk), direction="inbound", device_id="BULB-001")
        self.assertEqual(ev["unique_dst_ports"], 40)
        self.assertEqual(detect(ev, PROFILES["BULB-001"])["attack_type"], "Port Scan")

    def test_port_scan_horizontal_across_devices(self):
        pk = []
        for i, dev in enumerate(DEVICES):                         # one port, six devices
            pk += H.refused(100.0 + i * 0.1, H.ATTACKER, dev["ip"], 41000 + i, 80)
        extra = ["192.168.1.%d" % n for n in range(200, 210)]     # plus unknown hosts
        for i, ip in enumerate(extra):
            pk += H.refused(101.0 + i * 0.1, H.ATTACKER, ip, 42000 + i, 80)
        ev = self.only(self.events(pk), direction="inbound", device_id="CAM-001", src_ip=H.ATTACKER)
        self.assertGreaterEqual(ev["unique_dst_ips"], 10)
        self.assertEqual(detect(ev, PROFILES["CAM-001"])["attack_type"], "Port Scan")

    def test_syn_flood_dos(self):
        pk = []
        for i in range(1500):
            pk += H.syn_only(100.0 + i * 0.0006, H.ATTACKER, H.CAMERA, 10000 + i, 554)
        ev = self.only(self.events(pk), direction="inbound", device_id="CAM-001")
        self.assertEqual(ev["connection_attempts"], 1500)
        self.assertEqual(ev["syn_count"], 1500)
        self.assertGreaterEqual(ev["Rate"], 1000)
        self.assertEqual(detect(ev, PROFILES["CAM-001"])["attack_type"], "DoS")

    def test_unexpected_inbound_port(self):
        pk = H.long_session(100.0, "192.168.1.77", "192.168.1.51", 3333, 4444)
        ev = self.only(self.events(pk), direction="inbound", device_id="THERMO-001")
        d = detect(ev, PROFILES["THERMO-001"])
        self.assertEqual((d["attack_type"], d["mitre_technique"]), ("Unexpected Protocol/Port", "T1571"))


class DirectionTests(PcapCase):
    def test_outbound_camera_traffic_has_direction_outbound_and_no_alarm(self):
        # review finding: normal outbound traffic (8883, 123) was flagged once the profile was passed
        pk = (H.long_session(100.0, H.CAMERA, H.CLOUD, 50001, 8883, seconds=8.0)
              + H.udp_exchange(105.0, H.CAMERA, H.NTP, 50002, 123))
        events = self.events(pk)
        out = [e for e in events if e["direction"] == "outbound"]
        self.assertTrue(out)
        self.assertFalse([e for e in events if e["direction"] == "inbound"])
        for e in out:
            self.assertEqual((e["device_id"], e["src_ip"]), ("CAM-001", H.CAMERA))
            self.assertEqual(detect(e, PROFILES["CAM-001"])["label"], "BENIGN", e["dst_port"])

    def test_device_to_device_gives_both_directions(self):
        pk = H.long_session(100.0, H.CAMERA, "192.168.1.51", 50003, 443)
        dirs = sorted((e["direction"], e["device_id"]) for e in self.events(pk))
        self.assertEqual(dirs, [("inbound", "THERMO-001"), ("outbound", "CAM-001")])

    def test_traffic_not_touching_any_device_is_ignored(self):
        pk = H.long_session(100.0, "10.0.0.1", "10.0.0.2", 1234, 80)
        engine = FlowEngine(DEVICES)
        self.assertEqual(self.events(pk, engine=engine), [])
        self.assertEqual(engine.ignored_flows, 1)


class WindowTests(PcapCase):
    def test_two_bursts_far_apart_do_not_add_up(self):
        pk = []
        for i in range(30):
            pk += H.refused(100.0 + i * 0.1, H.ATTACKER, H.BULB, 40000 + i, 2000 + i)
        for i in range(30):
            pk += H.refused(400.0 + i * 0.1, H.ATTACKER, H.BULB, 41000 + i, 3000 + i)
        events = [e for e in self.events(pk) if e["device_id"] == "BULB-001"]
        first = [e for e in events if e["timestamp"] < "1970-01-01T00:03:00"]    # burst at t=100 s
        second = [e for e in events if e["timestamp"] >= "1970-01-01T00:03:00"]  # burst at t=400 s
        self.assertTrue(first and second)
        self.assertEqual(max(e["unique_dst_ports"] for e in first), 30)
        self.assertEqual(max(e["unique_dst_ports"] for e in second), 30)   # NOT 60: the old burst left the window
        self.assertFalse([e for e in events if "1970-01-01T00:02:00" < e["timestamp"] < "1970-01-01T00:06:40"])  # quiet ticks stay silent

    def test_continuing_attack_updates_with_bigger_counts(self):
        pk = []
        for i in range(60):                                   # 60 s of one probe per second
            pk += H.refused(100.0 + i, H.ATTACKER, H.BULB, 40000 + i, 2000 + i)
        events = [e for e in self.events(pk) if e["device_id"] == "BULB-001"]
        counts = [e["unique_dst_ports"] for e in events]
        self.assertGreater(len(events), 3)
        self.assertEqual(counts, sorted(counts))              # the window only grows here
        self.assertEqual(len({e["event_ref"] for e in events}), len(events))

    def test_slow_scan_stays_under_the_rules(self):
        # KNOWN LIMITATION: 1 probe per 20 s never fills a 60 s window
        pk = []
        for i in range(10):
            pk += H.refused(100.0 + i * 20, H.ATTACKER, H.BULB, 40000 + i, 2000 + i)
        for e in self.events(pk):
            d = detect(e, PROFILES["BULB-001"])
            self.assertNotEqual(d["attack_type"], "Port Scan")   # the scan rule never fires
            # (the probes hit ports the bulb does not use, so the unexpected-port rule may still notice them)

    def test_same_pcap_gives_same_events(self):
        pk = H.long_session(100.0, H.CLIENT, H.CAMERA, 40000, 554)
        path = H.write(os.path.join(self.tmp.name, "r.pcap"), pk)
        self.assertEqual(FlowEngine(DEVICES).events_from_pcap(path), FlowEngine(DEVICES).events_from_pcap(path))


class ErrorHandlingTests(PcapCase):
    def test_missing_file(self):
        with self.assertRaises(FlowEngineError):
            self.engine.flows_from_pcap(os.path.join(self.tmp.name, "nope.pcap"))

    def test_corrupt_file(self):
        path = os.path.join(self.tmp.name, "bad.pcap")
        with open(path, "wb") as f:
            f.write(b"this is not a capture file at all" * 5)
        with self.assertRaises(FlowEngineError):
            self.engine.flows_from_pcap(path)

    def test_empty_capture_gives_no_events(self):
        path = H.write(os.path.join(self.tmp.name, "empty.pcap"), [])
        self.assertEqual(self.engine.events_from_pcap(path), [])

    def test_bad_config_and_bad_devices(self):
        with self.assertRaises(FlowEngineError):
            FlowEngine(DEVICES, {"window_secs": 60})               # misspelled key
        with self.assertRaises(FlowEngineError):
            FlowEngine(DEVICES, {"step_seconds": 90, "window_seconds": 60})
        with self.assertRaises(FlowEngineError):
            FlowEngine([{"device_id": "X"}])                      # no ip: direction impossible

    def test_flow_records_adapter_skips_bad_rows(self):
        rows = [{"start": 1, "end": 2, "src_ip": H.ATTACKER, "dst_ip": H.CAMERA, "src_port": 1, "dst_port": 22, "proto": "tcp"},
                {"start": "oops"}, {"nothing": 1}]
        self.assertEqual(len(self.engine.flows_from_records(rows)), 1)


if __name__ == "__main__":
    unittest.main()
