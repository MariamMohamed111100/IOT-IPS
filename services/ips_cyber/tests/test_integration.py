"""End-to-end checks of the cyber service with the repository's own detector, risk engine and policy.

Run from services/ips_cyber:  python -m pytest tests
Needs scapy and jsonschema (see requirements.txt).
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

import pytest

pytest.importorskip("scapy")
jsonschema = pytest.importorskip("jsonschema")

import pcap_helpers as H  # noqa: E402
from iot_ips import actions, detector, policy, risk  # noqa: E402
from iot_ips.paths import DATA_DIR, DEFAULT_DEVICES_PATH  # noqa: E402
from ips_cyber import envelope, flow_engine, sources  # noqa: E402
from ips_cyber import service as svc  # noqa: E402

CONTRACT = Path(__file__).resolve().parents[3] / "contract"
DEVICES = svc.load_devices(str(DEFAULT_DEVICES_PATH))
CONFIG = svc.load_service_config()
CAM, ATT, LAN, VIEWER, CLOUD = "192.168.1.50", "203.0.113.45", "192.168.1.66", "192.168.1.20", "52.29.14.7"


class Memory:
    def __init__(self):
        self.messages = []

    def publish(self, topic, payload):
        self.messages.append((topic, payload))
        return True

    def close(self):
        pass


def run_pcap(packets):
    with tempfile.TemporaryDirectory() as tmp:
        path = H.write(os.path.join(tmp, "x.pcap"), packets)
        memory = Memory()
        service = svc.IpsCyberService(DEVICES, memory, config=CONFIG)
        stats = service.run(sources.pcap_source(path, DEVICES, CONFIG["flow_engine"]), "x.pcap")
    return [m[1] for m in memory.messages], stats


def kinds(alerts):
    return {(a["type"], a["data"]["src_ip"]) for a in alerts}


class ContractTests(unittest.TestCase):
    def test_every_sample_alert_matches_the_backend_schema(self):
        schema = json.loads((CONTRACT / "ips_event_data.schema.json").read_text())
        memory = Memory()
        service = svc.IpsCyberService(DEVICES, memory, config=CONFIG)
        service.run(sources.csv_source(str(DATA_DIR / "sample_events.csv")), "sample")
        self.assertEqual(len(memory.messages), 7)
        for _, alert in memory.messages:
            jsonschema.validate(alert["data"], schema)          # includes duration and the protocol enum

    def test_protocol_outside_the_contract_is_refused_not_sent(self):
        event = {"device_id": "CAM-001", "protocol": "ESP", "src_ip": ATT, "dst_ip": CAM, "dst_port": "0"}
        service = svc.IpsCyberService(DEVICES, Memory(), config=CONFIG,
                                      detect_fn=lambda e, p: {"label": "ATTACK", "attack_type": "DoS",
                                                              "confidence": 0.9, "mitre_technique": "T1498"})
        self.assertIsNone(service.handle_event("r", event, "t"))


class TrafficTests(unittest.TestCase):
    def test_150_normal_viewer_sessions_are_not_a_dos(self):
        pk = []
        for i in range(150):
            pk += H.long_session(1 + i * 0.3, VIEWER, CAM, 40000 + i, 554, seconds=5)
        for i in range(30):
            pk += H.long_session(10 + i, CAM, CLOUD, 50000 + i, 443, seconds=3, packets=14)
        alerts, _ = run_pcap(pk)
        self.assertEqual(alerts, [])

    def test_a_port_scan_is_reported_as_a_scan_not_a_dos(self):
        pk = []
        for p in range(1, 1001):
            pk += H.refused(1 + p * 0.03, LAN, CAM, 42000 + p % 1000, p)
        alerts, _ = run_pcap(pk)
        types = {a["type"] for a in alerts}
        self.assertIn("cyber.port_scan", types)
        self.assertNotIn("cyber.dos", types)

    def test_brute_force_is_reported(self):
        pk = []
        for i in range(300):
            pk += H.failed_login(1 + i * 0.15, ATT, CAM, 41000 + i, 22)
        alerts, _ = run_pcap(pk)
        self.assertIn(("cyber.brute_force", ATT), kinds(alerts))

    def test_spread_out_flood_is_caught_by_the_aggregate_event(self):
        pk = []
        for i in range(5000):
            pk += H.syn_only(1 + i * 0.002, "198.51.100.%d" % (1 + i % 250), CAM, 10000 + i % 50000, 554)
        alerts, _ = run_pcap(pk)
        dos = [a for a in alerts if a["type"] == "cyber.dos"]
        self.assertTrue(dos)
        self.assertEqual({a["data"]["src_ip"] for a in dos}, {flow_engine.AGGREGATE_SRC})

    def test_the_aggregate_source_is_never_blocked_by_the_policy(self):
        self.assertTrue(actions.is_never_block(actions.ipaddress.ip_address(flow_engine.AGGREGATE_SRC)))
        event = {"src_ip": flow_engine.AGGREGATE_SRC, "device_id": "CAM-001", "direction": "inbound"}
        detection = {"label": "ATTACK", "attack_type": "DoS", "confidence": 0.95, "mitre_technique": "T1498"}
        profile = {d["device_id"]: d for d in DEVICES}["CAM-001"]
        rsk = risk.assess(detection, event, profile)
        decision = policy.decide(rsk, detection, event, profile)
        self.assertNotIn("block_source", decision["action"])
        self.assertNotIn("temporary_block", decision["action"])
        self.assertIn({"action": "temporary_block", "why": "source_never_block"}, decision["skipped"])

    def test_capture_limits_stop_a_runaway_pcap(self):
        cfg = dict(CONFIG["flow_engine"], max_packets=50)
        pk = []
        for i in range(30):
            pk += H.long_session(1 + i, VIEWER, CAM, 40000 + i, 554, seconds=1)
        with tempfile.TemporaryDirectory() as tmp:
            path = H.write(os.path.join(tmp, "big.pcap"), pk)
            with self.assertRaises(flow_engine.FlowEngineError):
                list(sources.pcap_source(path, DEVICES, cfg))

    def test_no_false_alarms_on_the_rtsp_profiles(self):
        pk = []
        for i in range(60):
            pk += H.long_session(1 + i * 2, VIEWER, CAM, 20000 + i, 554, seconds=2)
        alerts, _ = run_pcap(pk)
        self.assertEqual(alerts, [])


class DetectorRuleTests(unittest.TestCase):
    def test_default_rule_file_uses_the_calibrated_connection_floor(self):
        text = Path(detector.DEFAULT_CONFIG).read_text()
        self.assertRegex(text, r"min_connection_attempts:\s*500\b")


class MlTests(unittest.TestCase):
    def test_the_ml_attack_groups_map_onto_the_four_contract_event_types(self):
        wanted = {"Recon": "cyber.port_scan", "BruteForce": "cyber.brute_force", "DDoS": "cyber.dos",
                  "DoS": "cyber.dos", "Mirai": "cyber.dos", "Spoofing": "cyber.unexpected_traffic",
                  "Web": "cyber.unexpected_traffic"}
        self.assertEqual({k: envelope.event_type(k) for k in wanted}, wanted)

    def test_combined_detector_adds_the_attacks_the_rules_miss(self):
        pytest.importorskip("ids_ml")
        out = []

        class Collect(Memory):
            def publish(self, topic, payload):
                out.append(payload)
                return True
        csv = str(DATA_DIR / "sample_events.csv")
        rc = svc.main(["--source", "csv", "--file", csv, "--devices", str(DEFAULT_DEVICES_PATH),
                       "--publisher", "stdout", "--detector", "combined"], publisher_override=Collect())
        self.assertEqual(rc, 0)
        types = [(a["type"], a["data"]["attack_type"]) for a in out]
        self.assertEqual(len(out), 9)                                       # the 7 of the rules + Recon + Spoofing
        self.assertIn(("cyber.port_scan", "Recon"), types)
        self.assertIn(("cyber.unexpected_traffic", "Spoofing"), types)
        schema = json.loads((CONTRACT / "ips_event_data.schema.json").read_text())
        for a in out:
            jsonschema.validate(a["data"], schema)

    def test_combined_without_the_ml_package_stops_with_a_clear_message(self):
        import builtins
        real = builtins.__import__

        def no_ml(name, *a, **k):
            if name.startswith("ids_ml"):
                raise ImportError("no ids_ml")
            return real(name, *a, **k)
        builtins.__import__ = no_ml
        try:
            rc = svc.main(["--source", "csv", "--file", str(DATA_DIR / "sample_events.csv"),
                           "--devices", str(DEFAULT_DEVICES_PATH), "--detector", "combined"])
        finally:
            builtins.__import__ = real
        self.assertEqual(rc, 2)


class DetailsTests(unittest.TestCase):
    """Warden reads data.details from the STORED EVENT, so the sensor has to put it there (contract v1.2)."""

    def run_sample(self, **kw):
        memory = Memory()
        service = svc.IpsCyberService(DEVICES, memory, config=CONFIG, **kw)
        service.run(sources.csv_source(str(DATA_DIR / "sample_events.csv")), "sample")
        return [m[1] for m in memory.messages]

    def test_every_alert_carries_valid_details(self):
        schema = json.loads((CONTRACT / "incident_details.schema.json").read_text())
        alerts = self.run_sample()
        self.assertEqual(len(alerts), 7)
        for a in alerts:
            jsonschema.validate(a["data"]["details"], schema)
            self.assertTrue(a["data"]["details"]["reports"]["technical"])
            self.assertTrue(a["data"]["details"]["reports"]["executive"])
            self.assertLess(len(json.dumps(a["data"])), 32 * 1024)

    def test_details_follow_the_alert_not_a_fixed_text(self):
        by_type = {a["type"]: a["data"]["details"] for a in self.run_sample()}
        self.assertEqual(by_type["cyber.brute_force"]["mitre_technique"], "T1110")
        self.assertEqual(by_type["cyber.port_scan"]["mitre_technique"], "T1046")
        self.assertNotEqual(by_type["cyber.brute_force"]["reports"]["technical"],
                            by_type["cyber.dos"]["reports"]["technical"])

    def test_an_alert_is_still_sent_when_the_ips_chain_fails(self):
        from unittest import mock
        with mock.patch("ips_cyber.service.enrich.build_details", return_value=None):
            alerts = self.run_sample()
        self.assertEqual(len(alerts), 7)
        self.assertTrue(all("details" not in a["data"] for a in alerts))

    def test_ml_alerts_carry_details_too(self):
        pytest.importorskip("ids_ml")
        from ids_ml.combined import make_detect
        alerts = self.run_sample(detect_fn=make_detect())
        self.assertEqual(len(alerts), 9)
        self.assertTrue(all("details" in a["data"] for a in alerts))
