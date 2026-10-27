"""Tests for the IPS cyber service (services/ips_cyber).
Run from services/ips_cyber:  python -m pytest tests

Optional cross-check against the backend's own validator: set WARDEN_IPS_SCRIPTS to the
scripts/ips folder of this repository and the envelopes are also checked with ips_to_backend.check_message.
"""
import copy
import json
import os
import sys
import tempfile
import unittest

import yaml
from iot_ips import detector
from iot_ips.detector import DetectorConfigError
from iot_ips.paths import DATA_DIR, DEFAULT_DEVICES_PATH
from ips_cyber import envelope, sources
from ips_cyber import publisher as pub
from ips_cyber import service as cyber_main

DEVICES_FILE = str(DEFAULT_DEVICES_PATH)
REPLAY_FILE = str(DATA_DIR / "sample_events.csv")        # the 14 sample events of the whole project
CONFIG = cyber_main.load_service_config()
DEVICES = cyber_main.load_devices(DEVICES_FILE)
ConfigError = (cyber_main.ConfigError, DetectorConfigError)

try:
    import pcap_helpers as H
    HAVE_SCAPY = True
except ImportError:  # pragma: no cover
    HAVE_SCAPY = False


def backend_checker():
    path = os.environ.get("WARDEN_IPS_SCRIPTS")
    if not path:
        return None
    sys.path.insert(0, path)
    import ips_to_backend
    return ips_to_backend.check_message


def make_service(publisher=None, **kw):
    publisher = publisher or pub.MemoryPublisher()
    return cyber_main.IpsCyberService(DEVICES, publisher, CONFIG, **kw), publisher


def replay(service):
    return service.run(sources.csv_source(REPLAY_FILE), "sample_events.csv")


class ReplayTests(unittest.TestCase):
    def test_replay_sample_gives_expected_alerts(self):
        service, memory = make_service()
        stats = replay(service)
        types = [m[1]["type"] for m in memory.messages]
        # the same 7 detections as `python scripts/evaluate.py` (EVT-005, 006, 008, 009, 010, 011, 014)
        self.assertEqual(types, ["cyber.port_scan", "cyber.unexpected_traffic", "cyber.brute_force",
                                 "cyber.unexpected_traffic", "cyber.dos", "cyber.dos", "cyber.dos"])
        self.assertTrue(all(topic == "security/alerts/cyber" for topic, _ in memory.messages))
        self.assertEqual(stats["events_read"], 14)
        self.assertEqual(stats["alerts_published"], 7)
        self.assertEqual(stats["skipped_bad_input"], 0)
        self.assertEqual(stats["benign"], 7)                   # 4 normal events + 3 missed attacks

    def test_normal_traffic_publishes_nothing(self):
        service, memory = make_service()
        replay(service)
        published = {m[1]["data"]["src_ip"] for m in memory.messages}
        for quiet in ("192.168.1.20", "192.168.1.21", "192.168.1.51"):       # viewer, owner's laptop, thermostat
            self.assertNotIn(quiet, published)

    def test_envelopes_are_valid_and_clean(self):
        service, memory = make_service()
        replay(service)
        check = backend_checker()
        for topic, alert in memory.messages:
            envelope.validate_alert(alert)
            self.assertEqual(alert["source"], "cyber")
            self.assertRegex(alert["data"]["device_id"], r"^[a-z0-9_]+$")
            self.assertTrue(alert["ts"].endswith("+00:00"))
            if check:
                check(topic, alert)

    def test_data_fields_follow_the_contract(self):
        service, memory = make_service()
        replay(service)
        brute = [m[1] for m in memory.messages if m[1]["type"] == "cyber.brute_force"][0]
        d = brute["data"]
        for key in ("src_ip", "dst_ip", "dst_port", "protocol", "direction", "device_id", "confidence",
                    "mitre_technique", "failed_attempts", "connection_attempts", "duration"):
            self.assertIn(key, d, key)
        self.assertEqual((d["device_id"], d["ips_device_id"], d["mitre_technique"]), ("cam_001", "CAM-001", "T1110"))
        self.assertEqual((d["direction"], d["failed_attempts"], d["attempts"]), ("inbound", 300, 300))
        self.assertEqual(brute["zone"], "network")

    def test_severity_hint_follows_confidence(self):
        cfg = CONFIG["severity"]
        self.assertEqual(envelope.severity_hint(0.5, cfg), "low")
        self.assertEqual(envelope.severity_hint(0.6, cfg), "medium")
        self.assertEqual(envelope.severity_hint(0.85, cfg), "high")
        self.assertEqual(envelope.severity_hint("junk", cfg), "low")

    def test_ids_are_deterministic_and_unique(self):
        a, mem_a = make_service()
        b, mem_b = make_service()
        replay(a)
        replay(b)
        ids_a = [m[1]["id"] for m in mem_a.messages]
        self.assertEqual(ids_a, [m[1]["id"] for m in mem_b.messages])
        self.assertEqual(len(set(ids_a)), len(ids_a))

    def test_zone_is_always_network_whatever_the_device_room(self):
        memory = pub.MemoryPublisher()
        service = cyber_main.IpsCyberService(DEVICES, memory, CONFIG)
        replay(service)
        self.assertTrue(any(d.get("zone") not in (None, "network") for d in DEVICES))      # rooms exist ...
        self.assertEqual({m[1]["zone"] for m in memory.messages}, {"network"})            # ... but are not used


class BadInputTests(unittest.TestCase):
    def test_hostile_text_is_cleaned(self):
        service, memory = make_service()
        ev = {"device_id": "CAM-001", "src_ip": "1.2.3.4\n<script>alert(1)</script>" + "A" * 500,
              "dst_ip": "192.168.1.50", "dst_port": "22", "protocol": "TCP\x00", "direction": "inbound",
              "failed_attempts": "300"}
        alert = service.handle_event("evil", ev, "t")
        self.assertIsNotNone(alert)
        self.assertNotIn("\n", alert["data"]["src_ip"])
        self.assertLessEqual(len(alert["data"]["src_ip"]), 64)
        self.assertNotIn("\x00", alert["data"]["protocol"])
        envelope.validate_alert(alert)

    def test_non_dict_and_missing_device_are_skipped(self):
        service, memory = make_service()
        for bad in (None, "text", 5, [], {}, {"device_id": ""}):
            self.assertIsNone(service.handle_event("x", bad, "t"))
        self.assertEqual(memory.messages, [])
        self.assertEqual(service.stats["skipped_bad_input"], 6)

    def test_unknown_device_still_alerts_without_profile(self):
        service, memory = make_service()
        alert = service.handle_event("r1", {"device_id": "NEW-DEV", "dst_port": "22", "failed_attempts": "99",
                                            "protocol": "TCP", "src_ip": "203.0.113.9", "dst_ip": "192.168.1.99"}, "t")
        self.assertEqual(alert["data"]["device_id"], "new_dev")
        self.assertEqual(alert["zone"], "network")

    def test_crashing_detector_does_not_stop_the_service(self):
        def boom(event, profile):
            if event.get("device_id") == "PLUG-001":
                raise RuntimeError("model exploded")
            return detector.detect(event, profile)
        service, memory = make_service(detect_fn=boom)
        stats = replay(service)
        self.assertEqual(stats["alerts_published"], 7)           # the other events are still processed
        self.assertEqual(stats["skipped_bad_input"], 3)          # the three PLUG-001 events

    def test_custom_detect_function_slot_for_the_ml_model(self):
        def ml(event, profile):
            return {"label": "ATTACK", "attack_type": "DoS", "confidence": 0.91,
                    "mitre_technique": "T1498"}
        service, memory = make_service(detect_fn=ml)
        alert = service.handle_event("r1", {"device_id": "CAM-001", "protocol": "TCP", "src_ip": "203.0.113.9",
                                            "dst_ip": "192.168.1.50", "dst_port": "80"}, "t")
        self.assertEqual((alert["type"], alert["severity_hint"]), ("cyber.dos", "high"))

    def test_benign_detection_from_ml_publishes_nothing(self):
        def ml(event, profile):
            return {"label": "BENIGN", "attack_type": "None", "confidence": 0.99,
                    "mitre_technique": None}
        service, memory = make_service(detect_fn=ml)
        self.assertIsNone(service.handle_event("r1", {"device_id": "CAM-001"}, "t"))
        self.assertEqual(service.stats["benign"], 1)


class ConfigTests(unittest.TestCase):
    def _bad_rules(self):
        with open(detector.DEFAULT_CONFIG, encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        cfg["rules"]["brute_force"]["min_faild_attempts"] = cfg["rules"]["brute_force"].pop("min_failed_attempts")
        fd, path = tempfile.mkstemp(suffix=".yaml")
        os.close(fd)
        self.addCleanup(os.remove, path)
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f)
        return path

    def test_service_refuses_to_start_with_a_typo_in_rules(self):
        with self.assertRaises(ConfigError):
            cyber_main.IpsCyberService(DEVICES, pub.MemoryPublisher(), CONFIG, rules_path=self._bad_rules())

    def test_cli_exits_with_error_code_on_bad_rules(self):
        code = cyber_main.main(["--source", "csv", "--file", REPLAY_FILE, "--devices", DEVICES_FILE,
                                "--rules", self._bad_rules()], publisher_override=pub.MemoryPublisher())
        self.assertEqual(code, 2)

    def test_service_config_typo_is_rejected(self):
        fd, path = tempfile.mkstemp(suffix=".yaml")
        os.close(fd)
        self.addCleanup(os.remove, path)
        bad = copy.deepcopy(CONFIG)
        bad["topc"] = bad.pop("topic")
        with open(path, "w") as f:
            yaml.safe_dump(bad, f)
        with self.assertRaises(ConfigError):
            cyber_main.load_service_config(path)


class FakeInfo:
    def __init__(self, ok):
        self.ok = ok

    def wait_for_publish(self, timeout=None):
        pass

    def is_published(self):
        return self.ok


class FakeMqtt:
    """Stands in for paho's client."""
    def __init__(self, fail_first=0, always_fail=False):
        self.sent, self.calls = [], 0
        self.fail_first, self.always_fail = fail_first, always_fail

    def publish(self, topic, body, qos=0):
        self.calls += 1
        if self.always_fail or self.calls <= self.fail_first:
            return FakeInfo(False)
        self.sent.append((topic, json.loads(body), qos))
        return FakeInfo(True)

    def loop_stop(self):
        pass

    def disconnect(self):
        pass


class MqttTests(unittest.TestCase):
    def test_publishes_json_on_the_alert_topic_with_qos1(self):
        fake = FakeMqtt()
        service, _ = make_service(pub.MqttPublisher(client=fake, retry_wait=0))
        replay(service)
        self.assertEqual(len(fake.sent), 7)
        self.assertTrue(all(t == "security/alerts/cyber" and q == 1 for t, _, q in fake.sent))

    def test_retries_after_a_broker_hiccup(self):
        fake = FakeMqtt(fail_first=2)
        service, _ = make_service(pub.MqttPublisher(client=fake, retry_wait=0))
        replay(service)
        self.assertEqual(len(fake.sent), 7)                    # nothing lost
        self.assertEqual(service.stats["publish_errors"], 0)

    def test_broker_down_is_counted_not_fatal(self):
        fake = FakeMqtt(always_fail=True)
        service, _ = make_service(pub.MqttPublisher(client=fake, retries=2, retry_wait=0))
        stats = replay(service)
        self.assertEqual(stats["publish_errors"], 7)
        self.assertEqual(stats["alerts_published"], 0)

    def test_exception_from_client_is_retried_then_reported(self):
        class Raising(FakeMqtt):
            def publish(self, *a, **k):
                raise RuntimeError("not connected")
        service, _ = make_service(pub.MqttPublisher(client=Raising(), retries=2, retry_wait=0))
        self.assertEqual(replay(service)["publish_errors"], 7)

    def test_missing_mqtt_environment_gives_clear_error(self):
        saved = {k: os.environ.pop(k, None) for k in ("MQTT_HOST", "MQTT_PASSWORD")}
        try:
            with self.assertRaises(pub.PublishError):
                pub.MqttPublisher()
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v


class CliTests(unittest.TestCase):
    def test_csv_to_jsonl_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "alerts.jsonl")
            code = cyber_main.main(["--source", "csv", "--file", REPLAY_FILE, "--devices", DEVICES_FILE,
                                    "--publisher", "file", "--out", out])
            self.assertEqual(code, 0)
            with open(out, encoding="utf-8") as fh:
                lines = [json.loads(line) for line in fh]
            self.assertEqual(len(lines), 7)
            self.assertEqual(lines[0]["topic"], "security/alerts/cyber")

    def test_missing_file_and_bad_arguments_return_error_code(self):
        self.assertEqual(cyber_main.main(["--source", "csv", "--file", "/no/such.csv", "--devices", DEVICES_FILE,
                                          "--publisher", "stdout"]), 2)
        self.assertEqual(cyber_main.main(["--source", "csv", "--devices", DEVICES_FILE]), 2)       # no --file
        self.assertEqual(cyber_main.main(["--source", "csv", "--file", REPLAY_FILE, "--devices", "/no/devices.json"]), 2)


@unittest.skipUnless(HAVE_SCAPY, "scapy not installed")
class PcapEndToEndTests(unittest.TestCase):
    def test_pcap_to_alerts(self):
        with tempfile.TemporaryDirectory() as tmp:
            pk = []
            for i in range(70):                                         # SSH brute force on the camera
                pk += H.failed_login(100.0 + i * 0.3, H.ATTACKER, H.CAMERA, 30000 + i, 22)
            for i in range(30):                                         # normal viewing
                pk += H.long_session(100.0 + i * 0.2, H.CLIENT, H.CAMERA, 20000 + i, 554, seconds=3.0)
            pk += H.long_session(100.0, H.CAMERA, H.CLOUD, 50001, 8883, seconds=8.0)     # outbound MQTT
            pk += H.udp_exchange(105.0, H.CAMERA, H.NTP, 50002, 123)                      # outbound NTP
            path = H.write(os.path.join(tmp, "lab.pcap"), pk)

            service, memory = make_service()
            stats = service.run(sources.pcap_source(path, DEVICES, CONFIG["flow_engine"]), "lab.pcap")
            alerts = [m[1] for m in memory.messages]
            self.assertTrue(alerts)
            types = {a["type"] for a in alerts}
            self.assertIn("cyber.brute_force", types)
            # the first snapshots (before 50 failures) may say "unexpected traffic": SSH is not a camera port.
            # No DoS / scan, and no alert at all for the viewer or the camera's own outbound traffic:
            self.assertTrue(types <= {"cyber.brute_force", "cyber.unexpected_traffic"}, types)
            self.assertEqual({a["data"]["src_ip"] for a in alerts}, {H.ATTACKER})
            self.assertEqual(stats["publish_errors"], 0)
            check = backend_checker()
            for a in alerts:
                envelope.validate_alert(a)
                if check:
                    check("security/alerts/cyber", a)

    def test_replaying_the_pcap_twice_gives_the_same_alert_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            pk = []
            for i in range(60):
                pk += H.failed_login(100.0 + i * 0.3, H.ATTACKER, H.CAMERA, 30000 + i, 22)
            path = H.write(os.path.join(tmp, "x.pcap"), pk)
            runs = []
            for _ in range(2):
                service, memory = make_service()
                service.run(sources.pcap_source(path, DEVICES, CONFIG["flow_engine"]), "x.pcap")
                runs.append([m[1]["id"] for m in memory.messages])
            self.assertEqual(runs[0], runs[1])
            self.assertTrue(runs[0])

    def test_corrupt_pcap_returns_error_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.pcap")
            with open(bad, "wb") as f:
                f.write(b"garbage" * 20)
            code = cyber_main.main(["--source", "pcap", "--file", bad, "--devices", DEVICES_FILE],
                                   publisher_override=pub.MemoryPublisher())
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
