"""Offline tests for the IPS link scripts (no broker, no API).  Run:  python scripts/ips/test_ips.py"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fake_ips_publisher as pub  # noqa: E402
import ips_to_backend as m  # noqa: E402
import seed_ips_devices as seed  # noqa: E402

SAMPLES = pub.load_samples()
BRUTE = next(s for s in SAMPLES if s["name"] == "brute_force")
SKIP = next(s for s in SAMPLES if s["incident"]["skipped"])


def events(s, **kw):
    return m.build_events(s["incident"], s["event"], s["report"], s["profile"], **kw)


class TestConversion(unittest.TestCase):
    def test_score_table_of_the_integration_document(self):
        got = {x: m.to_published(x) for x in (29, 54, 67, 77, 81, 85, 86)}
        self.assertEqual(got, {29: 30, 54: 55, 67: 72, 77: 87, 81: 91, 85: 93, 86: 94})

    def test_levels_and_order_for_every_score(self):
        def level(x, cut):
            return "low" if x < cut[1] else "medium" if x < cut[2] else "high" if x < cut[3] else "critical"
        prev = -1
        for s in range(0, 101):
            out = m.to_published(s)
            self.assertGreaterEqual(out, prev)                                  # never decreases
            self.assertEqual(level(s, (0, 30, 60, 80)), level(out, (0, 31, 61, 91)), s)   # level names agree
            prev = out
        self.assertEqual((m.to_published(0), m.to_published(100)), (0, 100))
        self.assertEqual((m.to_published(-5), m.to_published("x"), m.to_published(999)), (0, 0, 100))

    def test_duration(self):
        self.assertEqual([m.duration_seconds(x) for x in ("4 minutes", "90 seconds", "2h", 12, 7.9, None, "soon", True)],
                         [240, 90, 7200, 12, 7, 0, 0, 0])

    def test_ids_and_types(self):
        self.assertEqual(m.backend_device_id("CAM-001"), "cam_001")
        self.assertEqual(m.backend_device_id("X-9", {"backend_id": "my_cam"}), "my_cam")
        self.assertEqual(m.backend_device_id("X-9", {"backend_id": "Bad Id!"}), "x_9")
        self.assertEqual(m.event_type("Brute Force"), "cyber.brute_force")
        self.assertEqual(m.event_type("Unexpected Protocol/Port"), "cyber.unexpected_traffic")
        self.assertEqual(m.event_type("DoS"), "cyber.dos")


class TestEvents(unittest.TestCase):
    def test_every_sample_follows_the_contract(self):
        for s in SAMPLES:
            msgs = events(s)
            self.assertEqual({t for t, _ in msgs}, {"security/alerts/cyber"})
            for topic, payload in msgs:
                m.check_message(topic, payload)
                self.assertEqual((payload["source"], payload["zone"]), ("cyber", "network"))

    def test_brute_force_matches_the_example_of_the_document(self):
        ev = events(BRUTE)[0][1]
        d = ev["data"]
        self.assertEqual((ev["type"], ev["severity_hint"]), ("cyber.brute_force", "critical"))
        self.assertEqual((d["src_ip"], d["dst_ip"], d["dst_port"], d["device_id"], d["target"]), ("203.0.113.45", "192.168.1.50", 22, "cam_001", "ssh"))
        self.assertEqual((d["failed_attempts"], d["attempts"], d["direction"], d["mitre_technique"]), (300, 300, "inbound", "T1110"))
        self.assertEqual((d["details"]["ips_score"], d["details"]["ips_score_raw"], d["details"]["ips_level"]), (93, 85, "critical"))
        self.assertTrue(d["details"]["reports"]["technical"].startswith("# Security Incident Report"))

    def test_port_scan_extra_fields(self):
        d = events(next(s for s in SAMPLES if s["name"] == "port_scan"))[0][1]["data"]
        self.assertEqual((d["ports"], d["port_count"] > 0), ([], True))
        self.assertIn("hosts_probed", d)

    def test_block_results_are_dry_run_events(self):
        msgs = events(BRUTE)
        kinds = [(p["type"], p["data"]["action"], p["data"]["ip"]) for _, p in msgs[1:]]
        self.assertIn(("cyber.block_applied", "block_source", "203.0.113.45"), kinds)
        self.assertIn(("cyber.block_applied", "isolate_device", "192.168.1.50"), kinds)
        self.assertTrue(all(p["data"]["dry_run"] for _, p in msgs[1:]))
        refused = [p for _, p in events(SKIP) if p["type"] == "cyber.block_refused"]
        self.assertEqual([(p["data"]["action"], p["data"]["reason"]) for p in refused], [("block_source", "source_is_device")])

    def test_ids_are_stable_and_unique(self):
        a, b = events(BRUTE), events(BRUTE)
        self.assertEqual([p["id"] for _, p in a], [p["id"] for _, p in b])
        self.assertEqual(len({p["id"] for _, p in a}), len(a))
        self.assertNotEqual(events(BRUTE, seq=1)[0][1]["id"], a[0][1]["id"])

    def test_hostile_and_broken_input_stays_valid(self):
        bad = dict(BRUTE["incident"], id="INC-9\n", src_ip="x" * 500, attack_type="<script>", level="nope", score="abc",
                   confidence="nan", mitre_technique="T1110' OR 1=1", dst_port="NaN", protocol="ESP", actions=["block_source", 7])
        ev = dict(BRUTE["event"], direction="sideways", failed_attempts="many", duration="soon")
        rep = {"technical": "a" * 50000, "executive": "b" * 50000}
        for topic, payload in m.build_events(bad, ev, rep, {"backend_id": "weird id"}):
            m.check_message(topic, payload)
        det = m.build_events(bad, ev, rep, None)[0][1]
        self.assertLessEqual(len(json.dumps(det["data"])), 32 * 1024)
        self.assertEqual((det["data"]["details"]["mitre_technique"], det["data"]["protocol"], det["data"]["direction"]), ("T1595", "TCP", "inbound"))

    def test_checker_rejects_what_breaks_the_contract(self):
        good = events(BRUTE)[0][1]
        for key, value in (("type", "nodot"), ("zone", "Bad Zone"), ("id", "short"), ("severity_hint", "huge"), ("data", [])):
            with self.assertRaises(m.MessageError):
                m.check_message("security/alerts/cyber", dict(good, **{key: value}))
        for key, value in (("protocol", "ESP"), ("direction", "up"), ("device_id", "CAM-001"), ("confidence", 2), ("dst_port", 70000)):
            bad = json.loads(json.dumps(good))
            bad["data"][key] = value
            with self.assertRaises(m.MessageError, msg=key):
                m.check_message("security/alerts/cyber", bad)
        bad = json.loads(json.dumps(good))
        del bad["data"]["duration"]
        with self.assertRaises(m.MessageError):
            m.check_message("security/alerts/cyber", bad)
        bad = json.loads(json.dumps(good))
        bad["data"]["details"]["extra"] = 1
        with self.assertRaises(m.MessageError):
            m.check_message("security/alerts/cyber", bad)

    def test_standalone_adds_risk_and_incident(self):
        msgs = pub.plan(SAMPLES, only=["brute_force"], standalone=True)
        self.assertEqual([t for t, _ in msgs].count("security/incidents"), 1)
        inc = next(p for t, p in msgs if t == "security/incidents")
        self.assertEqual((inc["level"], inc["score"], inc["id"]), ("critical", 93, "INC-00033"))
        self.assertEqual(inc["events"], [msgs[0][1]["id"]])


class TestPlanAndSeed(unittest.TestCase):
    def test_plan_counts(self):
        one = len(events(BRUTE))
        self.assertEqual(len(pub.plan(SAMPLES, only=["brute_force"], repeat=3)), 3 * one)
        self.assertEqual(len({p["id"] for _, p in pub.plan(SAMPLES, only=["brute_force"], repeat=3)}), 3 * one - 4)

    def test_seed_payloads_use_the_contract_device_file(self):
        profs = seed.load_profiles(Path(seed.__file__).resolve().parent.parent.parent / "config" / "ips_devices.json")
        self.assertEqual(len(profs), 6)
        body = {seed.device_payload(p)["device_id"]: seed.device_payload(p) for p in profs}
        cam = body["cam_001"]
        self.assertEqual((cam["device_type"], cam["zone"], cam["online"]), ("camera", "entrance", True))
        self.assertEqual(cam["state"]["ip"], "192.168.1.50")
        self.assertEqual((body["plug_001"]["device_type"], body["ind_001"]["device_type"]), ("plug", "industrial_sensor"))
        self.assertEqual(seed.device_payload(profs[0], zones=["garage"])["zone"], "network")     # unknown zone falls back

    def test_seed_rejects_bad_files(self):
        path = Path(tempfile.mkdtemp()) / "d.json"
        path.write_text("[1,2]")
        self.assertEqual(seed.load_profiles(path), [])


if __name__ == "__main__":
    unittest.main()
