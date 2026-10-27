"""Tests for the normal-traffic generator (baseline.py) and the calibration script."""

import contextlib
import copy
import importlib.util
import io
import os
import re
import tempfile
import unittest
from collections import Counter

from iot_ips import baseline, detector, policy
from iot_ips.baseline import Assumptions, generate
from iot_ips.paths import DEFAULT_DEVICES_PATH, REPO_ROOT
from iot_ips.pipeline import load_devices, read_events

DEVICES = load_devices(str(DEFAULT_DEVICES_PATH))


def load_calibrate():
    spec = importlib.util.spec_from_file_location("calibrate_under_test", REPO_ROOT / "scripts" / "calibrate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def alerts_for(events, devices):
    out = []
    for e in events:
        row = {k: str(v) for k, v in e.items()}
        d = detector.detect(row, dict(devices["CAM-001"]))
        if d["label"] == "ATTACK":
            out.append((e, d))
    return out


class TestGenerator(unittest.TestCase):
    def test_same_seed_same_events_and_other_seed_differs(self):
        self.assertEqual(list(generate(6, 7)), list(generate(6, 7)))
        self.assertNotEqual(list(generate(6, 7)), list(generate(6, 8)))

    def test_events_are_well_formed_and_in_time_order(self):
        events = list(generate(24, 3))
        self.assertGreater(len(events), 1000)
        self.assertEqual([e["event_id"] for e in events], ["BASE-%06d" % i for i in range(1, len(events) + 1)])
        stamps = [e["timestamp"] for e in events]
        self.assertEqual(stamps, sorted(stamps))
        self.assertTrue(all(re.fullmatch(r"2026-10-2[67]T\d\d:\d\d:\d\dZ", t) for t in stamps))
        self.assertTrue(stamps[-1] < "2026-10-27T00:00:00Z")
        for e in events:
            self.assertEqual(tuple(e), baseline.FIELDS)
            self.assertEqual(e["device_id"], "CAM-001")
            self.assertGreater(e["Rate"], 0)
            self.assertIn(e["protocol"], ("TCP", "UDP"))
            self.assertIn(e["traffic_kind"], baseline.KINDS)
            self.assertGreaterEqual(e["connection_attempts"], e["failed_attempts"])

    def test_every_kind_of_traffic_appears(self):
        kinds = Counter(e["traffic_kind"] for s in (1, 2, 3, 4, 5, 6, 7) for e in generate(24, s))
        self.assertEqual(set(kinds), set(baseline.KINDS))

    def test_camera_is_always_one_end_and_ports_match_the_kind(self):
        a = Assumptions()
        for e in generate(24, 2):
            self.assertIn(a.camera_ip, (e["src_ip"], e["dst_ip"]))
            expected = {"recorder_stream": 554, "live_view": 554, "cloud_upload": 443, "cloud_keepalive": 443,
                        "dns": 53, "ntp": 123, "password_typo": 443}[e["traffic_kind"]]
            self.assertEqual(e["dst_port"], expected)

    def test_daily_rhythm_more_uploads_by_day_than_at_night(self):
        uploads = [e for s in range(1, 6) for e in generate(24, s) if e["traffic_kind"] == "cloud_upload"]
        day = sum(1 for e in uploads if "06" <= e["timestamp"][11:13] < "22")
        night = len(uploads) - day
        self.assertGreater(day, 3 * night)

    def test_heavier_tail_gives_higher_rates(self):
        light = max(e["Rate"] for e in generate(24, 1, Assumptions(rate_spread=0.5)))
        heavy = max(e["Rate"] for e in generate(24, 1, Assumptions(rate_spread=3.0)))
        self.assertGreater(heavy, light)

    def test_bad_arguments_are_refused(self):
        for hours in (0, -1, True, "5", None, float("nan"), 10 ** 6):
            with self.subTest(hours=hours), self.assertRaises(ValueError):
                list(generate(hours))
        for spread in (0, -1, 21):
            with self.subTest(spread=spread), self.assertRaises(ValueError):
                list(generate(1, 1, Assumptions(rate_spread=spread)))

    def test_partial_hours_stop_in_time(self):
        events = list(generate(1.5, 4))
        self.assertTrue(events)
        self.assertLess(events[-1]["timestamp"], "2026-10-26T01:30:01Z")

    def test_csv_round_trip_through_the_pipeline_reader(self):
        events = list(generate(3, 5))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "baseline.csv")
            self.assertEqual(baseline.write_csv(path, events), len(events))
            read = list(read_events(path))
        self.assertEqual(len(read), len(events))
        self.assertTrue(all(err is None for _, _, err in read))
        self.assertEqual(read[0][1]["event_id"], events[0]["event_id"])
        self.assertEqual(float(read[0][1]["Rate"]), events[0]["Rate"])


class TestCalibrationResults(unittest.TestCase):
    """These tests pin the conclusions of docs/calibration-report.md."""

    def events(self, seeds=(1, 2, 3), spread=1.0):
        return [e for s in seeds for e in generate(24, s, Assumptions(rate_spread=spread))]

    def test_current_profile_has_no_alert_from_dns_or_ntp(self):
        events = self.events()
        types = Counter(d["attack_type"] for _, d in alerts_for(events, DEVICES))
        self.assertNotIn("Unexpected Protocol/Port", types)
        self.assertNotIn("Brute Force", types)
        self.assertNotIn("Port Scan", types)

    def test_outbound_dns_and_ntp_need_no_entry_in_the_profile(self):
        # Before the contract had a direction, a profile without ports 53 and 123 raised ~374 alerts a day
        # (every DNS lookup and NTP sync). The unexpected-port rule now ignores outbound traffic.
        old = copy.deepcopy(DEVICES)
        old["CAM-001"]["expected_ports"] = [554, 443]
        hits = [(e, d) for e, d in alerts_for(self.events((1,)), old) if d["attack_type"] == "Unexpected Protocol/Port"]
        self.assertEqual(hits, [])

    def test_every_generated_event_has_a_direction(self):
        events = self.events((1,))
        self.assertTrue(all(e["direction"] in ("inbound", "outbound") for e in events))
        self.assertTrue(all((e["direction"] == "outbound") == (e["src_ip"] == "192.168.1.50") for e in events))

    def test_false_dos_alerts_stay_rare_and_never_block(self):
        events = self.events((1, 2, 3, 4, 5))
        alerts = alerts_for(events, DEVICES)
        self.assertLessEqual(len(alerts), 5 * 3)               # at most 3 a day on average
        cal = load_calibrate()
        recs = cal.evaluate(events, DEVICES, policy.load_policy())
        self.assertFalse(any(cal.disruptive(r) for r in recs))

    def test_the_camera_profile_still_lists_what_it_needs(self):
        ports = DEVICES["CAM-001"]["expected_ports"]
        for needed in (554, 443, 53, 123):
            self.assertIn(needed, ports)


class TestCalibrateScript(unittest.TestCase):
    def run_script(self, *args):
        cal = load_calibrate()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cal.main(list(args))
        return code, out.getvalue()

    def test_generated_run_prints_every_section(self):
        code, text = self.run_script("--hours", "6", "--seeds", "1")
        self.assertEqual(code, 0)
        for heading in ("### A.", "### B.", "### C.", "### D.", "### E.", "### F.", "### G.", "### H."):
            self.assertIn(heading, text)
        self.assertIn("| 2000 |", text)

    def test_replay_of_a_recorded_file(self):
        events = list(generate(3, 9))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "lab.csv")
            baseline.write_csv(path, events)
            code, text = self.run_script("--events", path, "--hours", "3")
        self.assertEqual(code, 0)
        self.assertIn("Alerts on the recorded traffic", text)
        self.assertIn("%d events in 3 hours" % len(events), text)


if __name__ == "__main__":
    unittest.main()
