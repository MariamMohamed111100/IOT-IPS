"""The replay guards: a capture whose timestamps are far apart, and a row the CSV parser cannot
read, must not be able to spin or abort the whole service.
"""
import csv
import tempfile
import unittest
from pathlib import Path

import pytest
from iot_ips.paths import DATA_DIR, DEFAULT_DEVICES_PATH
from ips_cyber import service as cyber_main
from ips_cyber import sources
from ips_cyber.flow_engine import Flow, FlowEngine, FlowEngineError

DEVICES = cyber_main.load_devices(str(DEFAULT_DEVICES_PATH))


def flow(start, src="203.0.113.45", dst="192.168.1.50", dport=22):
    return Flow(start, src, dst, 40000, dport, 6)


def replay(text, **kwargs):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "in.csv"
        path.write_text(text, encoding="utf-8")
        return list(sources.csv_source(path, **kwargs))


class TestCaptureSpan(unittest.TestCase):
    def test_a_normal_capture_replays(self):
        events = FlowEngine(DEVICES).build_events([flow(1.0), flow(3.0), flow(5.0)])
        self.assertIsInstance(events, list)

    def test_a_capture_spanning_years_is_refused_instead_of_grinding(self):
        # The replay cost is (last - first) / step_seconds full-window scans: at the default 10 s
        # step, 1e6 s of span is 100_000 ticks, and a 32-bit pcap timestamp allows far more.
        engine = FlowEngine(DEVICES)
        with pytest.raises(FlowEngineError, match="refusing to replay"):
            engine.build_events([flow(1.0), flow(1_000_000.0)])

    def test_the_limit_is_configurable_and_reported(self):
        engine = FlowEngine(DEVICES, {"max_capture_seconds": 30})
        with pytest.raises(FlowEngineError, match=r"spans 100 s \(max 30 s"):
            engine.build_events([flow(0.0), flow(100.0)])

    def test_a_bad_limit_is_rejected_loudly(self):
        for bad in (0, -5, "60", True):
            with self.subTest(bad=bad), pytest.raises(FlowEngineError):
                FlowEngine(DEVICES, {"max_capture_seconds": bad})


class TestCsvGuards(unittest.TestCase):
    def test_good_rows_are_read(self):
        rows = replay("a,b\n1,2\n3,4\n")
        self.assertEqual(rows, [("row2", {"a": "1", "b": "2"}), ("row3", {"a": "3", "b": "4"})])

    def test_an_unterminated_quote_stops_the_replay_instead_of_crashing(self):
        rows = replay('a,b\n1,2\n3,"unterminated\n4,5\n')
        self.assertEqual(rows[0], ("row2", {"a": "1", "b": "2"}))
        self.assertLessEqual(len(rows), 2)          # csv cannot resynchronise: it must stop clean

    def test_an_oversized_field_is_skipped_when_over_the_limit_and_read_when_under(self):
        big = "x" * 200
        self.assertEqual(replay("a,b\n1,%s\n" % big, max_field_bytes=100), [])   # skipped, not fatal
        self.assertEqual(replay("a,b\n1,%s\n" % big, max_field_bytes=1000),
                         [("row2", {"a": "1", "b": big})])

    def test_the_global_field_limit_is_restored(self):
        before = csv.field_size_limit()
        replay("a\n1\n", max_field_bytes=1234)
        self.assertEqual(csv.field_size_limit(), before)

    def test_the_real_sample_file_still_reads_every_row(self):
        rows = list(sources.csv_source(str(DATA_DIR / "sample_events.csv")))
        self.assertEqual(len(rows), 14)