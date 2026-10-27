"""Tests for pipeline.py: the whole chain, bad input, limits and the command line."""
import contextlib
import io
import os
import tempfile
import unittest

from iot_ips import db as dbmod
from iot_ips import pipeline as rp
from iot_ips import report as reportmod
from iot_ips.paths import CONFIG_DIR, DATA_DIR, PACKAGE_DIR

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "fixtures", "pipeline_test_events.csv")   # written for the placeholder detector
P2_SAMPLE = str(DATA_DIR / "sample_events.csv")                       # the 14 sample events, used with the rule-based detector
DEVICES = str(CONFIG_DIR / "devices.json")
HEADER = "device_id,timestamp,src_ip,dst_ip,dst_port,protocol,failed_attempts,connection_attempts,Rate,syn_flag_number\n"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "i.db")
        self.log = os.path.join(self.tmp.name, "a.jsonl")

    def csv(self, body, header=HEADER):
        path = os.path.join(self.tmp.name, "e.csv")
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(header + body)
        return path

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = rp.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def run_events(self, path, *extra):
        return self.run_cli("run", path, "--db", self.db_path, "--devices", DEVICES, "--action-log", self.log, "--reset",
                            *(extra if "--detector" in extra else ("--detector", "placeholder") + extra))

    def rows(self):
        with dbmod.IncidentDB(self.db_path) as d:
            return d.query_incidents(limit=1000)


def Pipeline_for(case, modules):
    policy_cfg = modules.policy.load_policy()
    database = dbmod.IncidentDB(":memory:")
    case.addCleanup(database.close)
    executor = modules.actions.ActionExecutor.from_policy(policy_cfg, log_path=case.log)
    return rp.Pipeline(database, modules, rp.load_devices(DEVICES), executor, policy_cfg)


class TestSampleRun(Base):
    def test_levels_match_the_expected_level_column(self):
        code, out, _ = self.run_events(SAMPLE)
        self.assertEqual(code, 0, out)
        got = sorted((r["timestamp"], r["risk_level"]) for r in self.rows())
        import csv
        with open(SAMPLE, encoding="utf-8", newline="") as f:
            expected = [r["expected_level"] for r in csv.DictReader(f) if r["expected_level"] != "none"]
        self.assertEqual(sorted(l for _t, l in got), sorted(expected))

    def test_counts_in_the_run_summary(self):
        _c, out, _e = self.run_events(SAMPLE)
        self.assertIn("benign       : 3", out)
        self.assertIn("attacks      : 9, incidents stored: 9", out)

    def test_expected_columns_never_reach_the_detector(self):
        seen = []
        modules = rp.Modules()
        modules.detect = lambda e: (seen.append(dict(e)), {"label": "BENIGN"})[1]
        pipeline = Pipeline_for(self, modules)
        for _l, event, _p in rp.read_events(SAMPLE):
            pipeline.process_event(event)
        self.assertTrue(seen)
        self.assertFalse([k for e in seen for k in e if k.lower().startswith("expected_")])

    def test_benign_rows_store_nothing(self):
        self.run_events(SAMPLE)
        self.assertEqual(len(self.rows()), 9)

    def test_chain_intact_after_run(self):
        self.run_events(SAMPLE)
        code, out, _ = self.run_cli("verify", "--db", self.db_path)
        self.assertEqual(code, 0)
        self.assertIn("intact", out)

    def test_show_prints_summary(self):
        self.run_events(SAMPLE)
        code, out, _ = self.run_cli("show", "--db", self.db_path)
        self.assertEqual(code, 0)
        self.assertIn("Incidents by level: Low 2, Medium 1, High 3, Critical 3", out)
        code, out, _ = self.run_cli("show", "--db", self.db_path, "--level", "Critical")
        self.assertEqual(out.count("INC-"), 3)

    def test_full_incident_view_has_reports(self):
        self.run_events(SAMPLE)
        code, out, _ = self.run_cli("show", "--db", self.db_path, "--full", "INC-00001")
        self.assertEqual(code, 0)
        self.assertIn("technical report", out)

    def test_nothing_real_is_executed_everything_simulated(self):
        self.run_events(SAMPLE)
        import json
        with open(self.log, encoding="ascii") as f:
            records = [json.loads(line) for line in f]
        self.assertTrue(records)
        self.assertTrue(all(r["dry_run"] for r in records))
        self.assertTrue(all(r["status"] in ("simulated", "skipped", "refused") for r in records))

    def test_spoofed_router_source_is_never_blocked(self):
        self.run_events(SAMPLE)
        import json
        with open(self.log, encoding="ascii") as f:
            records = [json.loads(line) for line in f]
        self.assertFalse([r for r in records if r["target"] == "192.168.1.1" and r["status"] == "simulated"])

    def test_dry_run_flag_stored(self):
        self.run_events(SAMPLE)
        self.assertTrue(all(r["dry_run"] for r in self.rows()))
        self.assertTrue(all(r["status"] != "contained" for r in self.rows()))

    def test_rerun_with_reset_gives_same_count(self):
        self.run_events(SAMPLE)
        self.run_events(SAMPLE)
        self.assertEqual(len(self.rows()), 9)


class TestBadInput(Base):
    def test_missing_fields_do_not_crash(self):
        path = self.csv(",,,,,,,,,\n,,,,22,,50,50,,\nCAM-001,,,,,,,,,\nCAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,50,50,,\n")
        code, out, err = self.run_events(path)
        self.assertEqual(code, 0, out + err)
        rows = self.rows()
        self.assertTrue(rows)
        warnings = " ".join(" ".join(r["risk_warnings"]) for r in rows)
        self.assertIn("missing_src_ip", warnings)

    def test_garbage_values(self):
        path = self.csv("CAM-001,xx,1.2.3.999,y,99999,TCP,nan,inf,-5,1e999\nCAM-001,2026,<script>,,-1,TCP,40,40,,\n"
                        "CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,'; DROP TABLE incidents;--,50,,\n")
        code, out, err = self.run_events(path)
        self.assertIn(code, (0, 2), out + err)
        self.assertNotIn("Traceback", err)
        for r in self.rows():
            self.assertIn(r["risk_level"], dbmod.LEVELS)

    def test_untrusted_text_is_not_echoed(self):
        marker = "EVIL_MARKER_123"
        path = self.csv("%s,2026-10-20T08:00:00Z,%s,%s,22,TCP,50,50,,\n" % (marker, marker, marker))
        code, out, err = self.run_events(path)
        self.assertNotIn(marker, out + err)

    def test_extra_fields_row_rejected_not_fatal(self):
        path = self.csv("CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,50,50,,,EXTRA,EXTRA\n"
                        "CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,50,50,,\n")
        code, out, _ = self.run_events(path)
        self.assertEqual(code, 2)
        self.assertIn("too_many_fields", out)
        self.assertEqual(len(self.rows()), 1)

    def test_file_level_problems(self):
        empty = os.path.join(self.tmp.name, "empty.csv")
        open(empty, "w").close()
        for path, text in ((empty, "empty"), (os.path.join(self.tmp.name, "nope.csv"), "cannot read")):
            code, _o, err = self.run_events(path)
            self.assertEqual(code, 2)
            self.assertIn(text, err)
        dup = self.csv("", header="device_id,Device_ID\n")
        self.assertEqual(self.run_events(dup)[0], 2)
        weird = self.csv("", header="device_id,<script>\n")
        self.assertEqual(self.run_events(weird)[0], 2)
        binary = os.path.join(self.tmp.name, "b.csv")
        with open(binary, "wb") as f:
            f.write(b"device_id\n\xff\xfe\x00\x01\n")
        self.assertEqual(self.run_events(binary)[0], 2)

    def test_row_limit(self):
        body = "CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,50,50,,\n" * 10
        code, out, _ = self.run_events(self.csv(body), "--max-rows", "3", "--group-window", "0")
        self.assertIn("row limit", out)
        self.assertEqual(len(self.rows()), 3)

    def test_incident_limit(self):
        body = "CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,50,50,,\n" * 5
        code, out, _ = self.run_events(self.csv(body), "--max-incidents", "2", "--group-window", "0")
        self.assertEqual(len(self.rows()), 2)
        self.assertEqual(code, 2)
        self.assertIn("incident_limit_reached", out)

    def test_bad_cli_numbers(self):
        for v in ("0", "-1", "99999999999"):
            self.assertEqual(self.run_cli("run", SAMPLE, "--max-rows", v)[0], 2)

    def test_missing_database_for_show_and_verify(self):
        self.assertEqual(self.run_cli("show", "--db", os.path.join(self.tmp.name, "none.db"))[0], 2)
        self.assertEqual(self.run_cli("verify", "--db", os.path.join(self.tmp.name, "none.db"))[0], 2)

    def test_show_bad_filters(self):
        self.run_events(SAMPLE)
        self.assertEqual(self.run_cli("show", "--db", self.db_path, "--level", "x'--")[0], 2)
        self.assertEqual(self.run_cli("show", "--db", self.db_path, "--full", "1;DROP")[0], 2)
        self.assertEqual(self.run_cli("show", "--db", self.db_path, "--full", "INC-99999")[0], 2)

    def test_tampering_found_by_verify_command(self):
        import sqlite3
        self.run_events(SAMPLE)
        con = sqlite3.connect(self.db_path)
        con.execute("UPDATE incidents SET risk_level='Low' WHERE id=5")
        con.commit()
        con.close()
        code, out, _ = self.run_cli("verify", "--db", self.db_path)
        self.assertEqual(code, 1)
        self.assertIn("TAMPERING", out)

    def test_no_devices_file_uses_cautious_defaults(self):
        code, out, err = self.run_cli("run", SAMPLE, "--db", self.db_path, "--devices", os.path.join(self.tmp.name, "none.json"),
                                      "--action-log", self.log, "--reset")
        self.assertEqual(code, 0, err)
        self.assertIn("not found", out)
        self.assertTrue(self.rows())


class TestModuleFailures(Base):
    def make(self, **overrides):
        modules = rp.Modules(use_placeholder_detector=True)
        for k, v in overrides.items():
            setattr(modules, k, v)
        policy_cfg = modules.policy.load_policy()
        database = dbmod.IncidentDB(":memory:")
        self.addCleanup(database.close)
        executor = modules.actions.ActionExecutor.from_policy(policy_cfg, log_path=self.log)
        return rp.Pipeline(database, modules, rp.load_devices(DEVICES), executor, policy_cfg), database

    EVENT = {"device_id": "CAM-001", "timestamp": "2026-10-20T08:00:00Z", "src_ip": "203.0.113.5",
             "dst_ip": "192.168.1.50", "dst_port": "22", "failed_attempts": "50", "connection_attempts": "50"}

    def test_detector_crash_is_contained(self):
        def boom(_e):
            raise RuntimeError("secret detail")
        pipeline, database = self.make(detect=boom)
        res = pipeline.process_event(self.EVENT)
        self.assertEqual(res["outcome"], "error")
        self.assertNotIn("secret", res["error"])
        self.assertEqual(database.count(), 0)

    def test_detector_bad_output_is_contained(self):
        for bad in (None, "ATTACK", {"label": "MAYBE"}, {"label": 5}, []):
            pipeline, _d = self.make(detect=lambda e, b=bad: b)
            self.assertEqual(pipeline.process_event(self.EVENT)["error"], "detector_invalid_output")

    def test_report_crash_does_not_lose_the_incident(self):
        def boom(_i):
            raise RuntimeError("x")
        pipeline, database = self.make(make_report=boom)
        self.assertEqual(pipeline.process_event(self.EVENT)["outcome"], "incident")
        self.assertEqual(database.count(), 1)

    def test_non_mapping_event(self):
        pipeline, _d = self.make()
        for bad in (None, 5, "x", [1]):
            self.assertEqual(pipeline.process_event(bad)["outcome"], "rejected")

    def test_attack_without_create_incident_is_not_stored(self):
        pipeline, database = self.make()
        original = pipeline.m.policy.decide
        pipeline.m.policy = type("P", (), {"decide": staticmethod(lambda *a, **k: dict(original(*a, **k), action=["log"])),
                                          "PolicyConfigError": pipeline.m.policy.PolicyConfigError})
        res = pipeline.process_event(self.EVENT)
        self.assertEqual(res["outcome"], "no_incident")
        self.assertEqual(database.count(), 0)

class TestReportsInTheDatabase(Base):
    def setUp(self):
        super().setUp()

    def test_reports_stored_and_notification_only_for_high_and_critical(self):
        self.run_events(SAMPLE)
        with dbmod.IncidentDB(self.db_path) as d:
            for inc in d.query_incidents(limit=100, include_reports=True):
                self.assertTrue(inc["report_technical"] and inc["report_plain"])
                self.assertIn(inc["incident_id"], inc["report_technical"])
                if inc["risk_level"] in ("High", "Critical"):
                    self.assertTrue(inc["report_notification"], inc["incident_id"])
                else:
                    self.assertIsNone(inc["report_notification"])

    def test_report_score_matches_database_score(self):
        self.run_events(SAMPLE)
        with dbmod.IncidentDB(self.db_path) as d:
            for inc in d.query_incidents(limit=100, include_reports=True):
                self.assertIn("%d/100" % inc["risk_score"], inc["report_plain"] + inc["report_technical"])

    def test_report_status_matches_database_status(self):
        self.run_events(SAMPLE)
        with dbmod.IncidentDB(self.db_path) as d:
            crit = d.query_incidents(level="Critical", include_reports=True)[0]
        self.assertIn("Status: Open", crit["report_notification"])
        self.assertNotIn("Status: Contained", crit["report_notification"])

    def test_csv_text_cannot_become_a_markdown_link_in_a_report(self):
        evil = "[click here](http://evil.example) <img src=x>"
        path = self.csv('CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,"%s",50,50,,\n' % evil)
        self.assertEqual(self.run_events(path)[0], 0)
        with dbmod.IncidentDB(self.db_path) as d:
            inc = d.get_incident("INC-00001")
        text = inc["report_technical"] + inc["report_plain"] + (inc["report_notification"] or "")
        for bad in ("evil", "<img", "]("):
            self.assertNotIn(bad, text)

    def test_attempt_count_reaches_the_report(self):
        path = self.csv("CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,50,50,,\n")
        self.run_events(path)
        with dbmod.IncidentDB(self.db_path) as d:
            self.assertIn("50", d.get_incident("INC-00001")["report_technical"])

    def test_report_survives_missing_numbers(self):
        r = reportmod.make_report({"id": "INC-00001", "score": None, "confidence": None, "level": None,
                                    "attack_type": None, "actions": None, "factors": None,
                                    "skipped": None, "warnings": None, "commands": None})
        self.assertTrue(r["technical"] and r["executive"])

    def test_report_shows_the_duration_when_the_csv_has_one(self):
        header = "device_id,timestamp,src_ip,dst_ip,dst_port,protocol,failed_attempts,connection_attempts,duration\n"
        path = self.csv("CAM-001,2026-10-20T08:00:00Z,203.0.113.5,192.168.1.50,22,TCP,50,50,4 minutes\n", header)
        self.run_events(path)
        with dbmod.IncidentDB(self.db_path) as d:
            self.assertIn("4 minutes", d.get_incident("INC-00001")["report_technical"])

    def test_no_incident_is_marked_contained(self):
        self.run_events(SAMPLE)
        self.assertNotIn("contained", [r["status"] for r in self.rows()])


class TestRuleDetectorOnSampleEvents(Base):
    """The 14 sample events (data/sample_events.csv) through the rule-based detector."""

    def setUp(self):
        super().setUp()
        # --group-window 0: one incident per event, so every sample event can be checked on its own
        self.assertEqual(self.run_cli("run", P2_SAMPLE, "--db", self.db_path, "--devices", DEVICES,
                                      "--action-log", self.log, "--reset", "--group-window", "0")[0], 0)

    def outcomes(self):
        import csv
        with open(P2_SAMPLE, encoding="utf-8", newline="") as handle:
            expected = {r["event_id"]: r["expected_label"] for r in csv.DictReader(handle)}
        with dbmod.IncidentDB(self.db_path) as d:
            stored = {i["timestamp"] for i in d.query_incidents(limit=100)}
        with open(P2_SAMPLE, encoding="utf-8", newline="") as handle:
            return {r["event_id"]: (expected[r["event_id"]], r["timestamp"] in stored) for r in csv.DictReader(handle)}

    def test_no_false_alarms_on_the_benign_events(self):
        false_alarms = [e for e, (label, stored) in self.outcomes().items() if label == "BENIGN" and stored]
        self.assertEqual(false_alarms, [])

    def test_known_misses_are_exactly_the_payload_level_attacks(self):
        # web attacks inside normal-looking HTTP flows are invisible to threshold rules; the ML model should cover them
        missed = sorted(e for e, (label, stored) in self.outcomes().items() if label == "ATTACK" and not stored)
        self.assertEqual(missed, ["EVT-007", "EVT-012", "EVT-013"])

    def test_the_thousand_port_probe_is_a_port_scan(self):
        by_time = {i["timestamp"]: i for i in self.rows()}
        self.assertEqual(by_time["2026-10-21T09:03:00Z"]["attack_type"], "port_scan")

    def test_seven_of_ten_attacks_become_incidents(self):
        # EVT-012 (a fake camera upload with 3 connections) is no longer a DoS: a rate alone is not enough
        self.assertEqual(len(self.rows()), 7)

    def test_incidents_never_exceed_what_the_policy_allows(self):
        for inc in self.rows():
            self.assertIn(inc["risk_level"], dbmod.LEVELS)
            self.assertTrue(inc["dry_run"])


class TestDevicesFile(Base):
    def write(self, text):
        p = os.path.join(self.tmp.name, "d.json")
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def test_loads_sample(self):
        devices = rp.load_devices(DEVICES)
        self.assertEqual(devices["CAM-001"]["criticality"], "high")
        self.assertEqual(devices["CAM-001"]["expected_ports"], [554, 443, 53, 123])

    def test_invalid_things_are_dropped_or_refused(self):
        devs = rp.load_devices(self.write('[{"device_id":"A","ip":"999","criticality":"galactic","expected_ports":[1,"x",true,70000]},'
                                          '{"device_id":"bad id!"}, 5]'))
        self.assertEqual(list(devs), ["A"])
        self.assertIsNone(devs["A"]["ip"])
        self.assertIsNone(devs["A"]["criticality"])
        self.assertEqual(devs["A"]["expected_ports"], [1])
        for text in ("not json", "5", "[NaN]", '[{"device_id":"A"},{"device_id":"A"}]', "[" * 100000):
            with self.assertRaises(rp.PipelineError, msg=text[:20]):
                rp.load_devices(self.write(text))


class TestModulesAndKey(Base):
    def test_db_key_rules(self):
        old = os.environ.get("IOTIPS_DB_KEY")
        self.addCleanup(lambda: os.environ.__setitem__("IOTIPS_DB_KEY", old) if old else os.environ.pop("IOTIPS_DB_KEY", None))
        os.environ.pop("IOTIPS_DB_KEY", None)
        self.assertIsNone(rp.db_key_from_env())
        os.environ["IOTIPS_DB_KEY"] = "short"
        with self.assertRaises(rp.PipelineError):
            rp.db_key_from_env()
        os.environ["IOTIPS_DB_KEY"] = "a" * 24
        self.assertEqual(len(rp.db_key_from_env()), 24)

    def test_keyed_run_then_wrong_mode_refused(self):
        old = os.environ.get("IOTIPS_DB_KEY")
        self.addCleanup(lambda: os.environ.__setitem__("IOTIPS_DB_KEY", old) if old else os.environ.pop("IOTIPS_DB_KEY", None))
        os.environ["IOTIPS_DB_KEY"] = "k" * 32
        self.assertEqual(self.run_events(SAMPLE)[0], 0)
        self.assertEqual(self.run_cli("verify", "--db", self.db_path)[0], 0)
        os.environ.pop("IOTIPS_DB_KEY")
        self.assertEqual(self.run_cli("verify", "--db", self.db_path)[0], 2)

    def test_source_has_no_subprocess_or_network(self):
        for name in ("pipeline.py", "db.py", "placeholders.py"):
            with open(os.path.join(PACKAGE_DIR, name), encoding="utf-8") as fh:
                text = fh.read()
            for word in ("subprocess", "import socket", "os.system", "eval(", "exec(", "pickle", "shell=True"):
                self.assertNotIn(word, text, "%s contains %s" % (name, word))


if __name__ == "__main__":
    unittest.main()



# ---------------------------------------------------------------------------
# Review fixes: grouping, save-before-act, loud configuration errors, report labels
# ---------------------------------------------------------------------------
from unittest import mock

from iot_ips import detector as detectormod


class TestGrouping(Base):
    def setUp(self):
        super().setUp()

    def run_sample(self, *extra):
        return self.run_cli("run", P2_SAMPLE, "--db", self.db_path, "--devices", DEVICES, "--action-log", self.log,
                            "--reset", *extra)

    def test_default_run_groups_repeated_events_of_one_attack(self):
        self.assertEqual(self.run_sample()[0], 0)
        rows = self.rows()
        self.assertEqual(len(rows), 6)                      # 7 detected attacks, two DoS floods from one source
        flood = [r for r in rows if r["event_count"] == 2]
        self.assertEqual(len(flood), 1)
        self.assertEqual(flood[0]["attack_type"], "dos")
        self.assertEqual((flood[0]["first_seen"], flood[0]["last_seen"]), ("2026-10-21T09:06:45Z", "2026-10-21T09:07:30Z"))
        self.assertEqual(flood[0]["risk_score"], max(r["risk_score"] for r in flood))

    def test_the_grouped_incident_keeps_the_highest_score_and_says_how_many_events(self):
        self.run_sample()
        with dbmod.IncidentDB(self.db_path) as d:
            incident = [i for i in d.query_incidents(limit=100, include_reports=True) if i["event_count"] == 2][0]
        self.assertIn("Repeated events in this incident | 2", incident["report_technical"])

    def test_group_window_zero_disables_grouping(self):
        self.run_sample("--group-window", "0")
        self.assertEqual(len(self.rows()), 7)
        self.assertTrue(all(r["event_count"] == 1 for r in self.rows()))

    def test_summary_reports_grouped_events(self):
        code, out, _ = self.run_sample()
        self.assertIn("incidents stored: 6 (1 repeated events grouped into them)", out)

    def event_rows(self, *rows):
        return self.csv("".join(rows))

    BF = "CAM-001,%s,%s,192.168.1.50,22,TCP,%d,%d,,\n"

    def test_events_far_apart_are_separate_incidents(self):
        path = self.event_rows(self.BF % ("2026-10-20T08:00:00Z", "203.0.113.5", 60, 60),
                               self.BF % ("2026-10-20T08:02:00Z", "203.0.113.5", 70, 70),
                               self.BF % ("2026-10-20T09:30:00Z", "203.0.113.5", 80, 80))
        self.run_events(path)
        self.assertEqual(sorted(r["event_count"] for r in self.rows()), [1, 2])

    def test_different_sources_are_never_grouped(self):
        path = self.event_rows(self.BF % ("2026-10-20T08:00:00Z", "203.0.113.5", 60, 60),
                               self.BF % ("2026-10-20T08:00:10Z", "203.0.113.6", 60, 60))
        self.run_events(path)
        self.assertEqual(len(self.rows()), 2)

    def test_events_without_a_usable_time_or_source_are_not_grouped(self):
        path = self.event_rows(self.BF % ("not-a-time", "203.0.113.5", 60, 60), self.BF % ("not-a-time", "203.0.113.5", 60, 60),
                               self.BF % ("2026-10-20T08:00:00Z", "", 60, 60), self.BF % ("2026-10-20T08:00:05Z", "", 60, 60))
        self.run_events(path)
        self.assertEqual(len(self.rows()), 4)

    def test_grouped_incident_counts_the_largest_attempt_number(self):
        path = self.event_rows(self.BF % ("2026-10-20T08:00:00Z", "203.0.113.5", 60, 60),
                               self.BF % ("2026-10-20T08:01:00Z", "203.0.113.5", 300, 300))
        self.run_events(path)
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["attempts"], rows[0]["event_count"]), (300, 2))


class _SpyExecutor:
    """Wraps the real executor and remembers how many incidents were stored when each action ran."""

    def __init__(self, real, database):
        self.real, self.db, self.seen = real, database, []

    def run(self, decision):
        self.seen.append(self.db.count())
        return self.real.run(decision)


class TestSaveBeforeAct(Base):
    def make(self, **kw):
        modules = rp.Modules(use_placeholder_detector=True)
        policy_cfg = modules.policy.load_policy()
        database = dbmod.IncidentDB(":memory:")
        self.addCleanup(database.close)
        real = modules.actions.ActionExecutor.from_policy(policy_cfg, log_path=self.log)
        spy = _SpyExecutor(real, database)
        return rp.Pipeline(database, modules, rp.load_devices(DEVICES), spy, policy_cfg, **kw), database, spy

    EVENT = {"device_id": "CAM-001", "timestamp": "2026-10-20T08:00:00Z", "src_ip": "203.0.113.5", "dst_ip": "192.168.1.50",
             "dst_port": "22", "protocol": "TCP", "failed_attempts": "400", "connection_attempts": "400"}

    def test_the_incident_exists_before_the_actions_run(self):
        pipeline, database, spy = self.make()
        result = pipeline.process_event(dict(self.EVENT), 1)
        self.assertEqual(result["outcome"], "incident")
        self.assertEqual(spy.seen, [1])          # the incident was already stored when the executor ran

    def test_the_action_outcome_is_written_after_the_actions_ran(self):
        pipeline, database, _ = self.make()
        pipeline.process_event(dict(self.EVENT), 1)
        stored = database.get_incident(1)
        self.assertFalse(any(":planned:" in r for r in stored["action_result"]), stored["action_result"])
        self.assertTrue(any(":simulated:" in r for r in stored["action_result"]), stored["action_result"])
        self.assertTrue(database.verify_chain()["ok"])

    def test_nothing_is_blocked_when_the_incident_cannot_be_saved(self):
        pipeline, database, spy = self.make(max_incidents=0)
        result = pipeline.process_event(dict(self.EVENT), 1)
        self.assertEqual((result["outcome"], result["error"]), ("error", "incident_limit_reached"))
        self.assertEqual(spy.seen, [])           # no record, no block

    def test_a_crashing_executor_keeps_the_incident_and_says_so(self):
        pipeline, database, spy = self.make()
        pipeline.executor = mock.Mock(run=mock.Mock(side_effect=RuntimeError("boom")))
        result = pipeline.process_event(dict(self.EVENT), 1)
        self.assertEqual(result["outcome"], "incident")
        self.assertTrue(result["error"].startswith("actions_failed"))
        self.assertTrue(all(":failed:" in r for r in database.get_incident(1)["action_result"]))


class TestLoudConfigurationErrors(Base):
    def test_a_bad_rules_file_stops_the_run_with_a_clear_error(self):
        with mock.patch.object(detectormod, "load_config", side_effect=detectormod.DetectorConfigError("rule dos: missing keys ['min_rate']")):
            code, out, err = self.run_cli("run", P2_SAMPLE, "--db", self.db_path, "--devices", DEVICES,
                                          "--action-log", self.log, "--reset")
        self.assertEqual(code, 2)
        self.assertIn("configuration problem", err)
        self.assertIn("min_rate", err)


class TestReportsFromThePipeline(Base):
    def setUp(self):
        super().setUp()
        self.assertEqual(self.run_cli("run", P2_SAMPLE, "--db", self.db_path, "--devices", DEVICES, "--action-log", self.log,
                                      "--reset", "--group-window", "0")[0], 0)

    def reports(self):
        with dbmod.IncidentDB(self.db_path) as d:
            return d.query_incidents(limit=100, include_reports=True)

    def test_no_report_says_see_risk_factors(self):
        for incident in self.reports():
            self.assertNotIn("see risk factors", incident["report_technical"])

    def test_the_source_label_comes_from_the_risk_engine(self):
        by_src = {}
        for incident in self.reports():
            by_src.setdefault(incident["src_ip"], incident["report_technical"])
        self.assertIn("203.0.113.45 (external, outside the network)", by_src["203.0.113.45"])
        self.assertIn("192.168.1.66 (internal, not a known device)", by_src["192.168.1.66"])

    def test_a_trusted_source_is_labelled_trusted(self):
        text = reportmod.technical_report(reportmod.build_incident(
            {"src_ip": "192.168.1.10", "dst_ip": "192.168.1.50", "dst_port": 22},
            {"attack_type": "brute_force", "confidence": 0.9},
            {"score": 70, "level": "High", "factors": {"source_trust": {"value": 20, "weight": 0.1, "contribution": 2, "detail": "trusted_internal"}}},
            {"action": ["notify_admin"]}, {"device_id": "CAM-001"}))
        self.assertIn("192.168.1.10 (trusted internal device)", text)

    def test_text_in_the_risk_detail_cannot_reach_the_label(self):
        text = reportmod.technical_report(reportmod.build_incident(
            {"src_ip": "1.2.3.4"}, {"attack_type": "brute_force", "confidence": 0.9},
            {"score": 70, "level": "High", "factors": {"source_trust": {"detail": "<script>alert(1)</script>"}}},
            {"action": ["notify_admin"]}, {"device_id": "CAM-001"}))
        self.assertNotIn("<script>", text)
        self.assertIn("1.2.3.4 (unknown)", text)

    def test_unexpected_traffic_is_tagged_t1571(self):
        text = reportmod.technical_report(reportmod.build_incident(
            {"src_ip": "203.0.113.45", "dst_port": 8080}, {"attack_type": "Unexpected Protocol/Port", "confidence": 0.6},
            {"score": 56, "level": "Medium", "factors": {}}, {"action": ["notify_admin"]}, {"device_id": "CAM-001"}))
        self.assertIn("T1571 Non-Standard Port", text)
        self.assertIn("attack.mitre.org/techniques/T1571/", text)
        self.assertNotIn("T1071", text)


class TestDemoUsesTheRealDetector(unittest.TestCase):
    def test_run_demo_refuses_the_placeholder(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("run_demo_under_test", os.path.join(os.path.dirname(HERE), "run_demo.py"))
        demo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(demo)
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with mock.patch.object(demo, "ROOT", __import__("pathlib").Path(tmp)):
                (__import__("pathlib").Path(tmp) / "data").mkdir()
                import shutil
                shutil.copy(P2_SAMPLE, os.path.join(tmp, "data", "sample_events.csv"))
                self.assertEqual(demo.main(), 0)
        self.assertIn("detector=rules", out.getvalue())
        self.assertNotIn("placeholder", out.getvalue())

    def test_run_demo_fails_when_the_placeholder_detector_was_used(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("run_demo_under_test2", os.path.join(os.path.dirname(HERE), "run_demo.py"))
        demo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(demo)

        def fake_main(step):
            print("  modules      : detector=placeholder, report=templates")
            return 0
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(demo.pipeline, "main", fake_main), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(demo.main(), 1)
        self.assertIn("placeholder detector", err.getvalue())
