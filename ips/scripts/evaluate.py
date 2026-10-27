#!/usr/bin/env python3
"""evaluate.py - runs data/sample_events.csv through the real pipeline and checks every event
against data/expected_results.csv (the ground truth written by hand).

    python scripts/evaluate.py

Prints one line per event, then precision, recall and F1.
Exit code 0 = every event behaved as expected, 1 = at least one differs, 2 = the pipeline could not run.
Incidents are not grouped here (group window 0), so one attack event is one incident.
"""
import contextlib
import csv
import io
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from iot_ips import db as dbmod  # noqa: E402
from iot_ips import pipeline  # noqa: E402

EVENTS = os.path.join(ROOT, "data", "sample_events.csv")
EXPECTED = os.path.join(ROOT, "data", "expected_results.csv")
DEVICES = os.path.join(ROOT, "config", "devices.json")


def main() -> int:
    with open(EVENTS, newline="", encoding="utf-8-sig") as f:
        events = list(csv.DictReader(f))
    with open(EXPECTED, newline="", encoding="utf-8-sig") as f:
        expected = {r["event_id"]: r for r in csv.DictReader(f)}
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "eval.db")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = pipeline.main(["run", EVENTS, "--db", db_path, "--action-log", os.path.join(tmp, "a.jsonl"),
                                      "--devices", DEVICES, "--reset", "--group-window", "0"])
            except SystemExit as exc:
                code = exc.code
        if code != 0:
            print("error: the pipeline did not run cleanly:\n" + out.getvalue() + err.getvalue())
            return 2
        if "detector=rules" not in out.getvalue():
            print("error: the real rule-based detector was not used:\n" + out.getvalue())
            return 2
        with dbmod.IncidentDB(db_path) as database:
            incidents = {(r["timestamp"], r["src_ip"]): r for r in database.query_incidents(limit=1000)}
    tp = fp = fn = tn = differs = 0
    print("%-8s %-6s %-10s %-9s %-12s %s" % ("event", "truth", "expected", "got", "attack", "verdict"))
    for e in events:
        exp = expected[e["event_id"]]
        inc = incidents.get((e["timestamp"], e["src_ip"]))
        alarm = inc is not None
        allowed = {w.strip() for w in re.split(r"\bor\b", exp["expected_level"]) if w.strip() and w.strip() != "none"}
        ok = (alarm == (exp["expected_incident"] == "yes")) and (not alarm or not allowed or inc["risk_level"] in allowed)
        attack = exp["ground_truth"] == "ATTACK"
        tp, fp, fn, tn = tp + (attack and alarm), fp + ((not attack) and alarm), fn + (attack and not alarm), tn + ((not attack) and not alarm)
        differs += not ok
        print("%-8s %-6s %-10s %-9s %-12s %s" % (e["event_id"], exp["ground_truth"][:6], (exp["expected_level"] or "-")[:10],
              inc["risk_level"] if alarm else "-", (inc["attack_type"] if alarm else "-")[:12], "ok" if ok else "DIFFERS"))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    print("\nattacks detected %d of %d, false alarms %d of %d benign events" % (tp, tp + fn, fp, fp + tn))
    print("precision %.2f   recall %.2f   F1 %.2f" % (precision, recall, f1))
    print("behaved as expected: %d of %d events" % (len(events) - differs, len(events)))
    return 0 if differs == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
