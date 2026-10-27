"""make_samples.py - build the sample reports from REAL pipeline output.

    python scripts/make_samples.py

Runs the pipeline on the sample events, then takes one stored incident per level (the highest
score of that level) and writes its technical report, its executive report and (High/Critical)
its notification into examples/sample_reports/. The reports are exactly what the pipeline stored
in the incident database.

The 14 sample events (data/sample_events.csv) hold no Low incident, so a missing level is taken
from the pipeline's own test events (tests/fixtures, threshold stand-in detector); the source of
every sample is printed.
"""
import json
import os
import sys
import tempfile
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    import iot_ips  # noqa: F401  (installed with: pip install -e .)
except ImportError:
    sys.path.insert(0, str(ROOT / "src"))

from iot_ips import db as dbmod  # noqa: E402
from iot_ips import pipeline  # noqa: E402
from iot_ips.paths import DATA_DIR, DEFAULT_DEVICES_PATH, EXAMPLES_DIR  # noqa: E402

warnings.simplefilter("ignore")
LEVELS = ("Low", "Medium", "High", "Critical")
SOURCES = [(DATA_DIR / "sample_events.csv", "auto"),
           (ROOT / "tests" / "fixtures" / "pipeline_test_events.csv", "placeholder")]


def main():
    data = json.loads(DEFAULT_DEVICES_PATH.read_text(encoding="utf-8"))
    known = {d["device_id"] for d in (data["devices"] if isinstance(data, dict) else data)}   # real devices only, not rows with a missing device
    out = EXAMPLES_DIR / "sample_reports"
    out.mkdir(parents=True, exist_ok=True)
    for old in out.iterdir():
        if old.is_file():
            old.unlink()
    pools = []
    with tempfile.TemporaryDirectory() as tmp:
        for events, detector in SOURCES:
            dbfile, log = os.path.join(tmp, events.name + ".db"), os.path.join(tmp, events.name + ".jsonl")
            code = pipeline.main(["run", str(events), "--db", dbfile, "--action-log", log,
                                  "--devices", str(DEFAULT_DEVICES_PATH), "--reset", "--detector", detector])
            if code not in (0, 2):
                sys.exit("pipeline failed with status %s" % code)
            with dbmod.IncidentDB(dbfile) as database:
                pools.append((events.name, [r for r in database.query_incidents(limit=1000, include_reports=True)
                                            if r.get("report_technical") and r.get("device_id") in known]))
    for level in LEVELS:
        found = [(name, r) for name, rows in pools for r in rows if r["risk_level"] == level]
        if not found:
            print("no %s incident in any pipeline output" % level)
            continue
        name = found[0][0]
        inc = max((r for n, r in found if n == name), key=lambda r: r["risk_score"])
        tag = "%s_%s" % (inc.get("incident_id") or "INC-%05d" % inc["id"], level.lower())
        (out / (tag + "_technical.md")).write_text(inc["report_technical"], encoding="utf-8", newline="\n")
        (out / (tag + "_executive.md")).write_text(inc["report_plain"], encoding="utf-8", newline="\n")
        if inc.get("report_notification"):
            (out / (tag + "_notification.txt")).write_text(inc["report_notification"], encoding="utf-8", newline="\n")
        print("wrote", tag, "score", inc["risk_score"], "from", name)


if __name__ == "__main__":
    main()
