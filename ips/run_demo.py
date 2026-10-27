#!/usr/bin/env python3
"""One command for the whole demo:  python run_demo.py

Runs data/sample_events.csv through the pipeline into output/incidents.db, prints the stored
incidents with a count by level, then verifies the incident database. Nothing here touches a
real firewall.
"""
import contextlib
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
try:
    import iot_ips  # noqa: F401  (installed with: pip install -e .)
except ImportError:
    sys.path.insert(0, str(ROOT / "src"))

from iot_ips import pipeline  # noqa: E402


def main() -> int:
    db = str(ROOT / "output" / "incidents.db")
    steps = [
        ["run", str(ROOT / "data" / "sample_events.csv"), "--db", db, "--reset"],
        ["show", "--db", db],
        ["verify", "--db", db],
    ]
    status = 0
    for step in steps:
        print("\n$ iot-ips " + step[0] + "\n")
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            code = pipeline.main(step)
        text = captured.getvalue()
        print(text, end="")
        status = max(status, code)
        # The demo must run the REAL rule-based detector. The placeholder is for unit tests only;
        # a demo that silently used it would show results that mean nothing.
        if "detector=placeholder" in text:
            print("error: the demo ran with the placeholder detector", file=sys.stderr)
            status = max(status, 1)
    return status


if __name__ == "__main__":
    sys.exit(main())
