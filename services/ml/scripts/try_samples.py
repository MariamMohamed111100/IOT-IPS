"""Run detect() on the 14 demo events and write samples_result.md.

    python scripts/try_samples.py      # reads ips/data/sample_events.csv
"""
from pathlib import Path

import pandas as pd

from ids_ml.detector import detect

HERE = Path(__file__).resolve().parents[1]                 # services/ml
EVENTS = HERE.parents[1] / "ips" / "data" / "sample_events.csv"


def main() -> None:
    lines = ["# detect() on the 14 demo events", "",
             ("Each event is a real test row (never seen in training). `Right` = label and attack "
              "type both match."), "",
             "| Event | Story | Expected | Got | Confidence | MITRE | Right |",
             "|---|---|---|---|---|---|---|"]
    right = 0
    for e in pd.read_csv(EVENTS).to_dict("records"):
        d = detect(e)
        ok = d["label"] == e["expected_label"] and \
            (d["attack_type"] or "Benign") == e["expected_attack_type"]
        right += ok
        got = d["label"] + (f" ({d['attack_type']})" if d["attack_type"] else "")
        lines.append(f"| {e['event_id']} | {e['story']} | {e['expected_label']} "
                     f"({e['expected_attack_type']}) | {got} | {d['confidence']:.2f} | "
                     f"{d['mitre_technique'] or '-'} | {'yes' if ok else 'NO'} |")
        print(f"{e['event_id']}  expected {e['expected_label']:<6} {e['expected_attack_type']:<10}"
              f"  got {got:<22} {d['confidence']:.2f}  {'ok' if ok else 'WRONG'}")
    lines += ["", f"**{right} of 14 fully right.**"]
    (HERE / "evidence" / "samples_result.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{right} of 14 fully right -> samples_result.md")


if __name__ == "__main__":
    main()
