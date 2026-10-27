"""
calibrate.py - how many false alarms does normal traffic cause? (Task 7, Person 4)

    python scripts/calibrate.py                       # 5 seeds x 24 h of generated camera traffic
    python scripts/calibrate.py --hours 24 --seeds 1,2,3
    python scripts/calibrate.py --events lab_benign.csv --hours 3   # replay REAL benign lab traffic instead

Every event goes through the real detector, risk engine and policy (the same calls the pipeline
makes; nothing is stored and no action is executed) and the script prints Markdown tables:

  1. alerts per hour on normal traffic, by rule, level and traffic kind
  2. which alerts would have blocked something (the false alarms that matter)
  3. headroom: how far normal traffic stays from each threshold
  4. sweep of the DoS Rate threshold: false alarms per day vs attacks caught (14 sample events)
  5. sensitivity: what if the Rate of normal traffic has a heavier tail than assumed
  6. the three weight sets on the false alarms of a stress run

The generated traffic is an assumption (see src/iot_ips/baseline.py), so absolute numbers are
only as good as the assumptions. The point of 3-5 is to show how fragile each rule is. Feed it
real benign lab traffic with --events as soon as Task 8 can record some.
"""

from __future__ import annotations

import argparse
import copy
import os
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    import iot_ips  # noqa: F401  (installed with: pip install -e .)
except ImportError:
    sys.path.insert(0, str(ROOT / "src"))

import yaml  # noqa: E402

from iot_ips import baseline, detector, policy, risk  # noqa: E402
from iot_ips.paths import DATA_DIR, DEFAULT_DEVICES_PATH  # noqa: E402
from iot_ips.pipeline import load_devices, read_events  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError, OSError):
    pass

DISRUPTIVE = ("block_source", "isolate_device", "temporary_block")
LEVELS = risk.LEVELS


# --------------------------------------------------------------------------- running events
def evaluate(events, devices, policy_cfg, *, detector_config=None, weight_set=None):
    """detect -> risk -> policy for every event. Returns one record per event."""
    config_path = detector_config or detector.DEFAULT_CONFIG
    records = []
    for event in events:
        # The pipeline reads CSV text, so the detector gets strings; do the same here.
        row = {k: ("" if v is None else str(v)) for k, v in event.items()}
        profile = dict(devices.get(row.get("device_id"), {}))
        detection = detector.detect(dict(row), profile or None, config_path)
        rec = {"event": event, "alert": detection["label"] == "ATTACK", "attack_type": None, "level": None,
               "score": None, "actions": [], "confidence": detection.get("confidence"),
               "kind": event.get("traffic_kind")}
        if rec["alert"]:
            msg = risk.assess(detection, row, profile, weight_set=weight_set)
            decision = policy.decide(msg, detection, row, profile, policy=policy_cfg)
            rec.update(attack_type=detection["attack_type"], level=msg["level"], score=msg["score"],
                       actions=list(decision.get("action", [])))
        records.append(rec)
    return records


def disruptive(rec):
    return any(a in DISRUPTIVE for a in rec["actions"])


def notifies(rec):
    return "notify_admin" in rec["actions"]


def with_detector_overrides(overrides):
    """Write a copy of detector_rules.yaml with changed numbers; returns the temp file path."""
    with open(detector.DEFAULT_CONFIG, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    for (rule, key), value in overrides.items():
        cfg["rules"][rule][key] = value
    handle, path = tempfile.mkstemp(suffix=".yaml", prefix="calib_")
    with os.fdopen(handle, "w", encoding="utf-8") as fh:
        yaml.safe_dump(cfg, fh)
    return path


def with_ports(devices, device_id, ports):
    out = copy.deepcopy(devices)
    out[device_id]["expected_ports"] = list(ports)
    return out


def sample_events():
    path = DATA_DIR / "sample_events.csv"
    import csv
    labels = {}
    with open(path, "r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            labels[row["event_id"]] = row["expected_label"].strip().upper()
    events = [e for _, e, _ in read_events(str(path)) if e]
    return events, labels


def sample_score(devices, policy_cfg, detector_config=None):
    """Detections on the 14 sample events: (attacks caught, benign flagged, caught ids, flagged ids)."""
    events, labels = sample_events()
    recs = evaluate(events, devices, policy_cfg, detector_config=detector_config)
    caught = [r["event"]["event_id"] for r in recs if r["alert"] and labels[r["event"]["event_id"]] == "ATTACK"]
    flagged = [r["event"]["event_id"] for r in recs if r["alert"] and labels[r["event"]["event_id"]] == "BENIGN"]
    return caught, flagged, recs, labels


# --------------------------------------------------------------------------- tables
def md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def per_hour(count, hours):
    return "%.2f" % (count / hours) if hours else "n/a"


def section_alerts(records, hours, title):
    alerts = [r for r in records if r["alert"]]
    print("### %s\n" % title)
    print("%d events in %g hours (%.0f per hour); **%d alerts = %.2f per hour = %.1f per day**; "
          "%d of them would have blocked something and %d would have notified the admin.\n" % (
              len(records), hours, len(records) / hours, len(alerts), len(alerts) / hours, 24 * len(alerts) / hours,
              sum(disruptive(r) for r in alerts), sum(notifies(r) for r in alerts)))
    if not alerts:
        print("No alerts.\n")
        return
    rows = []
    for (attack, kind), n in sorted(Counter((r["attack_type"], r["kind"] or "-") for r in alerts).items()):
        levels = Counter(r["level"] for r in alerts if r["attack_type"] == attack and (r["kind"] or "-") == kind)
        group = [r for r in alerts if r["attack_type"] == attack and (r["kind"] or "-") == kind]
        rows.append((attack, kind, n, per_hour(n, hours), ", ".join("%s %d" % (lv, levels[lv]) for lv in LEVELS if levels[lv]),
                     sum(disruptive(r) for r in group), sum(notifies(r) for r in group)))
    print(md_table(("Rule that fired", "Traffic kind", "Alerts", "Per hour", "Levels", "Would block", "Admin notified"), rows))
    print()


def section_hourly(records, hours_per_seed, seeds):
    """Alerts per clock hour: how many hours were quiet, and the worst one."""
    counts = defaultdict(int)                       # (seed, hour index) -> alerts
    for r in records:
        if r["alert"]:
            counts[(r["seed"], int(r["event"]["timestamp"][11:13]), r["event"]["timestamp"][:10])] += 1
    total_hours = int(hours_per_seed) * len(seeds)
    quiet = total_hours - len(counts)
    worst = max(counts.values(), default=0)
    by_hour = Counter()
    for (_, hour, _), n in counts.items():
        by_hour[hour] += n
    print("%d of %d clock-hours had no alert at all; the worst single hour had %d alert(s)." % (quiet, total_hours, worst))
    if by_hour:
        print("Alerts by hour of day (all seeds): " + ", ".join("%02d:00 = %d" % kv for kv in sorted(by_hour.items())) + ".")
    print()


def section_headroom(records, devices, policy_cfg):
    caught, flagged, recs, labels = sample_score(devices, policy_cfg)
    with open(detector.DEFAULT_CONFIG, "r", encoding="utf-8") as fh:
        rules = yaml.safe_load(fh)["rules"]
    features = (("DoS", "Rate", rules["dos"]["min_rate"]), ("DoS", "syn_count", rules["dos"]["min_syn_count"]),
                ("Brute Force", "failed_attempts", rules["brute_force"]["min_failed_attempts"]),
                ("DoS", "connection_attempts", rules["dos"]["min_connection_attempts"]),
                ("Port Scan", "unique_dst_ports", rules["port_scan"]["min_unique_ports"]),
                ("Port Scan", "unique_dst_ips", rules["port_scan"]["min_unique_destinations"]))
    real_benign = [r["event"] for r in recs if labels[r["event"]["event_id"]] == "BENIGN"]
    rows = []
    for rule, feat, threshold in features:
        generated = max((float(r["event"][feat]) for r in records), default=0.0)
        real = max(float(e.get(feat) or 0) for e in real_benign)
        hits = [float(r["event"][feat]) for r in recs if r["alert"] and r["attack_type"] == rule
                and labels[r["event"]["event_id"]] == "ATTACK" and float(r["event"][feat] or 0) >= threshold]
        weakest = min(hits) if hits else None
        rows.append((rule, feat, "%g" % threshold, "%g (%d%%)" % (generated, round(100 * generated / threshold)),
                     "%g (%d%%)" % (real, round(100 * real / threshold)),
                     "%g (%d%%)" % (weakest, round(100 * weakest / threshold)) if weakest is not None else "none reaches it"))
    print(md_table(("Rule", "Feature", "Threshold", "Highest generated normal value (% of threshold)",
                    "Highest of the 4 real normal rows", "Weakest sample attack that reaches the threshold"), rows))
    print()


def section_dos_sweep(devices, policy_cfg, generated):
    rows = []
    for value in (1000, 1250, 1500, 1750, 2000, 2500, 3000, 4000):
        path = with_detector_overrides({("dos", "min_rate"): value})
        try:
            recs = evaluate(generated, devices, policy_cfg, detector_config=path)
            caught, flagged, srecs, slabels = sample_score(devices, policy_cfg, detector_config=path)
        finally:
            os.unlink(path)
        dos_alerts = sum(1 for r in recs if r["alert"] and r["attack_type"] == "DoS")
        as_dos = [r["event"]["event_id"] for r in srecs if r["alert"] and r["attack_type"] == "DoS"
                  and slabels[r["event"]["event_id"]] == "ATTACK"]
        rows.append((value, "%.1f" % (24 * dos_alerts / HOURS_TOTAL), "%d/10" % len(caught),
                     ", ".join(e[4:] for e in as_dos) or "-", ", ".join(flagged) or "-"))
    print(md_table(("min_rate", "False DoS alerts per day (generated)", "Sample attacks caught (any rule)",
                    "Sample attacks alerted as DoS (EVT-)", "Benign sample rows flagged"), rows))
    print()


def section_spread(devices, policy_cfg, seeds, hours):
    rows = []
    for spread in (0.5, 1.0, 1.5, 2.0, 3.0):
        recs = []
        for s in seeds:
            recs += evaluate(baseline.generate(hours, s, baseline.Assumptions(rate_spread=spread)), devices, policy_cfg)
        alerts = [r for r in recs if r["alert"]]
        rows.append(("x%g" % spread, "%.1f" % (24 * len(alerts) / (hours * len(seeds))),
                     "%.1f" % (24 * sum(disruptive(r) for r in alerts) / (hours * len(seeds))),
                     "%.1f" % (24 * sum(notifies(r) for r in alerts) / (hours * len(seeds))),
                     max((float(r["event"]["Rate"]) for r in recs), default=0)))
    print(md_table(("Spread of Rate (x the assumed sigma)", "Alerts per day", "Blocking alerts per day", "Admin notified per day", "Highest benign Rate"), rows))
    print()


def section_weights(devices, policy_cfg, seeds, hours):
    stress = []
    for s in seeds:
        stress += list(baseline.generate(hours, s, baseline.Assumptions(rate_spread=2.0)))
    base = with_ports(devices, "CAM-001", (554, 443))          # profile before the fix: DNS/NTP look unexpected
    cfg = risk.load_config()
    rows = []
    for name in cfg["weight_sets"]:
        recs = [r for r in evaluate(stress, base, policy_cfg, weight_set=name) if r["alert"]]
        levels = Counter(r["level"] for r in recs)
        scores = sorted(r["score"] for r in recs)
        rows.append((name + (" (active)" if name == cfg["active_weight_set"] else ""), len(recs),
                     ", ".join("%s %d" % (lv, levels[lv]) for lv in LEVELS if levels[lv]) or "-",
                     "%d-%d" % (scores[0], scores[-1]) if scores else "-", sum(disruptive(r) for r in recs)))
    print(md_table(("Weight set", "False alarms", "Levels", "Score range", "Would block"), rows))
    print()


def section_scores(devices, policy_cfg, seeds, hours):
    """Do false alarms score lower than real attacks? (current weights)"""
    stress = []
    for sd in seeds:
        stress += list(baseline.generate(hours, sd, baseline.Assumptions(rate_spread=2.0)))
    false = [r for r in evaluate(stress, devices, policy_cfg) if r["alert"]]
    caught, _, srecs, labels = sample_score(devices, policy_cfg)
    rows = []
    for rec in sorted((r for r in srecs if r["alert"] and labels[r["event"]["event_id"]] == "ATTACK"), key=lambda r: r["score"]):
        rows.append(("sample " + rec["event"]["event_id"], rec["attack_type"], "%.2f" % rec["confidence"], rec["score"], rec["level"]))
    for kind in sorted({r["attack_type"] for r in false}):
        group = [r for r in false if r["attack_type"] == kind]
        rows.append(("false alarms (%d, Rate spread x2)" % len(group), kind,
                     "%.2f-%.2f" % (min(r["confidence"] for r in group), max(r["confidence"] for r in group)),
                     "%d-%d" % (min(r["score"] for r in group), max(r["score"] for r in group)),
                     ", ".join("%s %d" % (lv, sum(1 for r in group if r["level"] == lv)) for lv in LEVELS if any(r["level"] == lv for r in group))))
    print(md_table(("Alert", "Rule", "Confidence", "Score", "Level"), rows))
    print()


# --------------------------------------------------------------------------- main
def main(argv=None):
    global HOURS_TOTAL
    parser = argparse.ArgumentParser(description="False-alarm calibration on normal traffic.")
    parser.add_argument("--hours", type=float, default=24, help="hours per seed (default 24)")
    parser.add_argument("--seeds", default="1,2,3,4,5", help="comma separated seeds (default 1..5)")
    parser.add_argument("--events", help="replay this CSV of REAL benign events instead of generating traffic")
    parser.add_argument("--devices", default=str(DEFAULT_DEVICES_PATH))
    args = parser.parse_args(argv)
    seeds = [int(s) for s in args.seeds.split(",") if s.strip()]
    devices = load_devices(args.devices)
    policy_cfg = policy.load_policy()

    if args.events:
        events = [e for _, e, _ in read_events(args.events) if e]
        for e in events:
            e["seed"] = 0
        HOURS_TOTAL = args.hours
        recs = evaluate(events, devices, policy_cfg)
        print("# Calibration on %s (%d events, %g hours given)\n" % (os.path.basename(args.events), len(events), args.hours))
        section_alerts(recs, args.hours, "Alerts on the recorded traffic")
        return 0

    HOURS_TOTAL = args.hours * len(seeds)
    generated, records = [], []
    for seed in seeds:
        for event in baseline.generate(args.hours, seed):
            event["seed"] = seed
            generated.append(event)
    records = evaluate(generated, devices, policy_cfg)
    for rec in records:
        rec["seed"] = rec["event"]["seed"]
    print("# Calibration run\n")
    print("Generated camera traffic: %d seeds x %g h = %g h, %d events (%s).\n" % (
        len(seeds), args.hours, HOURS_TOTAL, len(generated),
        ", ".join("%s %d" % kv for kv in Counter(e["traffic_kind"] for e in generated).most_common())))
    print("Detector config: %s; risk weight set: %s; devices: %s\n" % (
        os.path.relpath(detector.DEFAULT_CONFIG, ROOT), risk.load_config()["active_weight_set"], os.path.relpath(args.devices, ROOT)))

    base_devices = with_ports(devices, "CAM-001", (554, 443))
    before = evaluate(generated, base_devices, policy_cfg)
    for rec, ev in zip(before, generated):
        rec["seed"] = ev["seed"]
    section_alerts(before, HOURS_TOTAL, "A. Camera profile as first written (ports 554 and 443 only)")
    section_alerts(records, HOURS_TOTAL, "B. Current profile in config/devices.json (expected ports: %s)" % (
        ", ".join(str(p) for p in devices.get("CAM-001", {}).get("expected_ports", []))))
    print("### C. Alerts per clock hour with the current profile\n")
    section_hourly(records, args.hours, seeds)
    print("### D. Headroom of every threshold\n")
    section_headroom(records, devices, policy_cfg)
    print("### E. DoS Rate threshold sweep\n")
    section_dos_sweep(devices, policy_cfg, generated)
    print("### F. What if normal Rate has a heavier tail than assumed (current profile, current thresholds)\n")
    section_spread(devices, policy_cfg, seeds, args.hours)
    print("### G. Weight sets on the false alarms of a stress run (profile A, Rate spread x2)\n")
    section_weights(devices, policy_cfg, seeds, args.hours)
    print("### H. Scores of false alarms against scores of real attacks (current weights)\n")
    section_scores(devices, policy_cfg, seeds, args.hours)
    return 0


HOURS_TOTAL = 1.0

if __name__ == "__main__":
    raise SystemExit(main())
