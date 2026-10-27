"""
compare_weights.py - compare the weight sets in risk_weights.yaml on the reference
scenarios (iot_ips/scenarios.py) and print a Markdown table.

    python scripts/compare_weights.py

For every weight set it reports:
  * how many scenarios land in the level a human expected,
  * the total "level distance" of the misses (0 = perfect),
  * the score separation between the worst-scored Low/Medium/High/Critical
    scenarios (a positive gap means the levels do not overlap),
  * how much a smart bulb vs. a camera changes the score for the same attack
    (does the engine really know which device is attacked?).
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    import iot_ips  # noqa: F401  (installed with: pip install -e .)
except ImportError:
    sys.path.insert(0, str(ROOT / "src"))

from iot_ips.risk import LEVELS, assess, load_config  # noqa: E402
from iot_ips.scenarios import DEVICES, SCENARIOS, _s  # noqa: E402

# Tables use non-ASCII marks (✗, →, −). On a redirected console with a narrow
# code page (cp1252 on Windows) printing them raises UnicodeEncodeError, so
# emit UTF-8 and fall back to a replacement character instead of crashing.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError, OSError):
    pass


def _level_distance(a, b):
    return abs(LEVELS.index(a) - LEVELS.index(b))


def evaluate(cfg, set_name):
    rows = []
    for sc in SCENARIOS:
        res = assess(sc["detection"], sc["event"], DEVICES[sc["device"]], config=cfg, weight_set=set_name)
        rows.append((sc, res))
    hits = sum(1 for sc, r in rows if r["level"] == sc["expected_level"])
    distance = sum(_level_distance(r["level"], sc["expected_level"]) for sc, r in rows)

    # margin: for each pair of neighbouring expected levels, lowest score of the
    # higher level minus highest score of the lower level.
    by_level = {lv: [r["score"] for sc, r in rows if sc["expected_level"] == lv] for lv in LEVELS}
    gaps = []
    for lower, upper in zip(LEVELS, LEVELS[1:]):
        gaps.append(min(by_level[upper]) - max(by_level[lower]))

    # same attack on a bulb vs. a camera
    probe = _s("P", "Medium", "probe", "CAM-001", "brute_force", 0.85, "203.0.113.5", 22, failed=40)
    cam = assess(probe["detection"], probe["event"], DEVICES["CAM-001"], config=cfg, weight_set=set_name)["score"]
    bulb = assess(probe["detection"], probe["event"], DEVICES["BULB-001"], config=cfg, weight_set=set_name)["score"]
    return rows, hits, distance, gaps, cam - bulb


def main():
    cfg = load_config()
    names = list(cfg["weight_sets"])
    print("## Scores per scenario\n")
    print("| Scenario | Expected | " + " | ".join(names) + " |")
    print("|---|---|" + "---|" * len(names))
    results = {n: evaluate(cfg, n) for n in names}
    for i, sc in enumerate(SCENARIOS):
        cells = []
        for n in names:
            r = results[n][0][i][1]
            mark = "" if r["level"] == sc["expected_level"] else " ✗"
            cells.append("%d %s%s" % (r["score"], r["level"], mark))
        print("| %s | %s | %s |" % (sc["id"], sc["expected_level"], " | ".join(cells)))

    print("\n## Summary\n")
    print("| Weight set | Levels matched | Level distance of misses | Gap Low→Med | Gap Med→High | Gap High→Crit | Camera − bulb (same attack) |")
    print("|---|---|---|---|---|---|---|")
    for n in names:
        _rows, hits, distance, gaps, dev = results[n]
        print("| %s | %d / %d | %d | %+d | %+d | %+d | %+d |" % (n, hits, len(SCENARIOS), distance, gaps[0], gaps[1], gaps[2], dev))
    return 0


if __name__ == "__main__":
    sys.exit(main())
