"""Step 2: does our extractor reproduce the dataset's CSV values on the dataset's own PCAP?

    python scripts/compare_pcap.py pcap/CommandInjection.pcap pcap/CommandInjection.pcap.csv   # from services/ml

The dataset cut the capture into 10 MB pieces, converted them in parallel and merged the
results in no fixed order. Rows are therefore matched by values that need no timing (Tot sum,
Min, Max, Number and the four flag counts); then every feature is compared on the matched rows:
the share of rows where ours equals theirs (within 1% or 1e-6). Run once with the dataset's
10 MB cutting and once as one stream (how live traffic is processed).
Writes extractor_check.csv (one line per feature and setting) and prints the verdict.
"""
from __future__ import annotations

import argparse
import sys

import numpy as np
import pandas as pd

from ids_ml.extractor import FEATURES, extract, read_pcap

KEY = ["Tot sum", "Min", "Max", "Number", "ack_count", "syn_count", "fin_count", "rst_count"]
GOOD = 0.95          # a feature "matches" if it agrees on at least 95% of matched rows


def agree(ours: pd.Series, theirs: pd.Series) -> float:
    a, b = ours.to_numpy(float), theirs.to_numpy(float)
    return float(np.mean(np.isclose(a, b, rtol=0.01, atol=1e-6, equal_nan=True)))


def compare(packets, csv: pd.DataFrame, window: int = 10):
    ours = pd.DataFrame(extract(packets, window))
    theirs = csv[FEATURES].copy()
    for df in (ours, theirs):
        df["_key"] = list(map(tuple, df[KEY].round(6).to_numpy()))
    # keep keys that occur once on each side, so each match is one row to one row
    o1 = ours[~ours["_key"].duplicated(keep=False)].set_index("_key")
    t1 = theirs[~theirs["_key"].duplicated(keep=False)].set_index("_key")
    common = o1.index.intersection(t1.index)
    o, t = o1.loc[common], t1.loc[common]
    scores = {f: agree(o[f], t[f]) for f in FEATURES}
    return len(ours), len(theirs), len(common), scores


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("csv")
    ap.add_argument("--window", type=int, default=10)
    args = ap.parse_args()
    csv = pd.read_csv(args.csv)
    lines, verdict = [], None
    for split_mb, setting in ((10, "cut in 10 MB pieces, as the dataset"),
                              (None, "one stream (live)")):
        packets = read_pcap(args.pcap, split_mb)
        n_ours, n_theirs, n_match, scores = compare(packets, csv, args.window)
        print(f"\n{setting}: {len(packets):,} packets -> {n_ours:,} of our rows; CSV "
              f"{n_theirs:,} rows; {n_match:,} matched one-to-one "
              f"({n_match / max(1, n_theirs):.1%} of the CSV)")
        lines += [{"setting": setting, "feature": f, "agree": round(s, 4),
                   "matched_rows": n_match} for f, s in scores.items()]
        verdict = verdict or (setting, n_match, scores)
    pd.DataFrame(lines).to_csv("evidence/extractor_check.csv", index=False)
    setting, n_match, scores = verdict
    print(f"\nPer feature ({setting}, {n_match:,} matched rows)")
    print(f"{'feature':<18} agree   verdict")
    for f in FEATURES:
        print(f"{f:<18} {scores[f]:6.1%}  {'MATCHES' if scores[f] >= GOOD else 'differs'}")
    n_good = sum(s >= GOOD for s in scores.values())
    print(f"\n{n_good} of {len(FEATURES)} features match on >= {GOOD:.0%} of matched rows")
    return 0 if n_match else 1


if __name__ == "__main__":
    sys.exit(main())
