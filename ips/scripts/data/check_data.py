"""Independent checks of every deliverable against the task plan.

    python scripts/data/check_data.py             # checks the files in data/
    python scripts/data/check_data.py <folder>    # or checks the files in <folder>

Prints PASS/FAIL per check; exit code 1 on any failure. Needs only the five delivered files.
"""
import ipaddress
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data"
# the 39 feature columns of the CICIoT2023 CSV files, in file order
CICIOT2023_FEATURES = [
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate", "fin_flag_number",
    "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number",
    "ece_flag_number", "cwr_flag_number", "ack_count", "syn_count", "fin_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP", "ARP", "ICMP",
    "IGMP", "IPv", "LLC", "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number",
    "Variance"]
CONTEXT = ["device_id", "timestamp", "src_ip", "dst_ip", "dst_port", "protocol",
           "failed_attempts", "connection_attempts", "unique_dst_ports", "unique_dst_ips"]
GROUPS = {"Benign", "DDoS", "DoS", "Mirai", "Recon", "Spoofing", "BruteForce", "Web"}
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))


def main() -> int:
    print(f"checking the files in {OUT}")
    missing = [f for f in ("train.csv", "test.csv", "features.txt", "data_summary.md",
                           "sample_events.csv") if not (OUT / f).is_file()]
    for f in ("train.csv", "test.csv", "features.txt", "data_summary.md", "sample_events.csv"):
        check(f"{f} exists", f not in missing)
    if missing:
        print("\nCannot continue: put the five files in that folder (or pass the folder).")
        return 1
    train, test = pd.read_csv(OUT / "train.csv"), pd.read_csv(OUT / "test.csv")
    events = pd.read_csv(OUT / "sample_events.csv")
    all_features = CICIOT2023_FEATURES
    text = (OUT / "features.txt").read_text(encoding="utf-8")
    listed = re.findall(r"^\d+\s+(\S+(?: \S+)?)\s+\d\.\d{3}", text, re.MULTILINE)
    feats = [c for c in train.columns if c not in ("label", "attack_group", "original_label")]

    # size and balance
    check("about 200k rows in total", len(train) + len(test) == 200_000,
          f"{len(train):,} train + {len(test):,} test")
    check("80/20 split", len(train) == 160_000 and len(test) == 40_000)
    both = pd.concat([train, test])
    counts = both["label"].value_counts().to_dict()
    check("balanced benign vs attack", counts.get("BENIGN") == counts.get("ATTACK") == 100_000,
          str(counts))
    check("all 7 attack groups in train and in test",
          set(train["attack_group"]) == GROUPS and set(test["attack_group"]) == GROUPS)
    share = lambda d: d["attack_group"].value_counts(normalize=True)
    check("train and test have the same group mix (stratified)",
          (share(train) - share(test)).abs().max() < 0.002)

    # cleaning
    numeric = both[feats]
    check("no NaN or infinity in train/test",
          not numeric.isna().any().any() and np.isfinite(numeric.to_numpy()).all())
    check("no duplicate rows inside train", not train.duplicated(subset=feats).any())
    check("no duplicate rows inside test", not test.duplicated(subset=feats).any())
    h = lambda d: set(pd.util.hash_pandas_object(d[feats], index=False))
    overlap = len(h(train) & h(test))
    check("no row in both train and test", overlap == 0, f"{overlap} shared")
    keys = pd.util.hash_pandas_object(both[feats], index=False).to_numpy()
    contradictions = int((pd.Series(both["label"].to_numpy()).groupby(keys).nunique() > 1).sum())
    check("no identical feature values with both labels", contradictions == 0,
          f"{contradictions} found")
    check("label agrees with attack_group",
          ((both["label"] == "BENIGN") == (both["attack_group"] == "Benign")).all())

    # features
    check("15-20 features", 15 <= len(feats) <= 20, f"{len(feats)}")
    check("features.txt lists exactly the train/test feature columns", listed == feats,
          f"{len(listed)} listed")
    check("every feature is a real CICIoT2023 column", set(feats) <= set(all_features))
    check("every selected feature has a reason in features.txt",
          text.count("why:") == len(feats))

    # sample events
    check("10-15 sample events", 10 <= len(events) <= 15, f"{len(events)}")
    check("all context fields present and filled",
          set(CONTEXT) <= set(events.columns) and not events[CONTEXT].isna().any().any())
    check("all 39 feature columns present", set(all_features) <= set(events.columns))
    check("both benign and attack events",
          set(events["expected_label"]) == {"BENIGN", "ATTACK"})
    ips_ok = all(ipaddress.ip_address(v) for v in pd.concat([events.src_ip, events.dst_ip]))
    check("IP addresses are valid", ips_ok)
    check("ports are 0-65535 integers",
          events["dst_port"].between(0, 65535).all() and
          (events["dst_port"] == events["dst_port"].astype(int)).all())
    ts = pd.to_datetime(events["timestamp"], utc=True, errors="coerce")
    check("timestamps are ISO-8601 UTC and in order", ts.notna().all() and ts.is_monotonic_increasing)
    check("event ids are unique", events["event_id"].is_unique)
    scan = events[events["event_id"] == "EVT-005"].iloc[0]
    check("scan events cover many ports and the others touch one",
          scan["unique_dst_ports"] >= 20 and (events[events["event_id"] != "EVT-005"]["unique_dst_ports"] < 20).all()
          and (events["unique_dst_ips"] >= 1).all())
    ev_test = set(pd.util.hash_pandas_object(events[feats], index=False))
    te18 = set(pd.util.hash_pandas_object(test[feats], index=False))
    check("every event's features are a real test row", ev_test <= te18)
    # stricter than comparing all 39 columns: not even the 18 model features match a train row
    ev18 = set(pd.util.hash_pandas_object(events[feats], index=False))
    tr18 = set(pd.util.hash_pandas_object(train[feats], index=False))
    check("no event row was used for training", not (ev18 & tr18))
    proto_ok = all(
        (p == "UDP" and r["UDP"] >= 0.5) or (p == "GRE" and r["Protocol Type"] >= 40) or
        (p == "TCP" and r["TCP"] >= 0.5) for p, (_, r) in zip(events.protocol, events.iterrows(),
                                                               strict=True))
    check("each event's protocol matches its real traffic", proto_ok)
    ssh = events[events["dst_port"] == 22]
    check("port-22 brute-force events use rows with SSH traffic", (ssh["SSH"] > 0).all())
    print(f"\n{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
