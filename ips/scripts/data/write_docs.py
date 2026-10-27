"""Write features.txt and data_summary.md from the real numbers.

    python scripts/data/write_docs.py        # after prepare_data.py and make_sample_events.py

Also checks the feature choice: a Random Forest trained on the 18 chosen features is compared
with one trained on all 39 (same train/test split). Only the numbers measured here are written.
"""
import json
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "data"
INTERIM = ROOT / "data" / "interim"

MEANING = {  # CICIoT2023 feature -> plain meaning (values are per window of packets)
    "Max": "largest packet size in the window",
    "Min": "smallest packet size in the window",
    "AVG": "average packet size",
    "Variance": "how much packet sizes vary",
    "Tot sum": "total bytes of all packets in the window",
    "Number": "number of packets in the window",
    "Header_Length": "length of the packet headers",
    "Time_To_Live": "average IP time-to-live (how many hops the packets can still travel)",
    "IAT": "time between packets (inter-arrival time)",
    "ack_flag_number": "share of TCP packets with the ACK flag",
    "psh_flag_number": "share of TCP packets with the PSH flag",
    "syn_flag_number": "share of TCP packets with the SYN flag (connection requests)",
    "TCP": "share of packets that are TCP",
    "UDP": "share of packets that are UDP",
    "HTTPS": "share of packets that are HTTPS (port 443)",
    "HTTP": "share of packets that are HTTP (port 80)",
    "DNS": "share of packets that are DNS",
    "SSH": "share of packets that are SSH (port 22)",
}
WHY = {
    "Max": "floods and scans send small, uniform packets; normal video/uploads reach full size",
    "Min": "lower bound of packet size; tiny minimums are typical of SYN floods and probes",
    "AVG": "mean size separates bulk normal traffic from floods made of minimal packets",
    "Variance": "normal traffic mixes sizes; generated attack traffic is very uniform",
    "Tot sum": "bytes per window: floods move many small packets, video moves few large ones",
    "Number": "packets per window: very high for DoS/DDoS/Mirai floods",
    "Header_Length": "unusual header lengths appear in fragmentation and crafted-packet attacks",
    "Time_To_Live": "attack tools and distant attackers use TTLs unlike the local devices",
    "IAT": "packet timing: floods have near-zero gaps; also stands in for Rate (near-copy)",
    "ack_flag_number": "ACK patterns differ between real conversations and floods/scans",
    "psh_flag_number": "PSH marks real data transfer; floods and scans rarely carry data",
    "syn_flag_number": "many SYNs without data = port scan or SYN flood",
    "TCP": "protocol mix; Mirai GRE floods have neither TCP nor UDP",
    "UDP": "UDP floods are ~100% UDP, normal devices mostly TCP",
    "HTTPS": "normal IoT cloud traffic is mostly HTTPS",
    "HTTP": "web attacks and vulnerability scans hit the plain-HTTP web page",
    "DNS": "normal devices make DNS lookups; DNS spoofing manipulates them",
    "SSH": "SSH share separates password-guessing (brute force) from other traffic",
}
# context fields the pipeline needs but CICIoT2023 does not contain
MISSING = [
    ("device_id", ("rows are not linked to a device; the dataset does not say which IoT device "
                  "sent or received the traffic")),
    ("timestamp", "there is no capture time per row (the CSV files are shuffled windows)"),
    ("src_ip, dst_ip", "addresses were removed when the PCAPs were turned into CSV features"),
    ("dst_port", "only protocol indicators exist (HTTP, HTTPS, SSH, DNS, ...), no port number"),
    ("protocol (as a name)", ("only 'Protocol Type' (a number, e.g. 6 = TCP, 17 = UDP, 47 = GRE) "
                             "and per-protocol shares")),
    ("failed_attempts", "no count of failed logins or refused connections"),
    ("connection_attempts", "no count of connection attempts per source"),
    ("unique_dst_ports, unique_dst_ips", ("no count of distinct ports or hosts a source touched; "
                                          "the detector's port-scan rule reads these two")),
]


def main() -> None:
    info = json.loads((INTERIM / "_selection.json").read_text(encoding="utf-8"))
    train, test = pd.read_csv(INTERIM / "_train_full.csv"), pd.read_csv(INTERIM / "_test_full.csv")
    chosen, features = info["chosen"], info["features"]
    y_tr, y_te = (train["label"] == "ATTACK").astype(int), (test["label"] == "ATTACK").astype(int)
    scores = {}
    for name, cols in (("18 chosen", chosen), ("all 39", features)):
        rf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42,
                                    class_weight="balanced").fit(train[cols], y_tr)
        pred = rf.predict(test[cols])
        tn, fp, fn, tp = confusion_matrix(y_te, pred).ravel()
        scores[name] = {"f1": f1_score(y_te, pred), "fpr": fp / (fp + tn), "fnr": fn / (fn + tp)}
        print(name, {k: round(v, 4) for k, v in scores[name].items()})

    # features.txt -------------------------------------------------------------------------
    lines = [f"Selected features: {len(chosen)} of the {len(features)} CICIoT2023 feature columns",
             ("(column names exactly as in the dataset; most values are averages over a window "
             "of packets)"), "",
             "How they were chosen (on the training part only, never the test part):",
             "  1. drop near-constant columns (one value in >= 99.5% of rows)",
             "  2. rank the rest by Random Forest importance + mutual information (average rank)",
             "  3. go down the ranking, skipping a column that is a near-copy of one already",
             "     chosen (Spearman correlation > 0.95), until 18 are chosen", "",
             "Check: Random Forest on the 40,000 test rows, normal vs attack:",
             (f"  18 chosen features: F1 {scores['18 chosen']['f1']:.4f}, false positives "
             f"{scores['18 chosen']['fpr']:.2%}, missed attacks {scores['18 chosen']['fnr']:.2%}"),
             (f"  all 39 features:    F1 {scores['all 39']['f1']:.4f}, false positives "
             f"{scores['all 39']['fpr']:.2%}, missed attacks {scores['all 39']['fnr']:.2%}"),
             "", "-" * 98,
             f"{'#':<3}{'feature':<17}{'RF imp.':>8}{'MI':>7}  meaning / why it helps", "-" * 98]
    for i, f in enumerate(chosen, 1):
        lines.append(f"{i:<3}{f:<17}{info['importance'][f]:>8.3f}{info['mutual_info'][f]:>7.3f}"
                     f"  {MEANING[f]}")
        lines.append(f"{'':<35}why: {WHY[f]}")
    lines += ["", "Dropped as near-copies (redundant):"]
    lines += [f"  {f:<16} ~ {twin} (|Spearman| > 0.95)" for f, twin in info["skipped"].items()]
    lines += ["", "Dropped as near-constant (almost always the same value):",
              "  " + ", ".join(info["constant"])]
    rest = [f for f in features if f not in chosen and f not in info["skipped"]
            and f not in info["constant"]]
    lines += ["", "Kept out because they ranked lower (still in sample_events.csv):",
              "  " + ", ".join(rest)]
    (OUT / "features.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # data_summary.md ----------------------------------------------------------------------
    groups = ["Benign", "DDoS", "DoS", "Mirai", "Recon", "Spoofing", "BruteForce", "Web"]
    tc, ec, av = info["train_counts"], info["test_counts"], info["available"]
    md = ["# Data summary", "",
          ("Dataset: **CICIoT2023** (Canadian Institute for Cybersecurity), the provided CSV "
          "feature files, not the PCAPs. Each row is one window of packets described by 39 "
          "numeric features; labels are the 34 detailed CICIoT2023 classes, grouped into "
          "benign + 7 attack groups."), "",
          "## Source files", ""]
    md += [f"- {f}" for f in info["files"]]
    md += ["", ("Because the download server was very slow, only the first part of `Merged01.csv` "
           "and part of three per-attack files were downloaded. Every attack group is still "
           "present."), "", "## Cleaning (what was removed)", "", "| Step | Rows left |",
           "|---|---|"]
    md += [f"| {text[0].upper() + text[1:]} | {n:,} |" if n is not None
           else f"| {text[0].upper() + text[1:]} | (sample stays 200,000) |"
           for text, n in info["steps"]]
    md += ["", "## Balanced sample: 200,000 rows", "",
           ("100,000 benign + 100,000 attack. The attack half is shared over the 7 groups: groups "
           "smaller than an equal share (Web, Mirai, BruteForce) are taken whole, the other four "
           "share the rest equally. Random seed 42."), "",
           "| Group | Available after cleaning | In sample | Train | Test |", "|---|---|---|---|---|"]
    for g in groups:
        md.append(f"| {g} | {av.get(g, 0):,} | {tc.get(g, 0) + ec.get(g, 0):,} | {tc.get(g, 0):,} | "
                  f"{ec.get(g, 0):,} |")
    md += [(f"| **Total** | {sum(av.values()):,} | 200,000 | {sum(tc.values()):,} | "
           f"{sum(ec.values()):,} |"), "",
           (f"Binary balance: train {info['train_labels']['BENIGN']:,} BENIGN / "
           f"{info['train_labels']['ATTACK']:,} ATTACK; test {info['test_labels']['BENIGN']:,} "
           f"BENIGN / {info['test_labels']['ATTACK']:,} ATTACK."), "",
           "## Train / test split", "",
           ("80 / 20, stratified by attack group. Duplicates were removed twice: on all 39 "
           "columns before splitting, and again on the 18 selected columns after the features "
           "were chosen (rows that differed only in dropped columns become identical once those "
           "columns are gone). Train rows were kept first, repeats and contradictory rows (same "
           "18 values with both labels) were removed, and each split was refilled with unused "
           "cleaned rows of the same group. Where a small group had no unused rows left, a "
           "large attack group filled the gap, so the group counts above are the final ones. "
           f"A check confirms that **{info['overlap']} rows** with the same selected-feature "
           "values appear in both train and test."), "",
           "## Files", "",
           "| File | Contents |", "|---|---|",
           (f"| `train.csv` | 160,000 rows: the {len(chosen)} features + `label` (BENIGN/ATTACK) + "
           "`attack_group` + `original_label` |"),
           "| `test.csv` | 40,000 rows, same columns |",
           "| `features.txt` | the selected features, how and why they were chosen |",
           "| `sample_events.csv` | 14 demo events: real test rows (all 39 features) + context |",
           "", "## Context fields the dataset does not have", "",
           ("The rule-based detector and the risk engine also need these fields. CICIoT2023 does "
           "not contain them, so in `sample_events.csv` they were added by hand to match each "
           "row's story:"), ""]
    md += [f"- **{name}**: {why}." for name, why in MISSING]
    md += ["", "## Sample events", "",
           ("14 events, each a real row from the **test** part (never used for training) plus "
           "hand-written context. 4 benign, 10 attacks covering all 7 groups, including 2 "
           "evasion cases for the rule-based detector (a slow port scan, a low-rate SSH brute "
           "force). The row for each story was chosen so its real values fit: e.g. the SSH brute "
           "force uses rows with SSH traffic, the UDP flood a ~100% UDP row, Mirai a GRE "
           "(protocol 47) row. `expected_label` / `expected_attack_type` are for checking; the "
           "detector must not read them. Device ids CAM-001, THERMO-001 and PLUG-001 (IPs "
           "192.168.1.50-52) should match the team's devices.json."), "",
           "## Notes", "",
           ("- `Rate` was dropped from the model features as a near-copy of `IAT` (packet rate is "
           "the inverse of the time between packets). It is still in `sample_events.csv` for "
           "rules."),
           ("- `IAT` is suspected in some studies of leaking capture timing. Checked here: alone it "
           "is not among the 10 strongest single features, so it was kept."),
           ("- Feature check (Random Forest, test part): 18 features F1 "
           f"{scores['18 chosen']['f1']:.4f} vs all 39 F1 {scores['all 39']['f1']:.4f}."),
           ("- Rebuild everything with `python scripts/data/prepare_data.py`, `python scripts/data/make_sample_events.py`, "
           "`python scripts/data/write_docs.py`, then check with `python scripts/data/check_data.py`.")]
    (OUT / "data_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("wrote features.txt and data_summary.md")


if __name__ == "__main__":
    main()
