"""Build the CICIoT2023 training data for the IoT-IPS.

    python scripts/data/prepare_data.py   # reads data/raw, writes data/train.csv, data/test.csv

Steps (each one is printed and recorded in data/data_summary.md):
  1. load the CICIoT2023 CSV files (no PCAPs): one merged file + per-attack files
  2. clean: drop rows with NaN/infinity, exact duplicates, and rows whose identical feature
     values appear with both a benign and an attack label (contradictory)
  3. balanced sample of 200,000 rows: 100,000 benign + 100,000 attack spread over the 7 attack
     groups (small groups are taken whole, the rest share what is left)
  4. train/test split 80/20, stratified by attack group, then a check that no row (same
     feature values) is in both
  5. feature selection on the TRAIN part only: drop near-constant columns, rank by Random
     Forest importance and mutual information, skip near-copies (|Spearman| > 0.95), keep 18
  6. write train.csv, test.csv, features.txt, data_summary.md
Sample events (sample_events.csv) are made by make_sample_events.py from the test part.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data" / "raw"          # the CICIoT2023 CSV files (not in the repository)
OUT = ROOT / "data"                   # train.csv, test.csv
INTERIM = ROOT / "data" / "interim"   # large working files (not in the repository)
SEED = 42
N_BENIGN, N_ATTACK, N_FEATURES = 100_000, 100_000, 18
CATEGORIES = ["DDoS", "DoS", "Mirai", "Recon", "Spoofing", "BruteForce", "Web"]

# CICIoT2023 detailed label -> attack group (the 7 groups of the dataset paper)
_SPECIAL = {"BENIGN": "Benign", "VULNERABILITYSCAN": "Recon", "DICTIONARYBRUTEFORCE": "BruteForce",
            "DNS_SPOOFING": "Spoofing", "MITM-ARPSPOOFING": "Spoofing", "SQLINJECTION": "Web",
            "COMMANDINJECTION": "Web", "XSS": "Web", "BACKDOOR_MALWARE": "Web",
            "UPLOADING_ATTACK": "Web", "BROWSERHIJACKING": "Web"}
# per-attack file name -> the label spelling used in the merged CSV files
_FILE_LABEL = {"BenignTraffic": "BENIGN", "DictionaryBruteForce": "DICTIONARYBRUTEFORCE",
               "CommandInjection": "COMMANDINJECTION", "MITM-ArpSpoofing": "MITM-ARPSPOOFING",
               "Recon-PortScan": "RECON-PORTSCAN", "VulnerabilityScan": "VULNERABILITYSCAN"}


def group_of(label: str) -> str:
    if label in _SPECIAL:
        return _SPECIAL[label]
    for g in ("DDoS", "DoS", "Mirai", "Recon"):          # DDOS- before DOS-
        if label.startswith(g.upper() + "-"):
            return g
    raise ValueError(f"unknown CICIoT2023 label {label!r}")


def load() -> tuple[pd.DataFrame, list[str], list[str]]:
    log = []
    main = pd.read_csv(DATA / "Merged01_partial.csv")
    parts = [main.assign(source_file="Merged01.csv (first 143,502 rows)")]
    log.append(f"Merged01.csv (first part of the download): {len(main):,} rows, all classes mixed")
    for f in sorted((DATA / "extra").glob("*.csv")):
        name = f.name.split(".")[0].removesuffix("_partial")
        part = pd.read_csv(f)
        part["Label"] = _FILE_LABEL[name]
        part["source_file"] = f.name
        parts.append(part)
        log.append(f"{f.name}: {len(part):,} rows of {_FILE_LABEL[name]}")
    df = pd.concat(parts, ignore_index=True)
    df["Label"] = df["Label"].str.strip().str.upper()
    features = [c for c in main.columns if c != "Label"]
    return df, features, log


def dedupe_on(train, test, pool_all, cols, rng):
    """Make train/test free of repeats and contradictions on `cols`, keeping sizes per split
    and group. Returns (train, test, log lines)."""
    log = []
    used_ids = set(train["row_id"]) | set(test["row_id"])
    everything = pd.concat([train.assign(split="train"), test.assign(split="test"),
                            pool_all[~pool_all["row_id"].isin(used_ids)].assign(split="pool")],
                           ignore_index=True)
    everything["key"] = pd.util.hash_pandas_object(everything[cols], index=False).to_numpy()
    mixed = everything.groupby("key")["label"].transform("nunique") > 1
    n_mixed = int((mixed & (everything["split"] != "pool")).sum())
    everything = everything[~mixed]
    order = everything["split"].map({"train": 0, "test": 1, "pool": 2})
    everything = everything.assign(order=order).sort_values("order", kind="stable")
    first = ~everything.duplicated("key")
    n_dup = int((~first & (everything["split"] != "pool")).sum())
    everything = everything[first]
    log.append(((f"after choosing the features: removed {n_mixed:,} sampled rows whose "
                "selected-feature values also appear with the other label"), None))
    log.append(((f"after choosing the features: removed {n_dup:,} sampled rows that repeat "
                "another row on the selected features (inside a split or across train/test)"),
                None))
    pool = everything[everything["split"] == "pool"]
    refilled = 0
    out = {}
    for name, part in (("train", train), ("test", test)):
        kept = everything[everything["split"] == name]
        target = part["group"].value_counts().to_dict()
        pieces, short = [kept], 0
        for g, n in target.items():
            need = n - int((kept["group"] == g).sum())
            if need <= 0:
                continue
            cand = pool[pool["group"] == g]
            take = cand.sample(min(need, len(cand)), random_state=int(rng.integers(1 << 31)))
            pool = pool.drop(take.index)
            pieces.append(take)
            refilled += len(take)
            short += need - len(take) if g != "Benign" else 0
            if g == "Benign" and need > len(take):
                raise SystemExit("not enough unused benign rows to refill")
        big = ["DDoS", "DoS", "Recon", "Spoofing"]       # cover any small-group shortfall
        for i in range(short):
            cand = pool[pool["group"] == big[i % len(big)]]
            take = cand.sample(1, random_state=int(rng.integers(1 << 31)))
            pool = pool.drop(take.index)
            pieces.append(take)
            refilled += 1
        out[name] = pd.concat(pieces).drop(columns=["split", "key", "order"])
    log.append(((f"refilled {refilled:,} rows from unused cleaned rows of the same group "
                "(sizes and balance unchanged)"), None))
    return out["train"], out["test"], log


def main() -> None:
    OUT.mkdir(exist_ok=True)
    INTERIM.mkdir(exist_ok=True)
    rng = np.random.default_rng(SEED)
    df, features, files = load()
    steps = [("loaded", len(df))]

    # 2. clean -----------------------------------------------------------------------------
    df[features] = df[features].replace([np.inf, -np.inf], np.nan)
    bad = df[features].isna().any(axis=1)
    df = df[~bad]
    steps.append((f"removed {int(bad.sum()):,} rows with NaN or infinity", len(df)))
    before = len(df)
    df = df.drop_duplicates(subset=features + ["Label"])
    steps.append((f"removed {before - len(df):,} exact duplicate rows", len(df)))
    df["group"] = df["Label"].map(group_of)
    df["label"] = np.where(df["group"] == "Benign", "BENIGN", "ATTACK")
    n_labels = df.groupby(features)["label"].transform("nunique")
    conflict = n_labels > 1
    df = df[~conflict]
    steps.append(((f"removed {int(conflict.sum()):,} rows whose identical values had both a "
                  "benign and an attack label"), len(df)))
    # same values with two different attack labels: keep one row (the label is ambiguous)
    before = len(df)
    df = df.drop_duplicates(subset=features)
    steps.append(((f"removed {before - len(df):,} rows repeating the same values under a "
                  "different attack label"), len(df)))
    available = df["group"].value_counts().to_dict()
    df = df.reset_index(drop=True)
    df["row_id"] = np.arange(len(df))        # stable id: which cleaned rows are used

    # 3. balanced sample -------------------------------------------------------------------
    want = {"Benign": N_BENIGN}
    remaining, open_groups = N_ATTACK, list(CATEGORIES)
    while open_groups:                       # water-filling: small groups first, all of them
        share = remaining // len(open_groups)
        small = [g for g in open_groups if available[g] <= share]
        if not small:
            for i, g in enumerate(sorted(open_groups)):
                want[g] = share + (1 if i < remaining - share * len(open_groups) else 0)
            break
        for g in small:
            want[g] = available[g]
            remaining -= available[g]
            open_groups.remove(g)
    sample = pd.concat([df[df["group"] == g].sample(n, random_state=int(rng.integers(1 << 31)))
                        for g, n in want.items()], ignore_index=True)
    sample = sample.sample(frac=1, random_state=SEED).reset_index(drop=True)
    assert len(sample) == N_BENIGN + N_ATTACK

    # 4. split -----------------------------------------------------------------------------
    train, test = train_test_split(sample, test_size=0.2, stratify=sample["group"],
                                   random_state=SEED)
    key = lambda part: pd.util.hash_pandas_object(part[features], index=False)
    overlap = int(key(train).isin(set(key(test))).sum())
    assert overlap == 0, f"{overlap} rows are in both train and test"

    # 5. feature selection (train only) ----------------------------------------------------
    X, y = train[features], (train["label"] == "ATTACK").astype(int)
    top_share = X.apply(lambda c: c.value_counts(normalize=True).iloc[0])
    constant = sorted(top_share[top_share >= 0.995].index)
    candidates = [f for f in features if f not in constant]
    rf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=SEED,
                                class_weight="balanced").fit(X[candidates], y)
    imp = pd.Series(rf.feature_importances_, index=candidates)
    mi = pd.Series(mutual_info_classif(X[candidates].sample(40_000, random_state=SEED),
                                       y.loc[X[candidates].sample(40_000, random_state=SEED).index],
                                       random_state=SEED), index=candidates)
    rank = (imp.rank(ascending=False) + mi.rank(ascending=False)) / 2
    corr = X[candidates].corr(method="spearman").abs()
    chosen, skipped = [], {}
    for f in rank.sort_values().index:
        twin = next((c for c in chosen if corr.loc[f, c] > 0.95), None)
        if twin:
            skipped[f] = twin
        elif len(chosen) < N_FEATURES:
            chosen.append(f)

    # 5b. no duplicates on the CHOSEN features --------------------------------------------
    # Rows that differed only in dropped columns become identical once those columns are
    # gone. Remove such repeats and contradictions (same 18 values, benign AND attack), keep
    # the train rows (the selection set) first, then refill each split and group with unused
    # cleaned rows, so sizes and balance stay exact. Refill rows were not used for selection.
    train, test, fix_log = dedupe_on(train, test, df, chosen, rng)
    steps += fix_log
    overlap = int(pd.util.hash_pandas_object(test[chosen], index=False)
                  .isin(set(pd.util.hash_pandas_object(train[chosen], index=False))).sum())
    assert overlap == 0 and len(train) + len(test) == N_BENIGN + N_ATTACK

    # 6. write -----------------------------------------------------------------------------
    cols = chosen + ["label", "group", "Label"]
    rename = {"Label": "original_label", "group": "attack_group"}
    train[cols].rename(columns=rename).to_csv(OUT / "train.csv", index=False)
    test[cols].rename(columns=rename).to_csv(OUT / "test.csv", index=False)
    # the full rows of the test part stay available for the sample events (all 39 columns)
    test[features + ["label", "group", "Label", "source_file"]].to_csv(
        INTERIM / "_test_full.csv", index=False)
    train[features + ["label", "group", "Label", "source_file"]].to_csv(
        INTERIM / "_train_full.csv", index=False)     # internal: to compare 18 vs all 39 features
    info = {"features": features, "chosen": chosen, "constant": constant, "skipped": skipped,
            "importance": imp.round(4).to_dict(), "mutual_info": mi.round(4).to_dict(),
            "rank": rank.to_dict(), "steps": steps, "files": files, "available": available,
            "want": want, "overlap": overlap,
            "train_counts": train["group"].value_counts().to_dict(),
            "test_counts": test["group"].value_counts().to_dict(),
            "train_labels": train["label"].value_counts().to_dict(),
            "test_labels": test["label"].value_counts().to_dict()}
    (INTERIM / "_selection.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    for text, n in steps:
        print(f"{n:>9,}  {text}" if n is not None else f"{'':>9}  {text}")
    print("sample per group:", want)
    print("train", len(train), "test", len(test), "overlap", overlap)
    print("chosen features:", chosen)
    print("near-constant (dropped):", constant)
    print("near-copies (dropped):", skipped)


if __name__ == "__main__":
    main()
