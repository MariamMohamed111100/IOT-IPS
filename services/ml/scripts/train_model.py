"""Step 3: train and evaluate the BENIGN vs ATTACK model on features our extractor can produce.

    python scripts/train_model.py   # reads ips/data/train.csv and ips/data/test.csv

Trains on features.MODEL_FEATURES only (Person 2's 18 selected features, all confirmed equal
to what our extractor computes). Compares Random Forest with Gradient Boosting (sklearn's
HistGradientBoosting, the same family as XGBoost), reports precision, recall, F1, confusion
matrix and false-positive / false-negative rates, and what the timing feature IAT adds.
Because a random split is optimistic, it also hides each attack group from training in turn
and measures how much of that unseen group is still flagged.
Also trains the attack-type model used by detect() for `attack_type`.
Writes models/binary.joblib, models/attack_type.joblib and results.md.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

from ids_ml.features import MODEL_FEATURES

HERE = Path(__file__).resolve().parents[1]                 # services/ml
DATA = HERE.parents[1] / "ips" / "data"                    # train.csv and test.csv live with the IPS data
SEED = 42
THRESHOLD = 0.5       # ATTACK when P(attack) > THRESHOLD


def forest():
    # 100 trees, >= 5 rows per leaf: 24 MB saved instead of 860 MB for 200 full-depth trees,
    # F1 0.8765 vs 0.8778 and fewer false alarms (5.6% vs 6.6%)
    return RandomForestClassifier(n_estimators=100, min_samples_leaf=5, n_jobs=-1,
                                  random_state=SEED, class_weight="balanced")


def models():
    return {
        "Random Forest": forest(),
        "Gradient Boosting": HistGradientBoostingClassifier(max_iter=300, random_state=SEED,
                                                            class_weight="balanced"),
    }


def scores(y, pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"precision": precision_score(y, pred), "recall": recall_score(y, pred),
            "f1": f1_score(y, pred), "fpr": fp / (fp + tn), "fnr": fn / (fn + tp),
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}


def main() -> None:
    train, test = pd.read_csv(DATA / "train.csv"), pd.read_csv(DATA / "test.csv")
    y_tr = (train["label"] == "ATTACK").astype(int)
    y_te = (test["label"] == "ATTACK").astype(int)
    print(f"train {len(train):,} rows, test {len(test):,} rows; features: {MODEL_FEATURES}")

    # 1. model comparison on the extractor-safe features
    # one decision rule everywhere (here, results.md and detect()): ATTACK if P(attack) > 0.5
    results, fitted, preds = {}, {}, {}
    for name, model in models().items():
        t0 = time.time()
        model.fit(train[MODEL_FEATURES], y_tr)
        pred = (model.predict_proba(test[MODEL_FEATURES])[:, 1] > THRESHOLD).astype(int)
        fitted[name], preds[name] = model, pred
        results[name] = scores(y_te, pred) | {"seconds": round(time.time() - t0, 1)}
        print(f"{name:<18} F1 {results[name]['f1']:.4f}  FPR {results[name]['fpr']:.2%}  "
              f"FNR {results[name]['fnr']:.2%}  ({results[name]['seconds']} s)")
    best = max(results, key=lambda n: results[n]["f1"])
    model, pred, final = fitted[best], preds[best], results[best]

    # 2. what IAT adds (it depends on all traffic of the network, so worth knowing)
    no_iat = [f for f in MODEL_FEATURES if f != "IAT"]
    m = models()[best].fit(train[no_iat], y_tr)
    no_iat_scores = scores(y_te, (m.predict_proba(test[no_iat])[:, 1] > THRESHOLD).astype(int))

    # 3. per attack group on the test part
    per_group = {}
    for g, part in test.groupby("attack_group"):
        p = pred[part.index.to_numpy()]
        per_group[g] = float(p.mean()) if g != "Benign" else float(1 - p.mean())

    # 4. harder test: each attack group hidden from training
    unseen = {}
    for g in sorted(set(train["attack_group"]) - {"Benign"}):
        keep = train["attack_group"] != g
        m = models()[best].fit(train.loc[keep, MODEL_FEATURES], y_tr[keep])
        hidden = test[test["attack_group"] == g]
        unseen[g] = float((m.predict_proba(hidden[MODEL_FEATURES])[:, 1] > THRESHOLD).mean())
        print(f"  {g:<11} hidden from training: {unseen[g]:.1%} of its test rows still flagged")

    # 5. attack-type model (attack rows only) for detect()'s attack_type
    attacks_tr = train[train["label"] == "ATTACK"]
    attacks_te = test[test["label"] == "ATTACK"]
    typer = forest()
    typer.fit(attacks_tr[MODEL_FEATURES], attacks_tr["attack_group"])
    type_pred = typer.predict(attacks_te[MODEL_FEATURES])
    type_acc = float((type_pred == attacks_te["attack_group"]).mean())
    type_f1 = f1_score(attacks_te["attack_group"], type_pred, average="macro")

    out = HERE / "ids_ml" / "models"
    out.mkdir(exist_ok=True)
    joblib.dump({"model": model, "features": MODEL_FEATURES, "name": best,
                 "threshold": THRESHOLD},
                out / "binary.joblib", compress=3)
    joblib.dump({"model": typer, "features": MODEL_FEATURES}, out / "attack_type.joblib",
                compress=3)
    summary = {"models": results, "chosen": best, "final": final, "without_iat": no_iat_scores,
               "per_group": per_group, "unseen_group_flagged": unseen,
               "attack_type_accuracy": type_acc, "attack_type_macro_f1": type_f1,
               "features": MODEL_FEATURES}
    (HERE / "evidence" / "results.json").write_text(json.dumps(summary, indent=2, default=float))
    write_results(summary)
    import hashlib
    (out / "MODELS.sha256").write_text("".join(
        f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n"
        for n in ("binary.joblib", "attack_type.joblib")))         # checked before every load
    print(f"\nchosen: {best}; F1 {final['f1']:.4f}; attack type accuracy {type_acc:.1%}")


def write_results(s: dict) -> None:
    f = s["final"]
    lines = ["# Binary model results (Person 2, task 6)", "",
             f"Features ({len(s['features'])}, all computed by our extractor like the dataset): "
             + ", ".join(f"`{x}`" for x in s["features"]) + ".", "",
             ("`Number` and `Tot sum` are left out on purpose: the dataset used 100-packet "
              "windows for floods and 10 for the rest, so they reveal the window size, not the "
              "traffic. Live windows are always 10 packets."), "",
             "## Model comparison (test part, 40,000 rows)", "",
             "| Model | Precision | Recall | F1 | False positives | Missed attacks | Train time |",
             "|---|---|---|---|---|---|---|"]
    for name, r in s["models"].items():
        lines.append(f"| {name}{' (chosen)' if name == s['chosen'] else ''} | {r['precision']:.4f} "
                     f"| {r['recall']:.4f} | {r['f1']:.4f} | {r['fpr']:.2%} | {r['fnr']:.2%} | "
                     f"{r['seconds']} s |")
    lines += ["", "## Confusion matrix (chosen model)", "",
              "| | Predicted BENIGN | Predicted ATTACK |", "|---|---|---|",
              f"| **Actual BENIGN** | {f['tn']:,} | {f['fp']:,} |",
              f"| **Actual ATTACK** | {f['fn']:,} | {f['tp']:,} |", "",
              f"False-positive rate {f['fpr']:.2%}, false-negative rate {f['fnr']:.2%}.", "",
              "## What the timing feature IAT adds", "",
              (f"With IAT ({len(s['features'])} features) F1 {f['f1']:.4f}; without it F1 "
              f"{s['without_iat']['f1']:.4f}. IAT is the time between packets of the whole "
              "network, so it also depends on how busy the network is: the lab test will show "
              "whether it carries over to our network."), "",
              "## Per attack group (test part)", "", "| Group | Correct |", "|---|---|"]
    lines += [f"| {g} | {v:.1%} |" for g, v in s["per_group"].items()]
    lines += ["", "## Harder test: attack group never seen in training", "",
              ("The random split is optimistic: windows from the same capture are similar, so "
              "test rows resemble training rows. Here each attack group is removed from training "
              "and the model must still call its test rows attacks."), "",
              "| Group hidden from training | Still flagged as attack |", "|---|---|"]
    lines += [f"| {g} | {v:.1%} |" for g, v in s["unseen_group_flagged"].items()]
    lines += ["", (f"Attack-type model (for `attack_type`): accuracy "
              f"{s['attack_type_accuracy']:.1%}, macro F1 {s['attack_type_macro_f1']:.3f} on "
              "the test part's attack rows."), "",
              ("Not yet done: testing on our own lab traffic (no lab capture exists yet).")]
    (HERE / "evidence" / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    np.random.seed(SEED)
    main()
