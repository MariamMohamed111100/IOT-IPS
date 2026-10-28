"""Model integrity, the rules+ML combination, and the numbers the README promises."""
import json
import shutil
import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_ml import detector as ml_detector  # noqa: E402
from ids_ml.combined import make_detect  # noqa: E402
from ids_ml.features import MODEL_FEATURES  # noqa: E402

DATA = ROOT.parents[1] / "ips" / "data"


# ----------------------------------------------------------------------------- integrity
def test_the_shipped_models_match_their_hashes():
    ml_detector.verify_models()


def test_a_swapped_model_file_is_refused_before_it_is_loaded(tmp_path):
    for name in ("binary.joblib", "attack_type.joblib", "MODELS.sha256"):
        shutil.copy(ml_detector.HERE / "models" / name, tmp_path / name)
    (tmp_path / "binary.joblib").write_bytes(b"not the model that was trained")
    with pytest.raises(ml_detector.ModelIntegrityError, match="binary.joblib"):
        ml_detector.verify_models(tmp_path)
    (tmp_path / "MODELS.sha256").unlink()
    with pytest.raises(ml_detector.ModelIntegrityError):
        ml_detector.verify_models(tmp_path)


# ----------------------------------------------------------------------------- the combination (fake detectors)
ATTACK = {"label": "ATTACK", "attack_type": "DoS", "confidence": 0.8, "mitre_technique": "T1498"}
BENIGN = {"label": "BENIGN", "attack_type": None, "confidence": 0.9, "mitre_technique": None}


def ml_says(label, confidence, attack_type="Recon"):
    return lambda e, p=None: {"label": label, "attack_type": attack_type if label == "ATTACK" else None,
                              "confidence": confidence, "mitre_technique": "T1046", "detector": "ml", "notes": []}


def test_the_rules_decide_when_they_see_an_attack():
    d = make_detect(rules=lambda e, p=None: dict(ATTACK), ml=ml_says("BENIGN", 0.9))({"x": 1}, None)
    assert d["label"] == "ATTACK" and d["attack_type"] == "DoS" and d["ml_agrees"] is False
    assert "ml did not flag" in d["notes"][0]
    d = make_detect(rules=lambda e, p=None: dict(ATTACK), ml=ml_says("ATTACK", 0.95))({"x": 1}, None)
    assert d["attack_type"] == "DoS" and d["ml_agrees"] is True


def test_the_model_alone_needs_high_confidence():
    rules = lambda e, p=None: dict(BENIGN)  # noqa: E731
    assert make_detect(rules=rules, ml=ml_says("ATTACK", 0.89))({}, None)["label"] == "BENIGN"
    d = make_detect(rules=rules, ml=ml_says("ATTACK", 0.91))({}, None)
    assert d["label"] == "ATTACK" and d["detector"] == "ml" and d["attack_type"] == "Recon"
    assert make_detect(0.7, rules=rules, ml=ml_says("ATTACK", 0.75))({}, None)["label"] == "ATTACK"


def test_an_event_without_model_features_is_judged_by_the_rules_alone():
    def broken(e, p=None):
        raise ValueError("event lacks features ['Max']")
    d = make_detect(rules=lambda e, p=None: dict(ATTACK), ml=broken)({}, None)
    assert d["label"] == "ATTACK" and "ml not used" in d["notes"][0]


def test_the_threshold_is_checked():
    for bad in (0.4, 1.5):
        with pytest.raises(ValueError):
            make_detect(bad, rules=lambda e, p=None: BENIGN, ml=ml_says("BENIGN", 0.9))


# ----------------------------------------------------------------------------- the real thing
def test_the_combination_on_the_14_demo_events():
    pytest.importorskip("iot_ips")
    profiles = {d["device_id"]: d for d in json.loads((ROOT.parents[1] / "ips" / "config" / "devices.json").read_text())["devices"]}
    detect = make_detect()
    got = {}
    for e in pd.read_csv(DATA / "sample_events.csv").to_dict("records"):
        got[e["event_id"]] = (detect(e, profiles[e["device_id"]]), e["expected_label"])
    wrong = sorted(k for k, (d, want) in got.items() if d["label"] != want)
    assert wrong == ["EVT-013"]                                   # the rules miss 3 attacks, the model recovers 2
    for benign in ("EVT-001", "EVT-002", "EVT-003", "EVT-004"):
        assert got[benign][0]["label"] == "BENIGN"               # no false alarm on normal traffic
    assert got["EVT-007"][0]["detector"] == "ml" and got["EVT-012"][0]["attack_type"] == "Spoofing"


def test_false_alarms_on_normal_windows_at_the_chosen_confidence():
    """The README's number: 5.7% at 0.5 but about 0.1% at 0.9, measured on the 20,000 normal test windows."""
    test = pd.read_csv(DATA / "test.csv")
    normal = test[test["label"] == "BENIGN"]
    binary, _ = ml_detector._models()
    p = binary["model"].predict_proba(normal[MODEL_FEATURES])[:, 1]
    assert (p > 0.5).mean() == pytest.approx(0.057, abs=0.002)
    assert (p > 0.90).mean() < 0.003
