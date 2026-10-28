"""detect(event, profile): contract shape, errors, profile notes, and the 14 sample events."""
import math
import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ids_ml.detector import MITRE, detect
from ids_ml.extractor import FEATURES

EVENTS = pd.read_csv(ROOT.parents[1] / "ips" / "data" / "sample_events.csv")
CAM = {"device_id": "CAM-001", "ip": "192.168.1.50", "expected_ports": [554, 443, 53],
       "expected_protocols": ["TCP", "UDP"]}


def event(i):
    return EVENTS.iloc[i].to_dict()


def test_detection_has_the_contract_fields_for_every_sample_event():
    for i in range(len(EVENTS)):
        d = detect(event(i), CAM)
        assert d["label"] in ("BENIGN", "ATTACK")
        assert 0.5 <= d["confidence"] <= 1.0                  # confidence in the chosen label
        if d["label"] == "ATTACK":
            assert d["attack_type"] in MITRE and d["mitre_technique"] == MITRE[d["attack_type"]]
        else:
            assert d["attack_type"] is None and d["mitre_technique"] is None


def test_clear_cases():
    # Sanity only: the floods and the clearest normal event. The full 14-event result (some
    # are missed, honestly reported) is in samples_result.md, made by try_samples.py.
    by_id = {r["event_id"]: detect(r) for r in EVENTS.to_dict("records")}
    for eid, kind in (("EVT-010", "DDoS"), ("EVT-011", "DoS"), ("EVT-014", "Mirai")):
        assert by_id[eid]["label"] == "ATTACK" and by_id[eid]["attack_type"] == kind
    assert by_id["EVT-004"]["label"] == "BENIGN"               # owner logs in to the plug


def test_the_detector_ignores_the_answer_columns():
    e = event(9)                                               # DDoS
    flipped = e | {"expected_label": "BENIGN", "expected_attack_type": "Benign",
                   "original_label": "BENIGN", "story": "nothing to see"}
    assert detect(e) == detect(flipped)


def test_profile_notes_do_not_change_the_label():
    e = event(7)                                               # SSH brute force on port 22
    plain, with_profile = detect(e), detect(e, CAM)
    assert plain["label"] == with_profile["label"]
    assert any("port 22 is not expected" in n for n in with_profile["notes"])
    assert plain["notes"] == []


@pytest.mark.parametrize("change, message", [
    (lambda e: e.pop("Max"), "lacks features"),
    (lambda e: e.update(Max="big"), "not a number"),
    (lambda e: e.update(Max=math.inf), "not finite"),
])
def test_bad_events_are_rejected(change, message):
    e = event(0)
    change(e)
    with pytest.raises(ValueError, match=message):
        detect(e)


def test_extractor_rows_can_be_detected_directly():
    row = {f: event(0)[f] for f in FEATURES}                  # what extractor.py produces
    assert detect(row)["label"] in ("BENIGN", "ATTACK")
