"""The rule-based detector and the ML model together: one `detect(event, profile)` for the pipeline.

    from ids_ml.combined import make_detect
    detect = make_detect()                    # pass it as `detect_fn` to services/ips_cyber

Why both: the rules know the context (failed logins, ports, connections), the model only sees 16 packet
statistics of a 10-packet window. On the test part the model alone raises 5.7% false alarms on normal
windows (and 5.8% on windows it never saw in training); at confidence 0.90 that is 0.1%, which is why the
model may add an alert on its own only at `min_ml_confidence` (default 0.90). It misses 32% of the attacks
at that level, so it supplements the rules and never replaces them.

  rules say ATTACK            -> the rules' answer; a note says whether the model agrees
  rules BENIGN, ML >= 0.90    -> ATTACK from the model (detector "ml"), noted as "the rules saw nothing"
  otherwise                   -> BENIGN (the rules' answer)
An event without the model's features (a flow-engine event, for example) is judged by the rules alone.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

DEFAULT_MIN_ML_CONFIDENCE = 0.90


def make_detect(min_ml_confidence: float = DEFAULT_MIN_ML_CONFIDENCE, rules: Callable[..., dict] | None = None,
                ml: Callable[..., dict] | None = None) -> Callable[[dict, dict | None], dict]:
    if not 0.5 <= min_ml_confidence <= 1.0:
        raise ValueError("min_ml_confidence must be between 0.5 and 1.0")
    if rules is None:
        from iot_ips import detector as rule_detector
        rules = rule_detector.detect
    if ml is None:
        from .detector import detect as ml_detect
        ml = ml_detect

    def detect(event: dict, profile: dict | None = None) -> dict[str, Any]:
        verdict = dict(rules(dict(event), dict(profile)) if profile else rules(dict(event)))
        try:
            second = ml(event, profile)
        except ValueError as exc:                     # a missing, non-numeric or infinite feature
            verdict.setdefault("notes", []).append(f"ml not used: {exc}"[:120])
            return verdict
        notes = list(verdict.get("notes") or [])
        if verdict.get("label") == "ATTACK":
            same = second["label"] == "ATTACK"
            notes.append("ml agrees: %s (%.2f)" % (second["attack_type"], second["confidence"]) if same
                         else "ml did not flag this window")
            return {**verdict, "notes": notes, "ml_agrees": same}
        if second["label"] == "ATTACK" and second["confidence"] >= min_ml_confidence:
            return {**second, "notes": notes + second.get("notes", []) + ["the rules saw nothing; the model did"]}
        return {**verdict, "notes": notes}

    return detect
