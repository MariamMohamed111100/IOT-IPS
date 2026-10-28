"""Step 4: the ML detector, same interface as the rule-based detector (Person 3).

    from detector import detect
    detection = detect(event, profile)
    # {"label": "ATTACK", "attack_type": "BruteForce", "confidence": 0.93,
    #  "mitre_technique": "T1110.001", "detector": "ml", "notes": [...]}

`event` = one row of features (the CICIoT2023 column names, as produced by extractor.py or as
in sample_events.csv) plus the context fields; `profile` = the device profile (device_id,
expected_protocols, expected_ports, ...). The model decides the label from the features only;
the profile adds notes (an unexpected port or protocol) for the risk engine, it does not change
the label. Anything the model cannot judge (a missing or non-numeric feature) raises ValueError.
"""
from __future__ import annotations

import hashlib
import math
from functools import cache
from pathlib import Path

import joblib
import pandas as pd

HERE = Path(__file__).resolve().parent
# attack group -> MITRE ATT&CK technique
MITRE = {
    "DDoS": "T1498.001",        # Network Denial of Service: Direct Network Flood
    "DoS": "T1498.001",
    "Mirai": "T1498",           # botnet flood
    "Recon": "T1046",           # Network Service Discovery
    "Spoofing": "T1557.002",    # Adversary-in-the-Middle: ARP Cache Poisoning
    "BruteForce": "T1110.001",  # Brute Force: Password Guessing
    "Web": "T1190",             # Exploit Public-Facing Application
}


class ModelIntegrityError(RuntimeError):
    """A model file is not the one that was trained (its SHA-256 differs from models/MODELS.sha256)."""


def verify_models(folder: Path = HERE / "models") -> None:
    """A .joblib file is a pickle, and loading a pickle runs code: check the hash BEFORE loading."""
    try:
        listed = dict(line.split()[::-1] for line in (folder / "MODELS.sha256").read_text().splitlines() if line.strip())
    except (OSError, ValueError) as exc:
        raise ModelIntegrityError(f"cannot read {folder / 'MODELS.sha256'}: {exc}") from exc
    for name in ("binary.joblib", "attack_type.joblib"):
        try:
            actual = hashlib.sha256((folder / name).read_bytes()).hexdigest()
        except OSError as exc:
            raise ModelIntegrityError(f"cannot read {name}: {exc}") from exc
        if listed.get(name) != actual:
            raise ModelIntegrityError(f"{name} does not match models/MODELS.sha256: not loading it")


@cache
def _models():
    verify_models()
    binary = joblib.load(HERE / "models" / "binary.joblib")
    typer = joblib.load(HERE / "models" / "attack_type.joblib")
    for saved in (binary, typer):
        if hasattr(saved["model"], "n_jobs"):
            saved["model"].n_jobs = 1      # one event at a time: worker start-up costs more
    return binary, typer


def _features(event: dict, names: list[str]) -> pd.DataFrame:
    missing = [n for n in names if n not in event]
    if missing:
        raise ValueError(f"event lacks features {missing}")
    values = {}
    for n in names:
        try:
            v = float(event[n])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"feature {n!r} is not a number: {event[n]!r}") from exc
        if not math.isfinite(v):
            raise ValueError(f"feature {n!r} is not finite: {v}")
        values[n] = v
    return pd.DataFrame([values], columns=names)


def _profile_notes(event: dict, profile: dict | None) -> list[str]:
    if not profile:
        return []
    notes = []
    port, proto = event.get("dst_port"), event.get("protocol")
    ports = {int(p) for p in profile.get("expected_ports", [])}
    protos = {str(p).upper() for p in profile.get("expected_protocols", [])}
    to_device = profile.get("ip") is None or event.get("dst_ip") == profile.get("ip")
    if to_device and ports and port is not None and int(port) not in ports:
        notes.append(f"port {int(port)} is not expected for {profile.get('device_id', 'device')}")
    if protos and proto and str(proto).upper() not in protos:
        notes.append(f"protocol {proto} is not expected for {profile.get('device_id', 'device')}")
    return notes


def detect(event: dict, profile: dict | None = None) -> dict:
    binary, typer = _models()
    x = _features(event, binary["features"])
    p_attack = float(binary["model"].predict_proba(x)[0, 1])
    notes = _profile_notes(event, profile)
    if p_attack > binary["threshold"]:
        proba = typer["model"].predict_proba(x[typer["features"]])[0]
        best = int(proba.argmax())
        attack_type = str(typer["model"].classes_[best])
        return {"label": "ATTACK", "attack_type": attack_type,
                "confidence": round(p_attack, 3), "mitre_technique": MITRE[attack_type],
                "attack_type_confidence": round(float(proba[best]), 3),
                "detector": "ml", "notes": notes}
    return {"label": "BENIGN", "attack_type": None, "confidence": round(1 - p_attack, 3),
            "mitre_technique": None, "detector": "ml", "notes": notes}
