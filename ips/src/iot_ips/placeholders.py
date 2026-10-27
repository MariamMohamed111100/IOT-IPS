"""
placeholders.py - a minimal threshold detector used only for testing.

The pipeline's unit tests run it (``--detector placeholder``) so that they do not depend on the
thresholds of the real rule-based detector in detector.py. It follows the same contract:
detect(event) -> {"label", "attack_type", "confidence", "mitre_technique"}.

It is deliberately simple and is NOT a security control.
"""

from __future__ import annotations

import math
import numbers
from collections.abc import Mapping
from typing import Any, Optional

__all__ = ["detect"]

_REMOTE_LOGIN_PORTS = {21, 22, 23, 554, 3389}


def _num(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, numbers.Real):
        number = float(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text or len(text) > 32:
            return None
        try:
            number = float(text)
        except ValueError:
            return None
    else:
        return None
    return number if math.isfinite(number) else None


def detect(event: Any) -> dict:
    """Threshold detector (test stand-in for detector.py). Returns the Detection message."""
    if not isinstance(event, Mapping):
        event = {}
    failed = _num(event.get("failed_attempts"))
    conns = _num(event.get("connection_attempts"))
    port = _num(event.get("dst_port"))
    rate = _num(event.get("Rate"))
    syn = _num(event.get("syn_flag_number"))

    if failed is not None and failed >= 10 and port is not None and int(port) in _REMOTE_LOGIN_PORTS:
        return {"label": "ATTACK", "attack_type": "brute_force", "confidence": round(min(0.95, 0.60 + failed / 200.0), 2),
                "mitre_technique": "T1110"}
    if (rate is not None and rate >= 5000) or (syn is not None and syn >= 500):
        return {"label": "ATTACK", "attack_type": "dos",
                "confidence": 0.95 if (rate is not None and rate >= 20000) else 0.85, "mitre_technique": "T1498"}
    if conns is not None and conns >= 20:
        return {"label": "ATTACK", "attack_type": "port_scan", "confidence": 0.70, "mitre_technique": "T1046"}
    if conns is not None and conns >= 5:
        return {"label": "ATTACK", "attack_type": "port_scan", "confidence": 0.45, "mitre_technique": "T1046"}
    return {"label": "BENIGN", "attack_type": "benign", "confidence": 0.90, "mitre_technique": None}
