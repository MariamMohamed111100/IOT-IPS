"""enrich.py - the `details` object of a detection alert (docs/IPS_INTEGRATION.md sections 3, 5 and 6).

    from iot_ips.enrich import build_details
    details = build_details(alert, profile)       # alert: the contract event {"id", "ts", "type", "data": {...}}

`details` = MITRE technique, IPS score on the published 0/31/61/91 scale (and the raw 0-100 score), IPS level and the
technical and executive report as plain text. It is built from the alert alone with the IPS risk engine, the policy
(dry run: nothing is executed) and the report templates, so the sensor (services/ips_cyber) and the engine fallback
(services/engine/eng/ips.py) give the same answer for the same alert, which a test checks.

It never raises: a problem gives None and the alert is simply sent without details.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

from . import policy, report, risk

__all__ = ["IPS_TYPES", "build_details", "to_published"]

log = logging.getLogger("iot_ips.enrich")

IPS_TYPES = {"cyber.port_scan": "Port Scan", "cyber.brute_force": "Brute Force",
             "cyber.dos": "DoS", "cyber.unexpected_traffic": "Unexpected Protocol/Port"}
LEVELS = ("low", "medium", "high", "critical")
MAX_REPORT_CHARS = 12 * 1024
MAX_DATA_BYTES = 32 * 1024                      # the API drops an event whose data is larger
MITRE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")
BANDS = [(0, 29, 0, 30), (30, 59, 31, 60), (60, 79, 61, 90), (80, 100, 91, 100)]    # IPS band -> published band


def to_published(ips_score: Any) -> int:
    """IPS score (bands 0/30/60/80) -> published score (0/31/61/91). Never decreases; levels keep their names."""
    try:
        s = float(ips_score)
    except (TypeError, ValueError):
        return 0
    if s != s or s in (float("inf"), float("-inf")):                # NaN or infinite: not a score
        return 0
    s = max(0.0, min(100.0, s))
    for lo, hi, out_lo, out_hi in BANDS:
        if s <= hi or hi == 100:
            return int(round(out_lo + (min(s, hi) - lo) * (out_hi - out_lo) / (hi - lo)))
    return 100


def _text(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", value)
    return text if len(text) <= MAX_REPORT_CHARS else text[:MAX_REPORT_CHARS - 16] + "\n...[truncated]"


def build_details(alert: Any, profile: Optional[dict] = None) -> Optional[dict]:
    """details for one IPS alert, or None (not an IPS alert type, unusable data, or any failure)."""
    try:
        attack = IPS_TYPES.get(alert.get("type"))
        data = alert.get("data")
        if attack is None or not isinstance(data, dict):
            return None
        profile = dict(profile or {})
        duration = data.get("duration")
        event = {"timestamp": alert.get("ts"), "src_ip": data.get("src_ip"), "dst_ip": data.get("dst_ip"),
                 "dst_port": data.get("dst_port"), "protocol": data.get("protocol"),
                 "direction": data.get("direction"), "device_id": profile.get("device_id"),
                 "failed_attempts": data.get("failed_attempts"),
                 "connection_attempts": data.get("connection_attempts"),
                 "duration": "%d seconds" % duration
                 if isinstance(duration, (int, float)) and not isinstance(duration, bool) and duration >= 0 else None}
        mitre = data.get("mitre_technique")
        detection = {"label": "ATTACK", "attack_type": attack, "confidence": data.get("confidence", 0),
                     "mitre_technique": mitre if isinstance(mitre, str) and MITRE.match(mitre) else None}
        risk_msg = risk.assess(detection, event, profile)
        decision = policy.decide(risk_msg, detection, event, profile)             # dry run: nothing is executed
        incident = report.build_incident(event, detection, risk_msg, decision, profile, incident_id=alert.get("id"))
        text = report.make_report(incident)
        raw, level = risk_msg.get("score"), str(risk_msg.get("level", "")).lower()
        if not isinstance(raw, (int, float)) or isinstance(raw, bool) or level not in LEVELS:
            return None
        raw = max(0, min(100, int(round(raw))))
        details: dict = {"ips_score": to_published(raw), "ips_level": level, "ips_score_raw": raw}
        if detection["mitre_technique"]:
            details = {"mitre_technique": detection["mitre_technique"], **details}
        reports = {k: _text(text.get(k)) for k in ("technical", "executive")}
        reports = {k: v for k, v in reports.items() if v}
        if reports:
            details["reports"] = reports
        while len(json.dumps({**data, "details": details})) > MAX_DATA_BYTES - 1024 and reports:   # keep the event small
            reports = {k: v[:len(v) // 2] for k, v in reports.items()}
            details["reports"] = reports
        return details
    except Exception:
        log.exception("could not build the IPS details")
        return None
