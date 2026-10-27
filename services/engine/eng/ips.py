"""IPS details for incidents (docs/IPS_INTEGRATION.md).

Two jobs, both optional:

* `clean_details(raw)`   checks the `details` object an IPS adapter sent inside an alert and keeps
                         only what contract/incident_details.schema.json allows.
* `IpsEnricher.enrich()` for an IPS alert that arrived WITHOUT details (for example from
                         services/ips_cyber) runs the IPS chain, risk engine -> policy (dry run) -> reports,
                         and returns the details object. It never runs an action: the engine's own
                         `block_ip` is the only thing that blocks.

The `iot_ips` package is optional. Without it the engine works exactly as before and incidents simply
have no details.
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

log = logging.getLogger("engine.ips")

IPS_TYPES = {"cyber.port_scan": "Port Scan", "cyber.brute_force": "Brute Force",
             "cyber.dos": "DoS", "cyber.unexpected_traffic": "Unexpected Protocol/Port"}
LEVELS = ("low", "medium", "high", "critical")
MAX_REPORT_CHARS = 12 * 1024
MITRE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")
BANDS = [(0, 29, 0, 30), (30, 59, 31, 60), (60, 79, 61, 90), (80, 100, 91, 100)]   # IPS band -> published band


def to_published(ips_score: Any) -> int:
    """IPS score (bands 0/30/60/80) -> published score (0/31/61/91). Same function as IPS_INTEGRATION section 5."""
    try:
        s = max(0.0, min(100.0, float(ips_score)))
    except (TypeError, ValueError):
        return 0
    for lo, hi, out_lo, out_hi in BANDS:
        if s <= hi or hi == 100:
            return int(round(out_lo + (min(s, hi) - lo) * (out_hi - out_lo) / (hi - lo)))
    return 100


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100 else None


def _text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", value)
    return text if len(text) <= MAX_REPORT_CHARS else text[:MAX_REPORT_CHARS - 16] + "\n...[truncated]"


def clean_details(raw: Any) -> dict | None:
    """The valid part of an IPS details object, or None when nothing usable is left."""
    if not isinstance(raw, dict):
        return None
    out: dict = {}
    if isinstance(raw.get("mitre_technique"), str) and MITRE.match(raw["mitre_technique"]):
        out["mitre_technique"] = raw["mitre_technique"]
    for key in ("ips_score", "ips_score_raw"):
        if _int(raw.get(key)) is not None:
            out[key] = raw[key]
    if raw.get("ips_level") in LEVELS:
        out["ips_level"] = raw["ips_level"]
    reports = raw.get("reports")
    if isinstance(reports, dict):
        kept = {k: _text(reports.get(k)) for k in ("technical", "executive")}
        kept = {k: v for k, v in kept.items() if v is not None}
        if kept:
            out["reports"] = kept
    return out if "ips_score" in out and "ips_level" in out else None


def _seconds_text(value: Any) -> str | None:
    return "%d seconds" % value if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else None


class IpsEnricher:
    """Builds `details` for an IPS alert with the IPS modules. Create it with `IpsEnricher.load()`."""

    def __init__(self, modules: Any, profiles: dict[str, dict]) -> None:
        self.m = modules
        self.profiles = profiles                      # backend_id -> IPS device profile

    @classmethod
    def load(cls, devices_file: str | Path | None = None) -> "IpsEnricher | None":
        """None (and one log line) when the iot_ips package is not installed or its config is unusable."""
        try:
            from iot_ips import policy, report, risk
        except ImportError:
            log.info("iot_ips is not installed: incidents will have no IPS details")
            return None
        path = Path(devices_file or os.getenv("IPS_DEVICES_FILE", "/config/ips_devices.json"))
        try:
            profiles = {d["backend_id"]: d for d in json.loads(path.read_text(encoding="utf-8"))["devices"]
                        if isinstance(d, dict) and d.get("backend_id")}
        except (OSError, ValueError, KeyError, TypeError):
            log.warning("could not read %s: IPS details need the device profiles", path)
            return None

        class Modules:
            pass
        mods = Modules()
        mods.policy, mods.report, mods.risk = policy, report, risk
        return cls(mods, profiles)

    def enrich(self, event: Any) -> dict | None:
        """details for one IPS alert, or None. Never raises."""
        attack = IPS_TYPES.get(getattr(event, "type", None))
        data = getattr(event, "data", None)
        if attack is None or not isinstance(data, dict):
            return None
        try:
            profile = dict(self.profiles.get(data.get("device_id"), {}))
            ev = {"timestamp": event.ts, "src_ip": data.get("src_ip"), "dst_ip": data.get("dst_ip"),
                  "dst_port": data.get("dst_port"), "protocol": data.get("protocol"),
                  "direction": data.get("direction"), "device_id": profile.get("device_id"),
                  "failed_attempts": data.get("failed_attempts"),
                  "connection_attempts": data.get("connection_attempts"),
                  "duration": _seconds_text(data.get("duration"))}
            mitre = data.get("mitre_technique")
            detection = {"label": "ATTACK", "attack_type": attack, "confidence": data.get("confidence", 0),
                         "mitre_technique": mitre if isinstance(mitre, str) and MITRE.match(mitre) else None}
            risk_msg = self.m.risk.assess(detection, ev, profile)
            decision = self.m.policy.decide(risk_msg, detection, ev, profile)       # dry run: nothing is executed
            inc = self.m.report.build_incident(ev, detection, risk_msg, decision, profile, incident_id=event.id)
            rep = self.m.report.make_report(inc)
            raw = risk_msg.get("score")
            level = str(risk_msg.get("level", "")).lower()
            if not isinstance(raw, (int, float)) or level not in LEVELS:
                return None
            raw = max(0, min(100, int(round(raw))))
            return clean_details({"mitre_technique": detection["mitre_technique"] or None,
                                  "ips_score": to_published(raw), "ips_level": level, "ips_score_raw": raw,
                                  "reports": {"technical": rep.get("technical"), "executive": rep.get("executive")}})
        except Exception:
            log.exception("IPS enrichment failed for %s", getattr(event, "id", "?"))
            return None
