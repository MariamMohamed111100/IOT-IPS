"""ips_to_backend.py - turns an IoT-IPS detection into the events of contract v1.2 (docs/IPS_INTEGRATION.md).

Pure functions, no network. The IPS adapter publishes ONLY events on `security/alerts/cyber` (zone "network"):
  cyber.port_scan | cyber.brute_force | cyber.dos | cyber.unexpected_traffic   the detection (CONTRACT 3.1)
  cyber.block_applied | cyber.block_refused                                    what the IPS policy did (dry run)
The backend `engine` turns the detections into incidents. `standalone_messages()` can also build the incident and
risk messages, but only for demos without a running engine (the engine owns incidents and risk).
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent.parent
TOKEN = re.compile(r"^[a-z0-9_]+$")
EVENT_TYPE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
NAMESPACE = uuid.UUID("6f1d2c52-6c0e-4d0b-9d6e-0b1c6d3b7a11")
LEVELS = ("low", "medium", "high", "critical")
MAX_REPORT_CHARS = 12 * 1024          # per report; the API drops an event whose data is over 32 KB in total
MAX_DATA_BYTES = 32 * 1024
NETWORK_ACTIONS = ("block_source", "temporary_block", "isolate_device")

ATTACK_EVENT_TYPES = {
    "port_scan": "cyber.port_scan", "reconnaissance": "cyber.port_scan",
    "brute_force": "cyber.brute_force",
    "dos": "cyber.dos", "ddos": "cyber.dos",
    "unexpected_protocol_port": "cyber.unexpected_traffic", "unexpected_protocol": "cyber.unexpected_traffic",
    "unexpected_traffic": "cyber.unexpected_traffic",
}
DEFAULT_MITRE = {"cyber.port_scan": "T1046", "cyber.brute_force": "T1110", "cyber.dos": "T1498",
                 "cyber.unexpected_traffic": "T1571"}
SERVICE_NAMES = {22: "ssh", 23: "telnet", 554: "rtsp"}
BANDS = [(0, 29, 0, 30), (30, 59, 31, 60), (60, 79, 61, 90), (80, 100, 91, 100)]   # IPS band -> published band


# ----------------------------------------------------------------------------- helpers
def token(value: Any, default: str = "unknown") -> str:
    s = re.sub(r"[^a-z0-9]+", "_", str(value if value is not None else "").lower()).strip("_")
    return s or default


def backend_device_id(ips_id: Any, profile: Optional[dict] = None) -> str:
    """The profile's backend_id (config/ips_devices.json) wins; otherwise lowercase and replace - by _."""
    given = (profile or {}).get("backend_id")
    return str(given) if isinstance(given, str) and TOKEN.match(given) else token(ips_id)[:50]


def to_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool) or value is None:
        return default
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    return int(f) if f == f and 0 <= abs(f) < 10 ** 12 else default


def to_float(value: Any, default: float = 0.0) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    return f if f == f and abs(f) != float("inf") else default


def duration_seconds(value: Any) -> int:
    """Seconds from a number or text such as '4 minutes' / '90 seconds'; 0 when missing."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0, int(value))
    m = re.match(r"^\s*(\d+(?:\.\d+)?)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hour|hours)?\s*$",
                 str(value or "").lower())
    if not m:
        return 0
    unit = (m.group(2) or "s")[0]
    return int(float(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[unit])


def level_of(value: Any) -> str:
    v = str(value or "").strip().lower()
    return v if v in LEVELS else "low"


def to_published(ips_score: Any) -> int:
    """IPS score (bands 0/30/60/80) -> published score (bands 0/31/61/91). Never decreases; levels keep their names."""
    s = max(0.0, min(100.0, to_float(ips_score)))
    for lo, hi, out_lo, out_hi in BANDS:
        if s <= hi or hi == 100:
            return int(round(out_lo + (min(s, hi) - lo) * (out_hi - out_lo) / (hi - lo)))
    return 100


def iso(value: Any = None) -> str:
    moment = value if isinstance(value, datetime) else None
    if moment is None and value:
        try:
            moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            moment = None
    moment = moment or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def event_type(attack_type: Any) -> str:
    key = token(attack_type)
    return ATTACK_EVENT_TYPES.get(key) or "cyber." + key


def event_id(incident_id: Any, kind: str, seq: int = 0) -> str:
    """Deterministic: the same input gives the same ids (the API ignores duplicate events)."""
    return str(uuid.uuid5(NAMESPACE, "%s:%s:%d" % (incident_id, kind, seq)))


def clip(text: Any, limit: int) -> str:
    s = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", str(text if text is not None else ""))
    return s if len(s) <= limit else s[:limit - 16] + "\n...[truncated]"


def _protocol(value: Any) -> str:
    p = str(value or "").strip().upper()
    return p if p in ("TCP", "UDP", "ICMP", "GRE") else "TCP"      # the contract allows only these four


# ----------------------------------------------------------------------------- the messages
def detection_event(inc: dict, event: Optional[dict] = None, report: Optional[dict] = None,
                    profile: Optional[dict] = None, *, ts: Any = None, seq: int = 0) -> dict:
    """One detection as a contract event. inc: build_incident() output; event: the IPS event (numbers, direction ...)."""
    ev = event or {}
    etype = event_type(inc.get("attack_type"))
    mitre = str(inc.get("mitre_technique") or "")
    mitre = mitre if re.match(r"^T\d{4}(\.\d{3})?$", mitre) else DEFAULT_MITRE.get(etype, "T1595")
    level, raw = level_of(inc.get("level")), max(0, min(100, to_int(inc.get("score"))))
    port = to_int(inc.get("dst_port", ev.get("dst_port")))
    failed = to_int(ev.get("failed_attempts"))
    seconds = duration_seconds(ev.get("duration", inc.get("duration")))
    rep = report or {}
    data: Dict[str, Any] = {
        "src_ip": clip(inc.get("src_ip") or ev.get("src_ip") or "unknown", 45),
        "dst_ip": clip(inc.get("dst_ip") or ev.get("dst_ip") or "unknown", 45),
        "dst_port": min(port, 65535), "protocol": _protocol(inc.get("protocol") or ev.get("protocol")),
        "direction": "outbound" if str(ev.get("direction") or "").lower() == "outbound" else "inbound",
        "device_id": backend_device_id(inc.get("device_id"), profile),
        "confidence": round(min(1.0, to_float(inc.get("confidence"))), 3), "mitre_technique": mitre,
        "failed_attempts": failed, "connection_attempts": to_int(ev.get("connection_attempts")), "duration": seconds,
    }
    if etype == "cyber.port_scan":
        data.update(ports=[], port_count=to_int(ev.get("unique_dst_ports")), hosts_probed=to_int(ev.get("unique_dst_ips")))
    elif etype == "cyber.brute_force":
        data.update(target=SERVICE_NAMES.get(port, str(port)), attempts=failed, window_s=seconds)
    data["details"] = {"mitre_technique": mitre, "ips_score": to_published(raw), "ips_level": level, "ips_score_raw": raw,
                       "reports": {"technical": clip(rep.get("technical"), MAX_REPORT_CHARS),
                                   "executive": clip(rep.get("executive"), MAX_REPORT_CHARS)}}
    while len(json.dumps(data)) > MAX_DATA_BYTES - 1024:           # keep the whole event under the API limit
        data["details"]["reports"] = {k: clip(v, len(v) // 2) for k, v in data["details"]["reports"].items()}
    return {"id": event_id(inc.get("id"), "alert", seq), "ts": iso(ts or inc.get("timestamp")), "source": "cyber",
            "type": etype, "zone": "network", "severity_hint": level, "data": data}


def block_events(inc: dict, profile: Optional[dict] = None, *, ts: Any = None) -> List[dict]:
    """cyber.block_applied for every network action the policy took (dry run), cyber.block_refused for skipped ones."""
    out, base = [], iso(ts or inc.get("timestamp"))
    device = backend_device_id(inc.get("device_id"), profile)
    reason = token(inc.get("rule_id"), "policy")[:64]

    def make(kind: str, action: str, ip: Any, why: str) -> dict:
        data = {"ip": clip(ip or "unknown", 45), "action": action, "device_id": device, "reason": why[:64], "dry_run": True}
        return {"id": event_id(inc.get("id"), "%s:%s" % (kind, action)), "ts": base, "source": "cyber",
                "type": "cyber." + kind, "zone": "network", "severity_hint": "info", "data": data}
    for action in [a for a in (inc.get("actions") or []) if a in NETWORK_ACTIONS]:
        ip = (profile or {}).get("ip") if action == "isolate_device" else inc.get("src_ip")
        out.append(make("block_applied", action, ip, reason))
    for s in inc.get("skipped") or []:
        action = s.get("action") if isinstance(s, dict) else None
        if action in NETWORK_ACTIONS:
            out.append(make("block_refused", action, inc.get("src_ip"), token(s.get("why"), "refused")))
    return out


def build_events(inc: dict, event: Optional[dict] = None, report: Optional[dict] = None,
                 profile: Optional[dict] = None, *, ts: Any = None, seq: int = 0) -> List[Tuple[str, dict]]:
    """[(topic, payload)] for one detection: the detection first, then the block results."""
    msgs = [("security/alerts/cyber", detection_event(inc, event, report, profile, ts=ts, seq=seq))]
    msgs += [("security/alerts/cyber", b) for b in block_events(inc, profile, ts=ts)]
    return msgs


def standalone_messages(inc: dict, detection: dict, *, ts: Any = None) -> List[Tuple[str, dict]]:
    """Risk and incident messages for demos WITHOUT the backend engine (the engine owns these in the real stack)."""
    when = iso(datetime.fromisoformat(detection["ts"]) + timedelta(seconds=1) if not ts else ts)
    d = detection["data"]["details"]
    zone = "network"
    risk = {"ts": when, "zone": zone, "level": d["ips_level"], "score": d["ips_score"],
            "factors": [{"type": detection["type"], "weight": d["ips_score"]}], "actions": ["log"]}
    incident = {"id": str(inc.get("id")), "ts": when, "zone": zone, "level": d["ips_level"], "score": d["ips_score"],
                "trigger": detection["type"], "events": [detection["id"]],
                "actions": [a for a in (inc.get("actions") or []) if a not in ("log", "create_incident")] or ["log"],
                "summary": "%s %s on %s from %s (%s, IPS score %d/100)" % (
                    d["ips_level"].capitalize(), inc.get("attack_type"), detection["data"]["device_id"],
                    detection["data"]["src_ip"], d["mitre_technique"], d["ips_score"])}
    return [("security/risk", risk), ("security/incidents", incident)]


# ----------------------------------------------------------------------------- validation
class MessageError(ValueError):
    pass


def _schema(name: str) -> dict:
    return json.loads((ROOT / "contract" / name).read_text(encoding="utf-8"))


def check_message(topic: str, payload: dict) -> None:
    """Raise MessageError unless the message follows the contract (envelope rules of the API + the JSON schemas)."""
    import jsonschema
    if topic.startswith("security/alerts/"):
        keys = {"id", "ts", "source", "type", "zone", "severity_hint", "data"}
        if set(payload) != keys:
            raise MessageError("%s: keys must be exactly %s" % (topic, sorted(keys)))
        if not 8 <= len(payload["id"]) <= 100 or not payload["source"] or not EVENT_TYPE.match(payload["type"]) \
                or not TOKEN.match(payload["zone"]) or payload["severity_hint"] not in ("info",) + LEVELS:
            raise MessageError("%s: bad id, source, type, zone or severity_hint" % topic)
        if not isinstance(payload["data"], dict) or len(json.dumps(payload["data"])) > MAX_DATA_BYTES:
            raise MessageError("%s: data must be an object under 32 KB" % topic)
        name = {"cyber.block_applied": "ips_block_data", "cyber.block_refused": "ips_block_data"}.get(payload["type"])
        if payload["type"] in ("cyber.port_scan", "cyber.brute_force", "cyber.dos", "cyber.unexpected_traffic"):
            name = "ips_event_data"
        try:
            if name:
                jsonschema.validate({k: v for k, v in payload["data"].items() if k != "details"}, _schema(name + ".schema.json"))
            if "details" in payload["data"]:
                jsonschema.validate(payload["data"]["details"], _schema("incident_details.schema.json"))
        except jsonschema.ValidationError as exc:
            raise MessageError("%s %s: %s" % (topic, payload["type"], exc.message))
    elif topic == "security/incidents":
        need = ("id", "ts", "zone", "level", "score", "trigger", "events", "actions", "summary")
        if any(k not in payload for k in need) or payload["level"] not in LEVELS or not isinstance(payload["score"], int):
            raise MessageError("incident: missing or bad field")
    elif topic == "security/risk":
        if payload.get("level") not in LEVELS or not isinstance(payload.get("score"), int):
            raise MessageError("risk: bad level or score")
    else:
        raise MessageError("unexpected topic " + topic)
