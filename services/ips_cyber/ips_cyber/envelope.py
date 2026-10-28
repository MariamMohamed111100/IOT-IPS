"""envelope.py - builds the alert envelope the backend accepts on security/alerts/cyber.

Envelope (CONTRACT section 2, the same keys services/api/mqtt_handler.py checks):
    {"id", "ts", "source", "type", "zone", "severity_hint", "data"}

Every value that came from a CSV / PCAP is untrusted text: it is cleaned and
length-limited here before it goes on the bus.
"""
import re
import uuid
from datetime import datetime, timezone

from iot_ips.detector import resolve_direction

TOKEN = re.compile(r"^[a-z0-9_]+$")
EVENT_TYPE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
LEVELS = ("low", "medium", "high", "critical")
CONTRACT_PROTOCOLS = ("TCP", "UDP", "ICMP", "GRE")     # enum of contract/ips_event_data.schema.json
REQUIRED_DATA = ("src_ip", "dst_ip", "dst_port", "protocol", "direction", "device_id", "confidence",
                 "mitre_technique", "failed_attempts", "connection_attempts", "duration")   # CONTRACT 3.1
ENVELOPE_KEYS = {"id", "ts", "source", "type", "zone", "severity_hint", "data"}
NAMESPACE = uuid.UUID("b4c1f0de-5a77-4c63-8f0e-2d9a7b6c1e42")   # ids of cyber-service alerts only

# canonical attack name -> backend event type (same table as scripts/ips/ips_to_backend.py)
ATTACK_EVENT_TYPES = {
    "port_scan": "cyber.port_scan",
    "brute_force": "cyber.brute_force",
    "dos": "cyber.dos",
    "unexpected_protocol": "cyber.unexpected_traffic",
    "unexpected_protocol_port": "cyber.unexpected_traffic",
    "unexpected_traffic": "cyber.unexpected_traffic",
    # the ML model's attack groups (services/ml) onto the four IPS event types of the contract (3.1):
    "recon": "cyber.port_scan", "reconnaissance": "cyber.port_scan",
    "bruteforce": "cyber.brute_force",
    "ddos": "cyber.dos", "mirai": "cyber.dos",                       # floods, as the engine scores them (40)
    "spoofing": "cyber.unexpected_traffic", "web": "cyber.unexpected_traffic", "web_based": "cyber.unexpected_traffic",
}


class AlertError(ValueError):
    """The alert cannot be built or would be rejected by the backend."""


def token(value, default="unknown"):
    """Lowercase letters, digits and underscores only: CAM-001 -> cam_001."""
    s = re.sub(r"[^a-z0-9]+", "_", str(value if value is not None else "").lower()).strip("_")
    return s or default


def clean_text(value, limit=64):
    """Drop control characters and cap the length."""
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(value if value is not None else "")).strip()[:limit]


def to_int(value):
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return int(f) if f == f and abs(f) < 10 ** 12 else None


def to_float(value):
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if f == f and abs(f) != float("inf") else None


def iso(value=None):
    """UTC ISO-8601 with milliseconds (CONTRACT: ts is never local time)."""
    moment = None
    if isinstance(value, datetime):
        moment = value
    elif value:
        try:
            moment = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except ValueError:
            moment = None
    moment = moment or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def event_type(attack_type):
    key = token(attack_type)
    return ATTACK_EVENT_TYPES.get(key) or "cyber." + key


def severity_hint(confidence, cfg):
    """low / medium / high from the detector confidence (never critical: the risk engine decides that)."""
    c = to_float(confidence) or 0.0
    if c >= cfg["high_from"]:
        return "high"
    if c >= cfg["medium_from"]:
        return "medium"
    return "low"


def alert_id(source_name, event_ref):
    """Deterministic: replaying the same file gives the same ids (the API ignores duplicates)."""
    return str(uuid.uuid5(NAMESPACE, "%s:%s" % (source_name, event_ref)))


def build_alert(event, detection, profile, source_name, event_ref, config):
    """One ATTACK detection -> alert envelope. Raises AlertError if it cannot be built."""
    if not isinstance(event, dict) or not event.get("device_id"):
        raise AlertError("event has no device_id")
    if not isinstance(detection, dict) or detection.get("label") != "ATTACK":
        raise AlertError("only ATTACK detections become alerts")

    ips_id = clean_text(event.get("device_id"), 64)
    bdev = token(ips_id)[:100]
    zone = token(config.get("default_zone"), "network")        # CONTRACT 12: every cyber event uses zone "network"
    # (the device's room is not used: the engine would treat a network attack as a physical event there)
    etype = event_type(detection.get("attack_type"))
    protocol = clean_text(event.get("protocol"), 16).upper()
    if protocol not in CONTRACT_PROTOCOLS:
        raise AlertError("protocol %r is not one the contract accepts (%s)" % (protocol, ", ".join(CONTRACT_PROTOCOLS)))
    # The eleven fields of CONTRACT 3.1 are always present. What the source did not measure is 0 (never
    # invented): the same rule as docs/IPS_INTEGRATION.md ("duration: 0 when missing").
    failed = to_int(event.get("failed_attempts")) or 0
    conns = to_int(event.get("connection_attempts")) or 0
    duration = max(0.0, to_float(event.get("duration")) or 0.0)

    data = {
        "src_ip": clean_text(event.get("src_ip")) or None,
        "dst_ip": clean_text(event.get("dst_ip")) or None,
        "dst_port": to_int(event.get("dst_port")),
        "protocol": protocol,
        "direction": resolve_direction(event, profile),     # the same rule the detector used
        "device_id": bdev,
        "ips_device_id": ips_id,
        "target": bdev,
        "attack_type": clean_text(detection.get("attack_type")),
        "confidence": round(float(detection.get("confidence", 0)), 3),
        "mitre_technique": clean_text(detection.get("mitre_technique"), 16) or None,
        "failed_attempts": failed,
        "connection_attempts": conns,
        "unique_dst_ports": to_int(event.get("unique_dst_ports")),
        "unique_dst_ips": to_int(event.get("unique_dst_ips")),
        "duration": duration,
        # "attempts" keeps the field name scripts/ips/ips_to_backend.py already uses
        "attempts": failed if etype == "cyber.brute_force" else conns,
    }
    if etype == "cyber.port_scan" and data["dst_port"] is not None:
        data["ports"] = [data["dst_port"]]
    data = {k: v for k, v in data.items() if v is not None}
    missing = [k for k in REQUIRED_DATA if k not in data]
    if missing:
        raise AlertError("the event lacks required field(s) %s" % ", ".join(missing))

    alert = {
        "id": alert_id(source_name, event_ref),
        "ts": iso(event.get("timestamp")),
        "source": clean_text(config.get("source", "cyber"), 100),
        "type": etype,
        "zone": zone,
        "severity_hint": severity_hint(detection.get("confidence"), config["severity"]),
        "data": data,
    }
    validate_alert(alert)
    return alert


def validate_alert(payload):
    """Raise AlertError unless the backend would accept the payload (mirrors mqtt_handler.py)."""
    import json
    if not isinstance(payload, dict):
        raise AlertError("alert must be an object")
    missing = ENVELOPE_KEYS - set(payload)
    if missing:
        raise AlertError("missing key(s) %s" % sorted(missing))
    extra = set(payload) - ENVELOPE_KEYS
    if extra:
        raise AlertError("unknown key(s) %s" % sorted(extra))
    if not isinstance(payload["id"], str) or not 8 <= len(payload["id"]) <= 100:
        raise AlertError("bad id")
    if not isinstance(payload["source"], str) or not payload["source"] or len(payload["source"]) > 100:
        raise AlertError("bad source")
    if not EVENT_TYPE.match(str(payload["type"])):
        raise AlertError("bad type %r" % payload["type"])
    if not TOKEN.match(str(payload["zone"])):
        raise AlertError("bad zone %r" % payload["zone"])
    if payload["severity_hint"] not in ("info",) + LEVELS:
        raise AlertError("bad severity_hint")
    if not isinstance(payload["data"], dict) or len(json.dumps(payload["data"])) > 32 * 1024:
        raise AlertError("data must be an object under 32 KB")
    try:
        datetime.fromisoformat(str(payload["ts"]))
    except ValueError:
        raise AlertError("ts is not ISO-8601: %r" % payload["ts"]) from None
