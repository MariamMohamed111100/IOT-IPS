"""MQTT -> database ingestion, plus live push to connected dashboards.

Everything that arrives over MQTT is untrusted until validated: one malformed message must
never be stored (it would later break the listing endpoints for everyone) and must never stop
the other messages from being processed.
"""
import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, StrictBool, StrictInt, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from database import SessionLocal
from models import Device, Incident, RiskState
from models import Event as EventRow
from smartsecure_common import Event as Envelope
from storage import seal_json, seal_text
from websocket_manager import manager

logger = logging.getLogger("api.mqtt")

MAX_PAYLOAD_BYTES = 64 * 1024
MAX_DATA_BYTES = 32 * 1024
_TOKEN = re.compile(r"^[a-z0-9_]+$")

# Re-applied on EVERY (re)connect: the session is clean, so the broker forgets subscriptions
# whenever it restarts or the network drops.
SUBSCRIPTIONS = (
    "home/+/+/+/event",      # device events (simulators / real hardware)
    "home/+/+/+/status",     # retained device state
    "security/alerts/+",     # vision / cyber / engine alerts (event envelope)
    "security/risk",
    "security/incidents",
)

Level = Literal["low", "medium", "high", "critical"]


class StatusIn(BaseModel):
    online: StrictBool          # strict: "yes" / 1 are not booleans
    state: dict


class RiskIn(BaseModel):
    ts: str
    zone: str = Field(pattern=r"^[a-z0-9_]+$", max_length=50)
    level: Level
    score: StrictInt = Field(ge=0)
    factors: list[dict]
    actions: list[str]


class IncidentIn(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    ts: str
    zone: str = Field(pattern=r"^[a-z0-9_]+$", max_length=50)
    level: Level
    score: StrictInt = Field(ge=0)
    trigger: str = Field(min_length=1, max_length=100)
    events: list[str]
    actions: list[str]
    summary: str = Field(max_length=4000)


def _parse_ts(value: str) -> datetime:
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _reject(what: str, reason: Any) -> None:
    # Log the reason, never the payload: it may contain personal or sensitive data.
    logger.warning("rejected %s: %s", what, str(reason).splitlines()[0][:200])


def _small(obj: Any) -> bool:
    return len(json.dumps(obj)) <= MAX_DATA_BYTES


def _broadcast(message: dict) -> None:
    """MQTT callbacks run in a paho thread; websockets live on the asyncio loop."""
    if not manager.connections:
        return
    try:
        loop = manager.loop
        if loop is None or loop.is_closed():
            return
        asyncio.run_coroutine_threadsafe(manager.broadcast(message), loop)
    except Exception:
        logger.exception("failed to broadcast WebSocket message")


# ------------------------------------------------------------------ events and alerts
def _save_event(payload: dict, topic_zone: str | None = None) -> None:
    try:
        env = Envelope.model_validate(payload)
        if not 8 <= len(env.id) <= 100 or len(env.source) > 100:
            raise ValueError("id must be 8-100 chars and source at most 100")
        if not _small(env.data):
            raise ValueError("data too large")
        if topic_zone is not None and env.zone != topic_zone:
            raise ValueError(f"zone {env.zone!r} does not match topic zone {topic_zone!r}")
        ts = _parse_ts(env.ts)
    except (ValidationError, ValueError, TypeError) as exc:
        _reject("event", exc)
        return

    try:
        with SessionLocal() as db:
            if db.get(EventRow, env.id):
                logger.info("ignoring duplicate event %s", env.id)
                return
            db.add(EventRow(
                id=env.id, ts=ts, source=env.source, type=env.type, zone=env.zone,
                severity_hint=env.severity_hint, data_encrypted=seal_json(env.data, env.id),
            ))
            try:
                db.commit()
            except IntegrityError:        # lost a race with an identical message
                db.rollback()
                return
        logger.info("event saved: %s (%s)", env.id, env.type)
    except Exception:
        logger.exception("failed to save event")
        return
    _broadcast({"kind": "event", "data": env.model_dump()})


# ------------------------------------------------------------------ device status
def _save_status(zone: str, device_type: str, device_id: str, payload: dict) -> None:
    if not all(_TOKEN.match(t) for t in (zone, device_type, device_id)):
        _reject("status", "invalid topic tokens")
        return
    try:
        status = StatusIn.model_validate(payload)
        if not _small(status.state):
            raise ValueError("state too large")
    except (ValidationError, ValueError) as exc:
        _reject(f"status of {device_id}", exc)
        return

    try:
        with SessionLocal() as db:
            device = db.scalar(select(Device).where(Device.device_id == device_id))
            if device is None:
                device = Device(device_id=device_id, name=device_id)
                db.add(device)
            device.device_type, device.zone = device_type, zone
            device.online, device.state = status.online, json.dumps(status.state)
            db.commit()
    except Exception:
        logger.exception("failed to save status of %s", device_id)
        return
    _broadcast({
        "kind": "device_status",
        "data": {
            "device_id": device_id, "device_type": device_type,
            "zone": zone, "online": status.online, "state": status.state,
            "status_id": payload.get("id"), "ts": payload.get("ts"),
        },
    })


# ------------------------------------------------------------------ risk and incidents
def _save_risk(payload: dict) -> None:
    try:
        risk = RiskIn.model_validate(payload)
        if not _small(risk.factors):
            raise ValueError("factors too large")
        ts = _parse_ts(risk.ts)
    except (ValidationError, ValueError) as exc:
        _reject("risk state", exc)
        return
    try:
        with SessionLocal() as db:
            row = db.scalar(select(RiskState).where(RiskState.zone == risk.zone)
                            .order_by(RiskState.id.desc()))
            if row is None:
                row = RiskState(zone=risk.zone)
                db.add(row)
            row.ts, row.level, row.score = ts, risk.level, risk.score
            row.factors_encrypted = seal_json(risk.factors, risk.zone)
            row.actions_encrypted = seal_json(risk.actions, risk.zone)
            db.commit()
    except Exception:
        logger.exception("failed to save risk state")
        return
    _broadcast({"kind": "risk", "data": risk.model_dump()})


def _save_incident(payload: dict) -> None:
    try:
        inc = IncidentIn.model_validate(payload)
        if not _small(inc.events) or not _small(inc.actions):
            raise ValueError("events/actions too large")
        ts = _parse_ts(inc.ts)
    except (ValidationError, ValueError) as exc:
        _reject("incident", exc)
        return
    try:
        with SessionLocal() as db:
            row = db.get(Incident, inc.id)
            if row is None:              # the engine re-sends the same id to update (CONTRACT 4.4)
                row = Incident(id=inc.id)
                db.add(row)
            row.ts, row.zone, row.level, row.score = ts, inc.zone, inc.level, inc.score
            row.trigger = inc.trigger
            row.events_encrypted = seal_json(inc.events, inc.id)
            row.actions_encrypted = seal_json(inc.actions, inc.id)
            row.summary_encrypted = seal_text(inc.summary, inc.id)
            db.commit()
    except Exception:
        logger.exception("failed to save incident")
        return
    _broadcast({"kind": "incident", "data": inc.model_dump()})


# ------------------------------------------------------------------ paho callbacks
def on_message(client, userdata, message) -> None:
    topic = message.topic
    try:
        if len(message.payload) > MAX_PAYLOAD_BYTES:
            raise ValueError("payload too large")
        payload = json.loads(message.payload.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("payload must be a JSON object")
    except (UnicodeDecodeError, ValueError) as exc:
        _reject(f"message on {topic}", exc)
        return

    parts = topic.split("/")
    if len(parts) == 5 and parts[0] == "home" and parts[4] == "event":
        _save_event(payload, topic_zone=parts[1])
    elif len(parts) == 5 and parts[0] == "home" and parts[4] == "status":
        _save_status(parts[1], parts[2], parts[3], payload)
    elif len(parts) == 3 and parts[:2] == ["security", "alerts"]:
        _save_event(payload)
    elif topic == "security/risk":
        _save_risk(payload)
    elif topic == "security/incidents":
        _save_incident(payload)
    else:
        logger.debug("ignoring MQTT topic %s", topic)


def _subscribe_all(client) -> None:
    for topic in SUBSCRIPTIONS:
        result, _ = client.subscribe(topic, qos=1)
        if result != 0:
            logger.error("subscribe to %s failed (rc=%s)", topic, result)
    logger.info("MQTT subscriptions active: %s", ", ".join(SUBSCRIPTIONS))


def setup_mqtt_handlers(client) -> None:
    client.on_message = on_message
    previous = client.on_connect

    def on_connect(c, userdata, flags, reason_code, properties=None):
        if previous:
            previous(c, userdata, flags, reason_code, properties)
        if not getattr(reason_code, "is_failure", False):
            _subscribe_all(c)            # runs again after every broker restart or reconnect

    client.on_connect = on_connect
    if client.is_connected():
        _subscribe_all(client)
