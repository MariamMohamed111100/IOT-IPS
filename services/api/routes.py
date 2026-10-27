"""REST + WebSocket routes (CONTRACT section 5).

`router` carries the JWT requirement for every route registered on it, so a new endpoint is
protected by default. Events and incidents are write-protected over REST on purpose: they only
enter the system through MQTT (validated in mqtt_handler), so a logged-in user cannot forge
forensic history.
"""
import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import audit
from database import get_db
from models import AuditLog, Device, Incident, RiskState, Zone
from models import Event as EventRow
from security import decode_token, require_token
from smartsecure_common import topics
from storage import open_json, open_text
from websocket_manager import manager

logger = logging.getLogger("api.routes")

router = APIRouter(dependencies=[Depends(require_token)])   # every HTTP route needs a JWT
ws_router = APIRouter()                                     # WebSocket authenticates itself

Db = Annotated[Session, Depends(get_db)]
Claims = Annotated[dict, Depends(require_token)]
Token = r"^[a-z0-9_]+$"
Severity = Literal["info", "low", "medium", "high", "critical"]


def _iso(dt: datetime) -> str:
    """Always UTC with an explicit offset, whatever the database returned."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _ts_param(name: str, value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


# ------------------------------------------------------------------ WebSocket
MAX_WS_CLIENTS = int(os.getenv("WS_MAX_CLIENTS", "100"))


async def _close_when_token_expires(websocket: WebSocket, expires_at: float) -> None:
    """Close the socket with 1008 the moment the JWT's ``exp`` passes.

    The token is only checked at connect time, but the socket can outlive it by hours, so a
    user who logged out (or lost access) would keep receiving events. The dashboard must
    re-login and reconnect with the NEW token.
    """
    await asyncio.sleep(max(0.0, expires_at - time.time()))
    manager.disconnect(websocket)              # stop broadcasting to it first
    try:
        await websocket.close(code=1008)
    except Exception:                          # the client may already be gone
        logger.debug("socket already closed when its token expired")


@ws_router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """Live feed. Authenticate with ``?token=<JWT>`` (browsers cannot set WS headers).
    The reverse proxy does not access-log /ws/ so the token never lands in a log file."""
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return
    try:
        claims = decode_token(token)
    except ValueError:
        await websocket.close(code=1008)
        return
    if len(manager.connections) >= MAX_WS_CLIENTS:
        await websocket.close(code=1013)       # "try again later"
        return

    await manager.connect(websocket)
    # The read loop stays as simple as possible and is never cancelled mid-receive;
    # a separate timer task closes the socket at token expiry, which ends the loop.
    guard = asyncio.create_task(_close_when_token_expires(websocket, int(claims["exp"])))
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("websocket error")
    finally:
        guard.cancel()
        manager.disconnect(websocket)


# ------------------------------------------------------------------ zones
class ZoneCreate(BaseModel):
    name: str = Field(pattern=Token, max_length=50)
    is_outdoor: bool = False


class ZoneResponse(BaseModel):
    id: int
    name: str
    is_outdoor: bool
    model_config = {"from_attributes": True}


@router.get("/zones", response_model=list[ZoneResponse], tags=["zones"])
def list_zones(db: Db):
    return db.scalars(select(Zone).order_by(Zone.id)).all()


@router.post("/zones", response_model=ZoneResponse, status_code=201, tags=["zones"])
def create_zone(body: ZoneCreate, db: Db):
    zone = Zone(name=body.name, is_outdoor=body.is_outdoor)
    db.add(zone)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Zone already exists") from None
    db.refresh(zone)
    return zone


# ------------------------------------------------------------------ devices
class DeviceCreate(BaseModel):
    # device_id / device_type / zone become MQTT topic tokens, so they are restricted
    device_id: str = Field(pattern=Token, max_length=100)
    name: str = Field(min_length=1, max_length=100)
    device_type: str = Field(pattern=Token, max_length=50)
    zone: str = Field(pattern=Token, max_length=50)
    online: bool = False
    state: dict = Field(default_factory=dict)


class DeviceResponse(BaseModel):
    id: int
    device_id: str
    name: str
    device_type: str
    zone: str
    online: bool
    state: dict


class DeviceCommand(BaseModel):
    action: Literal["on", "off", "lock", "unlock", "open", "close"]
    reason: str = Field(default="api", max_length=200)


ALLOWED_ACTIONS = {
    "bulb": {"on", "off"},
    "siren": {"on", "off"},
    "lock": {"lock", "unlock"},
    "valve": {"open", "close"},
}


def _device_out(device: Device) -> DeviceResponse:
    try:
        state = json.loads(device.state)
    except (TypeError, json.JSONDecodeError):
        state = {}
    return DeviceResponse(
        id=device.id, device_id=device.device_id, name=device.name,
        device_type=device.device_type, zone=device.zone, online=device.online, state=state,
    )


@router.get("/devices", response_model=list[DeviceResponse], tags=["devices"])
def list_devices(db: Db, zone: Annotated[str | None, Query(pattern=Token)] = None):
    query = select(Device).order_by(Device.id)
    if zone:
        query = query.where(Device.zone == zone)
    return [_device_out(d) for d in db.scalars(query).all()]


@router.post("/devices", response_model=DeviceResponse, status_code=201, tags=["devices"])
def create_device(body: DeviceCreate, db: Db):
    device = Device(
        device_id=body.device_id, name=body.name, device_type=body.device_type,
        zone=body.zone, online=body.online, state=json.dumps(body.state),
    )
    db.add(device)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Device already exists") from None
    db.refresh(device)
    return _device_out(device)


@router.post("/devices/{device_id}/command", tags=["devices"])
def send_device_command(
    device_id: str, body: DeviceCommand, request: Request, claims: Claims, db: Db,
):
    device = db.scalar(select(Device).where(Device.device_id == device_id))
    if device is None:
        raise HTTPException(404, "Device not found")
    if body.action not in ALLOWED_ACTIONS.get(device.device_type, set()):
        raise HTTPException(
            400, f"Action '{body.action}' is not supported for device type '{device.device_type}'"
        )

    mqtt_client = getattr(request.app.state, "mqtt", None)
    if mqtt_client is None or not mqtt_client.is_connected():
        raise HTTPException(503, "MQTT is not connected")

    topic = topics.device_cmd(device.zone, device.device_type, device.device_id)
    payload = {
        "id": os.urandom(16).hex(),
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "action": body.action,
        "reason": body.reason,
        "requested_by": claims["sub"],           # who did it (also in the audit trail)
    }
    result = mqtt_client.publish(topic, json.dumps(payload), qos=1, retain=False)
    if result.rc != 0:
        raise HTTPException(503, "Failed to publish MQTT command")

    audit.record(claims["sub"], "device.command", device.device_id, {
        "action": body.action, "reason": body.reason, "command_id": payload["id"], "topic": topic,
    })
    return {
        "status": "sent", "device_id": device.device_id, "device_type": device.device_type,
        "zone": device.zone, "topic": topic, "command": payload,
    }


# ------------------------------------------------------------------ events (read-only)
class EventResponse(BaseModel):
    id: str
    ts: str
    source: str
    type: str
    zone: str
    severity_hint: Severity
    data: dict
    integrity_ok: bool = True          # False = failed its tamper check, data withheld


def _event_out(row: EventRow) -> EventResponse:
    data, ok = open_json(row.data_encrypted, row.id, "event data", {})
    return EventResponse(
        id=row.id, ts=_iso(row.ts), source=row.source, type=row.type, zone=row.zone,
        severity_hint=row.severity_hint, data=data, integrity_ok=ok,
    )


@router.get("/events", response_model=list[EventResponse], tags=["events"])
def list_events(
    db: Db,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    zone: Annotated[str | None, Query(pattern=Token)] = None,
    type: Annotated[str | None, Query(pattern=r"^[a-z0-9_]+\.[a-z0-9_]+$")] = None,
    source: Annotated[str | None, Query(max_length=100)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    ids: Annotated[str | None, Query(description="comma-separated event ids (max 100)")] = None,
):
    """Newest first. Filters combine with AND."""
    query = select(EventRow)
    if zone:
        query = query.where(EventRow.zone == zone)
    if type:
        query = query.where(EventRow.type == type)
    if source:
        query = query.where(EventRow.source == source)
    if since:
        query = query.where(EventRow.ts >= _ts_param("since", since))
    if until:
        query = query.where(EventRow.ts <= _ts_param("until", until))
    if ids:
        wanted = [i for i in ids.split(",") if i][:100]
        query = query.where(EventRow.id.in_(wanted))
    rows = db.scalars(query.order_by(EventRow.ts.desc()).limit(limit).offset(offset)).all()
    return [_event_out(r) for r in rows]


@router.get("/events/{event_id}", response_model=EventResponse, tags=["events"])
def get_event(event_id: str, db: Db):
    row = db.get(EventRow, event_id)
    if row is None:
        raise HTTPException(404, "Event not found")
    return _event_out(row)


# ------------------------------------------------------------------ incidents (read-only)
class IncidentResponse(BaseModel):
    id: str
    ts: str
    zone: str
    level: Severity
    score: int
    trigger: str
    events: list[str]
    actions: list[str]
    summary: str
    integrity_ok: bool = True


def _incident_out(row: Incident) -> IncidentResponse:
    events, ok1 = open_json(row.events_encrypted, row.id, "incident events", [])
    actions, ok2 = open_json(row.actions_encrypted, row.id, "incident actions", [])
    summary, ok3 = open_text(row.summary_encrypted, row.id, "incident summary")
    return IncidentResponse(
        id=row.id, ts=_iso(row.ts), zone=row.zone, level=row.level, score=row.score,
        trigger=row.trigger, events=events, actions=actions, summary=summary,
        integrity_ok=ok1 and ok2 and ok3,
    )


@router.get("/incidents", response_model=list[IncidentResponse], tags=["incidents"])
def list_incidents(
    db: Db,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    zone: Annotated[str | None, Query(pattern=Token)] = None,
):
    query = select(Incident)
    if zone:
        query = query.where(Incident.zone == zone)
    rows = db.scalars(query.order_by(Incident.ts.desc()).limit(limit).offset(offset)).all()
    return [_incident_out(r) for r in rows]


@router.get("/incidents/{incident_id}", response_model=IncidentResponse, tags=["incidents"])
def get_incident(incident_id: str, db: Db):
    row = db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(404, "Incident not found")
    return _incident_out(row)


@router.get("/incidents/{incident_id}/events", response_model=list[EventResponse],
            tags=["incidents"])
def incident_timeline(incident_id: str, db: Db):
    """The incident's events in chronological order (what the timeline page replays)."""
    row = db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(404, "Incident not found")
    event_ids, _ = open_json(row.events_encrypted, row.id, "incident events", [])
    if not event_ids:
        return []
    rows = db.scalars(
        select(EventRow).where(EventRow.id.in_(event_ids[:500])).order_by(EventRow.ts.asc())
    ).all()
    return [_event_out(r) for r in rows]


# ------------------------------------------------------------------ risk
class RiskResponse(BaseModel):
    ts: str
    zone: str
    level: Severity
    score: int
    factors: list[dict]
    actions: list[str]
    integrity_ok: bool = True


@router.get("/risk", response_model=list[RiskResponse], tags=["risk"])
def list_risk(db: Db):
    result = []
    for row in db.scalars(select(RiskState).order_by(RiskState.zone)).all():
        factors, ok1 = open_json(row.factors_encrypted, row.zone, "risk factors", [])
        actions, ok2 = open_json(row.actions_encrypted, row.zone, "risk actions", [])
        result.append(RiskResponse(
            ts=_iso(row.ts), zone=row.zone, level=row.level, score=row.score,
            factors=factors, actions=actions, integrity_ok=ok1 and ok2,
        ))
    return result


# ------------------------------------------------------------------ audit trail
class AuditResponse(BaseModel):
    id: str
    ts: str
    actor: str
    action: str
    target: str
    details: dict
    integrity_ok: bool = True


@router.get("/audit", response_model=list[AuditResponse], tags=["audit"])
def list_audit(
    db: Db,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    rows = db.scalars(
        select(AuditLog).order_by(AuditLog.ts.desc()).limit(limit).offset(offset)
    ).all()
    result = []
    for row in rows:
        details, ok = open_json(row.details_encrypted, row.id, "audit details", {})
        result.append(AuditResponse(
            id=row.id, ts=_iso(row.ts), actor=row.actor, action=row.action,
            target=row.target, details=details, integrity_ok=ok,
        ))
    return result
