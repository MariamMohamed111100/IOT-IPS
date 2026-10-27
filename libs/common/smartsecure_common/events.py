"""Event envelope shared by every module. Mirrors contract/event.schema.json."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Event(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ts: str = Field(default_factory=_now)
    source: str                       # e.g. "sim.pir", "vision", "cyber"
    type: str = Field(pattern=r"^[a-z0-9_]+\.[a-z0-9_]+$")   # e.g. "face.unknown"
    zone: str = Field(pattern=r"^[a-z0-9_]+$")                # e.g. "garage", "network"
    severity_hint: Severity = "info"
    data: dict[str, Any] = Field(default_factory=dict)


def make_event(
    source: str, type: str, zone: str, severity_hint: Severity = "info", **data
) -> Event:
    return Event(source=source, type=type, zone=zone, severity_hint=severity_hint, data=data)
