"""Audit trail: every login and device command is recorded with the acting user."""
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from database import SessionLocal
from models import AuditLog
from storage import seal_json

logger = logging.getLogger("api.audit")


def record(actor: str, action: str, target: str = "-",
           details: dict[str, Any] | None = None) -> None:
    """Never raises: a failing audit write must not turn a login or command into a 500."""
    row_id = str(uuid.uuid4())
    try:
        with SessionLocal() as db:
            db.add(AuditLog(
                id=row_id,
                ts=datetime.now(timezone.utc),
                actor=actor[:100],
                action=action,
                target=target[:100],
                details_encrypted=seal_json(details or {}, row_id),
            ))
            db.commit()
    except Exception:
        logger.exception("failed to write audit record (%s by %s)", action, actor)
