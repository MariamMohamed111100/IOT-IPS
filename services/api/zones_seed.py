"""Seeds the zones table from config/zones.yaml so the dashboard has its floor-plan zones."""
import logging
import os
from pathlib import Path

import yaml
from sqlalchemy import select

from database import SessionLocal
from models import Zone

logger = logging.getLogger("api.zones")


def seed_zones(path: str | None = None) -> int:
    """Insert missing zones (idempotent). Returns how many were added."""
    file = Path(path or os.getenv("ZONES_FILE", "/config/zones.yaml"))
    if not file.exists():
        logger.warning("zones file %s not found: zones table not seeded", file)
        return 0
    cfg = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
    outdoor = set(cfg.get("outdoor_zones", []))
    added = 0
    with SessionLocal() as db:
        existing = set(db.scalars(select(Zone.name)).all())
        for name in cfg.get("zones", []):
            if name not in existing:
                db.add(Zone(name=name, is_outdoor=name in outdoor))
                added += 1
        db.commit()
    if added:
        logger.info("seeded %d zone(s) from %s", added, file)
    return added
