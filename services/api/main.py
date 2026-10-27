"""API service: JWT-protected REST + WebSocket for SmartSecure Home."""
import logging
import os
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import text

import audit
import models  # noqa: F401  (registers the tables on Base before create_all)
from database import Base, SessionLocal, engine
from mqtt_handler import setup_mqtt_handlers
from routes import router, ws_router
from security import LoginRateLimiter, create_token, require_token, verify_user
from smartsecure_common import connect, start_heartbeat
from zones_seed import seed_zones

logger = logging.getLogger("api.auth")

_DOCS_ENABLED = os.getenv("API_DOCS_ENABLED", "false").lower() in {"1", "true", "yes"}


def _prepare_database() -> None:
    Base.metadata.create_all(bind=engine)
    # create_all skips tables that already exist, so add any index introduced later.
    for table in Base.metadata.tables.values():
        for index in table.indexes:
            index.create(bind=engine, checkfirst=True)
    seed_zones()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _prepare_database()
    client = connect("api")
    setup_mqtt_handlers(client)      # re-subscribes automatically after any reconnect
    start_heartbeat(client, "api")
    app.state.mqtt = client
    yield
    client.loop_stop()
    client.disconnect()


app = FastAPI(
    title="SmartSecure API",
    version="0.2.0",
    lifespan=lifespan,
    docs_url="/docs" if _DOCS_ENABLED else None,
    redoc_url="/redoc" if _DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
)
app.include_router(router)
app.include_router(ws_router)

limiter = LoginRateLimiter()


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/health")
def health():
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    return {"status": "ok", "mqtt_connected": app.state.mqtt.is_connected(), "db": db_ok}


@app.post("/auth/login", tags=["auth"])
def login(body: LoginRequest, request: Request):
    client_host = request.client.host if request.client else "unknown"
    key = f"{client_host}:{body.username}"

    if not limiter.allow(key):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed attempts, try again later",
            headers={"Retry-After": "60"},
        )

    if not verify_user(body.username, body.password):
        limiter.record_failure(key)
        logger.warning("failed login for user=%r from %s", body.username, client_host)
        audit.record(body.username, "login.failed", "-", {"ip": client_host})
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    limiter.reset(key)
    audit.record(body.username, "login.ok", "-", {"ip": client_host})
    return {"access_token": create_token(body.username), "token_type": "bearer"}


@app.get("/auth/me", tags=["auth"])
def me(claims: Annotated[dict, Depends(require_token)]):
    return {"username": claims["sub"], "expires_at": claims["exp"]}
