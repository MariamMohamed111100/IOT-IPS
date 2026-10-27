"""JWT bearer auth for the API (contract section 5).

Users are provisioned through the API_USERS environment variable
(``name:password,name:password``), so the dev stack needs no user database.
Replace verify_user() with a real user store (hashed passwords, roles) without touching
the token handling.
"""
from __future__ import annotations

import hmac
import os
import threading
import time
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)
_UNAUTHORIZED = {"WWW-Authenticate": "Bearer"}


def _settings() -> tuple[str, str, int]:
    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise RuntimeError("JWT_SECRET is not set")
    return secret, os.getenv("JWT_ALGORITHM", "HS256"), int(os.getenv("JWT_EXPIRE_MINUTES", "60"))


def create_token(subject: str) -> str:
    secret, algorithm, expire_minutes = _settings()
    now = int(time.time())
    payload = {"sub": subject, "iat": now, "exp": now + expire_minutes * 60}
    return jwt.encode(payload, secret, algorithm=algorithm)


def decode_token(token: str) -> dict:
    """Return the claims or raise ValueError (used by the WebSocket, which has no Request)."""
    secret, algorithm, _ = _settings()
    try:
        return jwt.decode(
            token, secret, algorithms=[algorithm], options={"require": ["exp", "sub"]}
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired") from None
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token") from None


def verify_user(name: str, password: str) -> bool:
    wanted = None
    for pair in os.getenv("API_USERS", "").split(","):
        if ":" not in pair:
            continue
        user, secret = pair.split(":", 1)
        if user.strip() == name:
            wanted = secret
    if wanted is None:
        return False
    # Constant-time compare to avoid timing side channels on password length.
    return hmac.compare_digest(wanted.encode(), password.encode())


def require_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Missing bearer token", headers=_UNAUTHORIZED
        )
    try:
        return decode_token(credentials.credentials)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, str(exc), headers=_UNAUTHORIZED
        ) from None


class LoginRateLimiter:
    """Slows password guessing: at most ``limit`` failures per ``window`` seconds per key."""

    def __init__(self, limit: int = 5, window: float = 60.0) -> None:
        self.limit = limit
        self.window = window
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        cutoff = time.monotonic() - self.window
        with self._lock:
            hits = [t for t in self._failures.get(key, []) if t > cutoff]
            self._failures[key] = hits
            return len(hits) < self.limit

    def record_failure(self, key: str) -> None:
        with self._lock:
            self._failures.setdefault(key, []).append(time.monotonic())

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
