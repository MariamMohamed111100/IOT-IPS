"""JWT bearer auth for the API (contract section 5).

Users come from ``API_USERS`` (``name:secret[:role],...``). Secrets are
``scrypt.N.r.p.salt.dk`` hashes (see :func:`hash_password`); a leftover
plaintext value is still accepted so existing test fixtures keep working.
Roles: ``viewer`` (read), ``operator`` / ``admin`` (commands and writes).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)
_UNAUTHORIZED = {"WWW-Authenticate": "Bearer"}
_FORBIDDEN = status.HTTP_403_FORBIDDEN

ALGORITHM = "HS256"
ISSUER = "smartsecure"
AUDIENCE = "smartsecure-api"
ROLES = frozenset({"viewer", "operator", "admin"})
OPERATOR_ROLES = frozenset({"operator", "admin"})
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P, _SCRYPT_DK = 16384, 8, 1, 32


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def hash_password(password: str) -> str:
    """Return a compose-safe scrypt hash (no ``$`` / ``,`` / ``:``)."""
    salt = os.urandom(16)
    dk = hashlib.scrypt(
        password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DK
    )
    return f"scrypt.{_SCRYPT_N}.{_SCRYPT_R}.{_SCRYPT_P}.{_b64(salt)}.{_b64(dk)}"


def _verify_scrypt(password: str, stored: str) -> bool:
    try:
        kind, n_s, r_s, p_s, salt_s, dk_s = stored.split(".")
        if kind != "scrypt":
            return False
        n, r, p = int(n_s), int(r_s), int(p_s)
        if n > 2**20 or n < 2 or r < 1 or p < 1:
            return False
        expected = _unb64(dk_s)
        got = hashlib.scrypt(
            password.encode(), salt=_unb64(salt_s), n=n, r=r, p=p, dklen=len(expected)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, expected)


def _verify_legacy_plaintext(password: str, stored: str) -> bool:
    """Constant-time compare that never raises on length mismatch."""
    left = hashlib.sha256(password.encode()).digest()
    right = hashlib.sha256(stored.encode()).digest()
    return hmac.compare_digest(left, right)


def verify_secret(password: str, stored: str) -> bool:
    if stored.startswith("scrypt."):
        return _verify_scrypt(password, stored)
    return _verify_legacy_plaintext(password, stored)


@dataclass(frozen=True)
class User:
    name: str
    secret: str
    role: str


def parse_users(raw: str | None = None) -> dict[str, User]:
    users: dict[str, User] = {}
    for pair in (raw if raw is not None else os.getenv("API_USERS", "")).split(","):
        pair = pair.strip()
        if ":" not in pair:
            continue
        name, rest = pair.split(":", 1)
        name = name.strip()
        role = "viewer"                  # least privilege: an unlabelled user may only read
        secret = rest
        if ":" in rest:
            secret, maybe_role = rest.rsplit(":", 1)
            maybe_role = maybe_role.strip().lower()
            if maybe_role in ROLES:
                role = maybe_role
            else:
                secret = rest
        if name:
            users[name] = User(name=name, secret=secret, role=role)
    return users


def _settings() -> tuple[str, int]:
    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise RuntimeError("JWT_SECRET is not set")
    # Algorithm is fixed in code. JWT_ALGORITHM in .env is documentation only;
    # a mis-set value must never select none/HS384/etc.
    return secret, int(os.getenv("JWT_EXPIRE_MINUTES", "60"))


def create_token(subject: str, role: str = "operator") -> str:
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}")
    secret, expire_minutes = _settings()
    now = int(time.time())
    payload = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + expire_minutes * 60,
        "iss": ISSUER,
        "aud": AUDIENCE,
    }
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """Return the claims or raise ValueError (used by the WebSocket, which has no Request)."""
    secret, _ = _settings()
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["exp", "sub", "role", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired") from None
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token") from None
    if claims.get("role") not in ROLES:
        raise ValueError("Invalid token")
    return claims


def verify_user(name: str, password: str) -> User | None:
    user = parse_users().get(name)
    if user is None or not verify_secret(password, user.secret):
        return None
    return user


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


def require_operator(claims: Annotated[dict, Depends(require_token)]) -> dict:
    if claims.get("role") not in OPERATOR_ROLES:
        raise HTTPException(_FORBIDDEN, "Operator role required")
    return claims


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
