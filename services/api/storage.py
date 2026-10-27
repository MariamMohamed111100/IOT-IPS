"""At-rest encryption helpers (CONTRACT section 8).

Every sensitive field is sealed with AES-256-GCM, bound to its record id (AAD) so a ciphertext
copied onto another row fails to open. Opening never raises into the request: a record that
fails its integrity check is reported as such (`ok=False`) and logged at ERROR, and its content
is withheld. It is never silently returned as empty data.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from smartsecure_common.crypto import decrypt, encrypt, key_from_env

logger = logging.getLogger("api.storage")


def storage_key() -> bytes:
    raw = os.getenv("STORAGE_KEY")
    if not raw:
        raise RuntimeError("STORAGE_KEY is not set")
    return key_from_env(raw)


def seal_json(value: Any, aad: str) -> bytes:
    blob = json.dumps(value, separators=(",", ":")).encode()
    return encrypt(storage_key(), blob, aad=aad.encode())


def seal_text(text: str, aad: str) -> bytes:
    return encrypt(storage_key(), text.encode(), aad=aad.encode())


def open_json(blob: bytes, aad: str, what: str, default: Any) -> tuple[Any, bool]:
    """Return (value, ok). ok=False means tampering, a wrong key or corruption."""
    try:
        return json.loads(decrypt(storage_key(), blob, aad=aad.encode()).decode()), True
    except Exception:
        logger.error("INTEGRITY CHECK FAILED: cannot decrypt %s (record %s)", what, aad)
        return default, False


def open_text(blob: bytes, aad: str, what: str) -> tuple[str, bool]:
    try:
        return decrypt(storage_key(), blob, aad=aad.encode()).decode(), True
    except Exception:
        logger.error("INTEGRITY CHECK FAILED: cannot decrypt %s (record %s)", what, aad)
        return "", False
