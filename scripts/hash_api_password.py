#!/usr/bin/env python3
"""Print a compose-safe scrypt hash of argv[1] (same format as services/api/security.py)."""
from __future__ import annotations

import base64
import hashlib
import os
import sys

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P, _SCRYPT_DK = 16384, 8, 1, 32


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(
        password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DK
    )
    return f"scrypt.{_SCRYPT_N}.{_SCRYPT_R}.{_SCRYPT_P}.{_b64(salt)}.{_b64(dk)}"


if __name__ == "__main__":
    if len(sys.argv) != 2 or not sys.argv[1]:
        sys.exit("usage: hash_api_password.py <password>")
    sys.stdout.write(hash_password(sys.argv[1]) + "\n")
