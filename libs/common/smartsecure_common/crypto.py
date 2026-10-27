"""AES-256-GCM encryption for application data at rest (owned by Person 2 / API).

Usage: derive a key once from ``STORAGE_KEY`` via :func:`key_from_env`, then
:func:`encrypt` any field before persisting it and :func:`decrypt` on read.
The ciphertext is ``12-byte nonce || ciphertext || 16-byte tag``; a shared
``aad`` (e.g. the event id) binds the blob to its context so a valid ciphertext
replayed against another row fails to decrypt. AES-GCM authenticates the data,
so any tampering raises an exception instead of decrypting garbage.
"""
from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_BYTES = 12
_TAG_BYTES = 16


def key_from_env(raw: str | bytes | None) -> bytes:
    """Derive the 32-byte AES-256 key from the ``STORAGE_KEY`` env value (hex)."""
    if not raw:
        raise ValueError("no key material given")
    if isinstance(raw, str):
        raw = raw.encode()
    return hashlib.sha256(raw).digest()


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Return ``nonce || ciphertext || tag``. Raises if ``key`` is not 32 bytes."""
    nonce = os.urandom(_NONCE_BYTES)
    blob = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + blob


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Decrypt a blob from :func:`encrypt`. Raises ValueError on tamper/wrong key."""
    if len(blob) < _NONCE_BYTES + _TAG_BYTES:
        raise ValueError("ciphertext too short")
    nonce, ciphertext = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad)