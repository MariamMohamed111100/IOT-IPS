"""AES-256-GCM round-trip, tamper detection and key derivation."""
import pytest
from cryptography.exceptions import InvalidTag

from smartsecure_common.crypto import decrypt, encrypt, key_from_env


def test_roundtrip():
    key = key_from_env("0123456789abcdef0123456789abcdef")
    blob = encrypt(key, b"incident 42 payload")
    assert blob != b"incident 42 payload"
    assert decrypt(key, blob) == b"incident 42 payload"


def test_deterministic_key_from_env():
    assert key_from_env("deadbeef") == key_from_env("deadbeef")
    assert key_from_env("a") != key_from_env("b")
    assert len(key_from_env("a")) == 32  # AES-256


def test_wrong_key_rejected():
    key1, key2 = key_from_env("a"), key_from_env("b")
    blob = encrypt(key1, b"secret")
    with pytest.raises(InvalidTag):
        decrypt(key2, blob)


def test_tamper_detected():
    key = key_from_env("k")
    blob = bytearray(encrypt(key, b"secret"))
    blob[-1] ^= 0xFF  # flip a tag/ciphertext bit
    with pytest.raises(InvalidTag):
        decrypt(key, bytes(blob))


def test_aad_binds_blob_to_context():
    key = key_from_env("k")
    blob = encrypt(key, b"secret", aad=b"event-1")
    assert decrypt(key, blob, aad=b"event-1") == b"secret"
    with pytest.raises(InvalidTag):
        decrypt(key, blob, aad=b"event-2")


def test_short_blob_rejected():
    with pytest.raises(ValueError):
        decrypt(key_from_env("k"), b"toolittle")