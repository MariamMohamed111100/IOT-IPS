import socket
from pathlib import Path

import pytest

from smartsecure_common.mqtt import connect

TEST_CA = Path(__file__).parent / "data" / "test_ca.crt"


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_connect_raises_timeout_when_broker_unreachable(monkeypatch):
    """connect() must block for CONNACK instead of returning a client whose
    first publishes would be silently dropped, and must fail loudly."""
    monkeypatch.setenv("MQTT_PASSWORD", "x")
    monkeypatch.setenv("MQTT_HOST", "127.0.0.1")
    monkeypatch.setenv("MQTT_PORT", str(_closed_port()))
    monkeypatch.setenv("MQTT_CA_FILE", str(TEST_CA))
    monkeypatch.delenv("MQTT_CLIENT_CERT", raising=False)
    monkeypatch.delenv("MQTT_CLIENT_KEY", raising=False)
    with pytest.raises(TimeoutError, match="refused connection"):
        connect("testsvc", timeout=1.0)


def test_connect_presents_client_certificate_when_configured(monkeypatch):
    """Client cert/key from the environment must reach the TLS context (mTLS)."""
    seen = {}
    monkeypatch.setenv("MQTT_PASSWORD", "x")
    monkeypatch.setenv("MQTT_HOST", "127.0.0.1")
    monkeypatch.setenv("MQTT_PORT", str(_closed_port()))
    monkeypatch.setenv("MQTT_CA_FILE", str(TEST_CA))
    monkeypatch.setenv("MQTT_CLIENT_CERT", "/certs/clients/api.crt")
    monkeypatch.setenv("MQTT_CLIENT_KEY", "/certs/clients/api.key")

    from smartsecure_common import mqtt as mqtt_mod

    real_context = mqtt_mod.tls_context

    # The cert/key paths below are representative, not real files (no private key is ever
    # committed), so record the load instead of touching the disk: the point is that the
    # environment reaches the context, not that these particular files exist.
    def spy_load_cert_chain(self, certfile, keyfile=None, password=None):
        seen["certfile"], seen["keyfile"] = certfile, keyfile

    monkeypatch.setattr(mqtt_mod.ssl.SSLContext, "load_cert_chain", spy_load_cert_chain)

    def spy_context():
        ctx = real_context()
        seen["minimum_version"] = ctx.minimum_version
        return ctx

    captured = {}

    def spy_set_context(self, context):
        captured["context"] = context

    monkeypatch.setattr(mqtt_mod, "tls_context", spy_context)
    monkeypatch.setattr(mqtt_mod.mqtt.Client, "tls_set_context", spy_set_context)
    with pytest.raises((TimeoutError, FileNotFoundError, OSError)):
        connect("testsvc", timeout=1.0)
    import ssl
    assert captured.get("context") is not None
    assert seen.get("minimum_version") == ssl.TLSVersion.TLSv1_3
    assert seen.get("certfile") == "/certs/clients/api.crt"
    assert seen.get("keyfile") == "/certs/clients/api.key"


def test_a_half_configured_client_certificate_is_refused(monkeypatch):
    """A cert without its key would make paho send no client certificate at all: fail loudly."""
    monkeypatch.setenv("MQTT_PASSWORD", "x")
    monkeypatch.setenv("MQTT_HOST", "127.0.0.1")
    monkeypatch.setenv("MQTT_PORT", str(_closed_port()))
    monkeypatch.setenv("MQTT_CA_FILE", str(TEST_CA))
    monkeypatch.setenv("MQTT_CLIENT_CERT", "/certs/clients/api.crt")
    monkeypatch.delenv("MQTT_CLIENT_KEY", raising=False)
    with pytest.raises(ValueError, match="must be set together"):
        connect("testsvc", timeout=1.0)
