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
    """Client cert/key from the environment must reach tls_set (mTLS)."""
    seen = {}
    monkeypatch.setenv("MQTT_PASSWORD", "x")
    monkeypatch.setenv("MQTT_HOST", "127.0.0.1")
    monkeypatch.setenv("MQTT_PORT", str(_closed_port()))
    monkeypatch.setenv("MQTT_CA_FILE", str(TEST_CA))
    monkeypatch.setenv("MQTT_CLIENT_CERT", "/certs/clients/api.crt")
    monkeypatch.setenv("MQTT_CLIENT_KEY", "/certs/clients/api.key")

    from smartsecure_common import mqtt as mqtt_mod

    def spy(self, *args, **kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(mqtt_mod.mqtt.Client, "tls_set", spy)
    with pytest.raises(TimeoutError):
        connect("testsvc", timeout=1.0)
    assert seen.get("certfile") == "/certs/clients/api.crt"
    assert seen.get("keyfile") == "/certs/clients/api.key"
