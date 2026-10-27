"""main.py wiring against a fake MQTT client: subscriptions, block handling, confirmations."""
import json
import threading
import time
import types

import main as cyber_main
import pytest
from conftest import alert, write_lines

from cyb.config import SID_HTTP_LOGIN
from cyb.firewall import BlocklistFirewall, FirewallError
from smartsecure_common import make_event, topics


class FakeClient:
    def __init__(self):
        self.on_connect = None
        self.subscribed, self.callbacks, self.published = [], {}, []

    def subscribe(self, topic, qos=0):
        self.subscribed.append(topic)
        return (0, 1)

    def message_callback_add(self, topic, cb):
        self.callbacks[topic] = cb

    def publish(self, topic, payload, qos=0, retain=False):
        self.published.append((topic, json.loads(payload), qos))
        return types.SimpleNamespace(rc=0)

    def disconnect(self):
        pass


@pytest.fixture
def env(monkeypatch, tmp_path):
    for key, value in {"EVE_PATH": tmp_path / "eve.json", "BLOCKLIST_FILE": tmp_path / "bl.json",
                       "KNOWN_DEVICES_FILE": tmp_path / "k.yaml"}.items():
        monkeypatch.setenv(key, str(value))
    monkeypatch.setenv("CYBER_FIREWALL", "blocklist")
    return tmp_path


@pytest.fixture
def running(monkeypatch, env):
    client = FakeClient()
    monkeypatch.setattr(cyber_main, "connect", lambda service: client)
    monkeypatch.setattr(cyber_main, "start_heartbeat", lambda c, s: None)
    stop, result = threading.Event(), {}
    thread = threading.Thread(target=lambda: result.update(rc=cyber_main.main(stop)))
    thread.start()
    deadline = time.time() + 5
    while time.time() < deadline and topics.BLOCK not in client.callbacks:
        time.sleep(0.01)
    yield client, env
    stop.set()
    thread.join(5)
    assert result.get("rc") == 0


def test_subscribes_to_block_and_resubscribes_after_a_reconnect(running):
    client, _ = running
    assert client.subscribed == [topics.BLOCK]
    client.on_connect(client, None, None, types.SimpleNamespace(is_failure=False))
    assert client.subscribed == [topics.BLOCK, topics.BLOCK]
    client.on_connect(client, None, None, types.SimpleNamespace(is_failure=True))
    assert len(client.subscribed) == 2


def test_block_message_is_executed_and_confirmed_on_the_cyber_alert_topic(running):
    client, env = running
    msg = {"id": "e" * 32, "ts": "2026-10-11T10:00:00Z", "ip": "203.0.113.9",
           "reason": "cyber.port_scan", "window_seconds": 3600}
    client.callbacks[topics.BLOCK](client, None, types.SimpleNamespace(
        payload=json.dumps(msg).encode()))
    ((topic, body, qos),) = client.published
    assert topic == "security/alerts/cyber" and qos == 1
    assert body["type"] == "cyber.ip_blocked" and body["data"]["ip"] == "203.0.113.9"
    saved = json.loads((env / "bl.json").read_text())
    assert [b["ip"] for b in saved["blocks"]] == ["203.0.113.9"]


def test_a_hostile_block_message_changes_nothing(running):
    client, _ = running
    for payload in (b"\xff\xfe", b"{", b'{"ip": "127.0.0.1"}', b'{"ip": "-j ACCEPT"}', b"[]"):
        client.callbacks[topics.BLOCK](client, None, types.SimpleNamespace(payload=payload))
    assert client.published == []


def test_suricata_alerts_become_published_events(running):
    client, env = running
    time.sleep(0.4)                                          # let the reader see the missing file
    write_lines(env / "eve.json", *[alert(SID_HTTP_LOGIN, dst="192.168.1.20", port=8080)
                                    for _ in range(8)])
    deadline = time.time() + 8
    while time.time() < deadline and not client.published:
        time.sleep(0.05)
    assert client.published[0][1]["type"] == "cyber.brute_force"
    assert client.published[0][0] == "security/alerts/cyber"


def test_invalid_configuration_stops_startup(monkeypatch, env):
    monkeypatch.setenv("CYBER_FIREWALL", "yolo")
    with pytest.raises(ValueError):
        cyber_main.main(threading.Event())


def test_an_unusable_firewall_backend_exits_non_zero(monkeypatch, env):
    class Unusable(BlocklistFirewall):
        def setup(self):
            raise FirewallError("iptables: Permission denied (you must be root)")

    client = FakeClient()
    monkeypatch.setattr(cyber_main, "connect", lambda service: client)
    monkeypatch.setattr(cyber_main, "start_heartbeat", lambda c, s: None)
    monkeypatch.setattr("cyb.service.make_firewall", lambda name: Unusable())
    assert cyber_main.main(threading.Event()) == 1
    assert client.subscribed == []


def test_sink_logs_but_survives_a_failed_publish():
    client = FakeClient()
    client.publish = lambda *a, **k: types.SimpleNamespace(rc=4)
    cyber_main.MqttSink(client).publish(make_event("cyber", "cyber.port_scan", "network"))
