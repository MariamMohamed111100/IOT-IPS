"""The broker forgets subscriptions whenever it restarts: the API must subscribe again."""
import types

import mqtt_handler

OK = types.SimpleNamespace(is_failure=False)
FAILED = types.SimpleNamespace(is_failure=True)


def _client(connected=True, previous=None):
    from conftest import FakeMqtt
    c = FakeMqtt()
    c.connected = connected
    c.on_connect = previous
    return c


def test_subscribes_immediately_when_already_connected():
    c = _client()
    mqtt_handler.setup_mqtt_handlers(c)
    assert c.subscriptions == list(mqtt_handler.SUBSCRIPTIONS)
    assert "security/alerts/+" in c.subscriptions


def test_resubscribes_after_every_reconnect():
    c = _client()
    mqtt_handler.setup_mqtt_handlers(c)
    c.subscriptions.clear()
    for _ in range(3):                      # broker restarted three times
        c.on_connect(c, None, {}, OK, None)
    assert c.subscriptions == list(mqtt_handler.SUBSCRIPTIONS) * 3


def test_does_not_subscribe_when_the_connection_was_refused():
    c = _client(connected=False)
    mqtt_handler.setup_mqtt_handlers(c)
    assert c.subscriptions == []
    c.on_connect(c, None, {}, FAILED, None)
    assert c.subscriptions == []
    c.on_connect(c, None, {}, OK, None)
    assert c.subscriptions == list(mqtt_handler.SUBSCRIPTIONS)


def test_keeps_the_previous_on_connect_callback():
    calls = []
    c = _client(previous=lambda *a: calls.append("previous"))
    mqtt_handler.setup_mqtt_handlers(c)
    c.on_connect(c, None, {}, OK, None)
    assert calls == ["previous"]


def test_app_startup_wires_the_handlers(client, fake_mqtt):
    assert fake_mqtt.on_message is mqtt_handler.on_message
    assert fake_mqtt.on_connect is not None
    assert fake_mqtt.subscriptions == list(mqtt_handler.SUBSCRIPTIONS)
