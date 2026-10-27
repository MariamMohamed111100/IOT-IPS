import asyncio
import json
import time

import jwt
import pytest
from conftest import make_event
from starlette.websockets import WebSocketDisconnect


def _expired():
    return jwt.encode({"sub": "admin", "exp": 1}, "j" * 48, algorithm="HS256")


@pytest.mark.parametrize("query", ["", "?token=", "?token=junk"])
def test_websocket_rejects_missing_or_bad_tokens(client, query):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/events" + query):
            pass


def test_websocket_rejects_expired_token(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/events?token=" + _expired()):
            pass


def test_websocket_closes_1008_once_the_token_expires(client):
    from websocket_manager import manager

    short = jwt.encode({"sub": "admin", "exp": int(time.time()) + 2}, "j" * 48, algorithm="HS256")
    with client.websocket_connect("/ws/events?token=" + short) as ws:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            while True:
                ws.receive_text()
        assert exc_info.value.code == 1008
        deadline = time.time() + 5
        while manager.connections and time.time() < deadline:
            time.sleep(0.1)
        assert len(manager.connections) == 0, "expired connection must be dropped from the manager"


def _token(auth):
    return auth["Authorization"].split()[1]


def test_live_event_and_status_are_pushed(client, auth, feed):
    with client.websocket_connect("/ws/events?token=" + _token(auth)) as ws:
        feed("security/alerts/vision", make_event("live-event-01"))
        message = json.loads(ws.receive_text())
        assert message["kind"] == "event" and message["data"]["id"] == "live-event-01"
        feed("home/kitchen/valve/valve_main/status", {"online": True, "state": {"open": False}})
        message = json.loads(ws.receive_text())
        assert message["kind"] == "device_status" and message["data"]["state"] == {"open": False}


def test_rejected_messages_are_not_broadcast(client, auth, feed):
    with client.websocket_connect("/ws/events?token=" + _token(auth)) as ws:
        feed("home/garage/pir/x/event", make_event("bad-sev-0001", severity_hint="EXTREME"))
        feed("security/alerts/vision", make_event("live-event-02"))
        assert json.loads(ws.receive_text())["data"]["id"] == "live-event-02"


def test_every_client_gets_the_message_and_disconnects_are_cleaned_up(client, auth, feed):
    from websocket_manager import manager
    token = _token(auth)
    with client.websocket_connect("/ws/events?token=" + token) as a:
        with client.websocket_connect("/ws/events?token=" + token) as b:
            feed("security/alerts/cyber", make_event("live-event-03", source="cyber"))
            assert json.loads(a.receive_text())["data"]["id"] == "live-event-03"
            assert json.loads(b.receive_text())["data"]["id"] == "live-event-03"
    assert len(manager.connections) == 0


# ------------------------------------------------------------------ robustness
def test_token_without_exp_is_never_accepted(client):
    forever = jwt.encode({"sub": "admin"}, "j" * 48, algorithm="HS256")
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {forever}"}).status_code == 401
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/events?token=" + forever):
            pass


def test_too_many_clients_are_turned_away_politely(client, auth, monkeypatch):
    import routes
    monkeypatch.setattr(routes, "MAX_WS_CLIENTS", 1)
    with client.websocket_connect("/ws/events?token=" + _token(auth)):
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws/events?token=" + _token(auth)):
                pass
        assert exc_info.value.code == 1013


class FakeSocket:
    def __init__(self, delay=0.0, fail=False):
        self.delay, self.fail, self.received, self.closed_with = delay, fail, [], None

    async def send_text(self, text):
        if self.fail:
            raise RuntimeError("connection reset")
        await asyncio.sleep(self.delay)
        self.received.append(text)

    async def close(self, code=1000):
        self.closed_with = code


def test_a_stalled_client_does_not_delay_the_others_and_is_dropped(monkeypatch):
    import websocket_manager as wm
    monkeypatch.setattr(wm, "SEND_TIMEOUT_SECONDS", 0.2)

    async def scenario():
        manager = wm.WebSocketManager()
        fast_a, fast_b = FakeSocket(), FakeSocket()
        stalled, broken = FakeSocket(delay=30), FakeSocket(fail=True)
        manager.connections.update({fast_a, fast_b, stalled, broken})
        started = time.monotonic()
        await manager.broadcast({"kind": "event", "data": {}})
        return manager, (fast_a, fast_b, stalled, broken), time.monotonic() - started

    manager, (fast_a, fast_b, stalled, broken), elapsed = asyncio.run(scenario())
    assert elapsed < 1.5, f"broadcast waited for the slow client ({elapsed:.1f}s)"
    assert len(fast_a.received) == len(fast_b.received) == 1
    assert manager.connections == {fast_a, fast_b}
    assert stalled.closed_with == 1011 and broken.closed_with == 1011
