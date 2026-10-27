"""Transport adapters. The runtime only needs publish() and subscribe(), so it can run against
real MQTT (MqttBus) or entirely in memory (LoopbackBus) for tests and dry runs."""
from __future__ import annotations

import logging
from typing import Callable

from paho.mqtt.client import topic_matches_sub

log = logging.getLogger("sim.bus")
Callback = Callable[[str, str], None]


class MqttBus:
    def __init__(self, client) -> None:
        self._client = client
        self._subs: dict[str, Callback] = {}
        client.on_message = self._dispatch
        client.on_connect = self._on_connect      # re-subscribe after a broker reconnect

    def publish(self, topic: str, payload: str, qos: int = 1, retain: bool = False,
                wait: bool = False) -> None:
        info = self._client.publish(topic, payload, qos=qos, retain=retain)
        if wait:  # only from the main thread: waiting inside an MQTT callback would deadlock
            info.wait_for_publish(timeout=5)

    def subscribe(self, topic: str, callback: Callback, qos: int = 1) -> None:
        self._subs[topic] = callback
        if self._client.is_connected():
            self._client.subscribe(topic, qos)

    def _on_connect(self, client, userdata, flags, reason_code, properties=None) -> None:
        if not getattr(reason_code, "is_failure", False):
            for topic in self._subs:
                client.subscribe(topic, 1)

    def _dispatch(self, client, userdata, msg) -> None:
        for sub, callback in list(self._subs.items()):
            if topic_matches_sub(sub, msg.topic):
                try:
                    callback(msg.topic, msg.payload.decode("utf-8", errors="replace"))
                except Exception:  # never let one bad message kill the network thread
                    log.exception("handler failed for %s", msg.topic)


class LoopbackBus:
    """In-memory broker: delivers publishes to matching subscribers and keeps retained messages."""

    def __init__(self) -> None:
        self.published: list[tuple[str, str, bool]] = []
        self.retained: dict[str, str] = {}
        self._subs: list[tuple[str, Callback]] = []

    def publish(self, topic: str, payload: str, qos: int = 1, retain: bool = False,
                wait: bool = False) -> None:
        self.published.append((topic, payload, retain))
        if retain:
            self.retained[topic] = payload
        for sub, callback in list(self._subs):
            if topic_matches_sub(sub, topic):
                callback(topic, payload)

    def subscribe(self, topic: str, callback: Callback, qos: int = 1) -> None:
        self._subs.append((topic, callback))

    def on(self, topic_filter: str) -> list[tuple[str, str]]:
        return [(t, p) for t, p, _ in self.published if topic_matches_sub(topic_filter, t)]
