"""Glue between the devices and MQTT. Contains no hardware or transport details."""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from smartsecure_common import make_event, topics

from . import catalog
from .hal import Actuator, Device, Sensor

log = logging.getLogger("sim.runtime")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class SimulatorRuntime:
    def __init__(self, devices: dict[str, Device], bus, allow_inject: bool = True) -> None:
        self.devices = devices
        self.bus = bus
        self.allow_inject = allow_inject
        self._cmd_topics = {
            topics.device_cmd(d.zone, d.kind, d.id): d
            for d in devices.values() if isinstance(d, Actuator)
        }
        self._published_state: dict[str, dict] = {}

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        for dev in self.devices.values():
            self._publish_status(dev)
        for topic in self._cmd_topics:
            self.bus.subscribe(topic, self._on_cmd)
        if self.allow_inject:
            self.bus.subscribe(topics.SIM_INJECT, self._on_inject)
        log.info("started: %d devices (%d actuators), inject=%s",
                 len(self.devices), len(self._cmd_topics), self.allow_inject)

    def tick(self) -> None:
        """Call about once per second: lets sensors report what happened on their own."""
        for dev in self.devices.values():
            if isinstance(dev, Sensor):
                try:
                    self._publish_emits(dev, dev.poll())
                    if dev.state() != self._published_state.get(dev.id) or dev.was_sampled():
                        self._publish_status(dev)
                except Exception:
                    log.exception("poll failed for %s", dev.id)

    def stop(self) -> None:
        for dev in self.devices.values():
            self._publish_status(dev, online=False, wait=True)

    # ------------------------------------------------------------------ inbound
    def _on_cmd(self, topic: str, payload: str) -> None:
        dev = self._cmd_topics[topic]
        try:
            cmd = json.loads(payload)
            emits = dev.apply(cmd["action"])
        except (ValueError, KeyError, TypeError) as exc:
            log.warning("rejected command on %s: %s (%r)", topic, exc, payload[:200])
            return
        log.info("%s <- %s (%s)", dev.id, cmd["action"], cmd.get("reason", "-"))
        self._publish_emits(dev, emits)
        self._publish_status(dev)

    def _on_inject(self, topic: str, payload: str) -> None:
        try:
            msg = json.loads(payload)
            dev = self.devices[msg["device"]]
            emits = dev.inject(msg["event"], msg.get("data") or {})
        except (ValueError, KeyError, TypeError, PermissionError) as exc:
            log.warning("rejected inject: %s (%r)", exc, payload[:200])
            return
        log.info("inject %s.%s", dev.id, msg["event"])
        self._publish_emits(dev, emits)
        self._publish_status(dev)

    # ------------------------------------------------------------------ outbound
    def _publish_emits(self, dev: Device, emits: list[catalog.Emit]) -> None:
        for event_type, data in emits:
            event = make_event(dev.source, event_type, dev.zone,
                               catalog.SEVERITY.get(event_type, "info"), **data)
            self.bus.publish(topics.sensor_event(dev.zone, dev.kind, dev.id),
                             event.model_dump_json(), qos=1, retain=False)

    def _publish_status(self, dev: Device, online: bool = True, wait: bool = False) -> None:
        state = dev.state()
        self._published_state[dev.id] = state
        payload = json.dumps({"id": str(uuid.uuid4()), "ts": _now(), "state": state,
                              "online": online})
        self.bus.publish(topics.device_status(dev.zone, dev.kind, dev.id), payload,
                         qos=1, retain=True, wait=wait)
