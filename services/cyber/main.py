"""cyber service: Suricata eve.json -> contract events on security/alerts/cyber, and the IPS.

Reads Suricata's alerts and DHCP records, turns each attack into ONE event for the risk engine,
detects rogue devices against an allowlist, and executes `system/block` commands from the engine
(plus a local auto-block for confirmed scans/brute force). See services/cyber/README.md.
"""
from __future__ import annotations

import logging
import signal
import sys
import threading

import paho.mqtt.client as mqtt

from cyb.config import Settings
from cyb.firewall import FirewallError
from cyb.service import CyberService
from smartsecure_common import Event, connect, start_heartbeat, topics

SERVICE = "cyber"
log = logging.getLogger("cyber")


class MqttSink:
    """Publishes to security/alerts/cyber (the only topic cyber's ACL allows it to write)."""

    def __init__(self, client: mqtt.Client) -> None:
        self.client, self.topic = client, topics.alert("cyber")

    def publish(self, event: Event) -> None:
        info = self.client.publish(self.topic, event.model_dump_json(), qos=1)
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            log.error("publish of %s failed (rc=%s); paho retries once reconnected",
                      event.type, info.rc)


def main(stop: threading.Event | None = None) -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = Settings.from_env()                    # ValueError = fail fast with a clear reason
    client = connect(SERVICE)
    start_heartbeat(client, SERVICE)
    service = CyberService(settings, MqttSink(client))
    try:
        service.restore()
    except FirewallError as exc:
        log.error("firewall backend %r is not usable: %s", settings.firewall, exc)
        client.disconnect()
        return 1

    def on_block(_client, _userdata, message) -> None:
        service.handle_block(message.payload)

    def on_connect(c, _userdata, _flags, reason_code, _properties=None) -> None:
        if not getattr(reason_code, "is_failure", False):
            c.subscribe(topics.BLOCK, qos=1)          # also after every automatic reconnect

    client.message_callback_add(topics.BLOCK, on_block)
    client.on_connect = on_connect
    client.subscribe(topics.BLOCK, qos=1)

    if stop is None:
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
    service.start(stop)
    log.info("cyber started: eve=%s firewall=%s autoblock=%s allowlist=%s",
             settings.eve_path, settings.firewall, ",".join(settings.autoblock) or "off",
             "on" if service.allowlist.enabled else "OFF (empty known_devices.yaml)")
    try:
        stop.wait()
    finally:
        client.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main())
