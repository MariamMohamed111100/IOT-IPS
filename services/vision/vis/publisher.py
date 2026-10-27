from __future__ import annotations

import logging

import paho.mqtt.client as mqtt

from smartsecure_common import Event, topics

log = logging.getLogger("vision.mqtt")


class MqttSink:
    """Publishes events to security/alerts/vision (the only topic vision's ACL allows)."""

    def __init__(self, client: mqtt.Client) -> None:
        self.client = client
        self.topic = topics.alert("vision")

    def publish(self, event: Event) -> None:
        info = self.client.publish(self.topic, event.model_dump_json(), qos=1)
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            log.error("publish of %s failed (rc=%s); paho will retry when reconnected",
                      event.type, info.rc)
