"""publisher.py - where alerts go: MQTT (the real backend), a JSON-lines file, stdout or memory (tests).

MqttPublisher uses paho with mutual TLS like scripts/ips/ips_transport.py (local mode). In the real
stack the service can swap it for libs/common connect("cyber"); the service only needs publish(topic, payload).
"""
import json
import os
import sys
import time


class PublishError(RuntimeError):
    """A message could not be delivered."""


class MemoryPublisher:
    def __init__(self):
        self.messages = []

    def publish(self, topic, payload):
        self.messages.append((topic, payload))

    def close(self):
        pass


class FilePublisher:
    """One JSON object per line: {"topic": ..., "payload": ...}."""
    def __init__(self, path):
        self._f = open(path, "w", encoding="utf-8")

    def publish(self, topic, payload):
        self._f.write(json.dumps({"topic": topic, "payload": payload}, ensure_ascii=False) + "\n")
        self._f.flush()

    def close(self):
        self._f.close()


class StdoutPublisher:
    def publish(self, topic, payload):
        print(json.dumps({"topic": topic, "payload": payload}, ensure_ascii=False))

    def close(self):
        sys.stdout.flush()


class MqttPublisher:
    """QoS 1 publisher. paho reconnects by itself after a broker restart (reconnect_delay_set);
    a failed publish is retried a few times and then raises PublishError (the service keeps running)."""

    def __init__(self, client=None, retries=3, retry_wait=1.0, wait_seconds=10):
        self.retries, self.retry_wait, self.wait_seconds = retries, retry_wait, wait_seconds
        self.client = client if client is not None else self._make_client()

    @staticmethod
    def _make_client():
        import paho.mqtt.client as mqtt
        env = os.environ
        for name in ("MQTT_HOST", "MQTT_PASSWORD"):
            if not env.get(name):
                raise PublishError("set the %s environment variable (and MQTT_USER, MQTT_CA, MQTT_CERT, MQTT_KEY)" % name)
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="cyber-%d" % os.getpid())
        client.username_pw_set(env.get("MQTT_USER", "cyber"), env["MQTT_PASSWORD"])
        if env.get("MQTT_CA"):
            client.tls_set(ca_certs=env["MQTT_CA"], certfile=env.get("MQTT_CERT"), keyfile=env.get("MQTT_KEY"))
        client.reconnect_delay_set(min_delay=1, max_delay=30)
        client.connect(env["MQTT_HOST"], int(env.get("MQTT_PORT", "8883")))
        client.loop_start()
        time.sleep(0.5)
        return client

    def publish(self, topic, payload):
        body = json.dumps(payload, ensure_ascii=False)
        last = "unknown error"
        for attempt in range(1, self.retries + 1):
            try:
                info = self.client.publish(topic, body, qos=1)
                info.wait_for_publish(self.wait_seconds)
                if info.is_published():
                    return
                last = "broker did not confirm"
            except Exception as exc:          # paho raises ValueError/RuntimeError when disconnected
                last = str(exc)
            if attempt < self.retries:
                time.sleep(self.retry_wait * attempt)
        raise PublishError("publish to %s failed after %d tries: %s" % (topic, self.retries, last))

    def close(self):
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass
