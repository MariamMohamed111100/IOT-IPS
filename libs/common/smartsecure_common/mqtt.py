"""TLS MQTT helper. Configuration comes only from environment variables so the same
code runs in Docker, on a laptop, and later on the Raspberry Pi."""
from __future__ import annotations

import json
import os
import threading
import time

import paho.mqtt.client as mqtt

from . import topics


def connect(service: str, timeout: float = 30.0) -> mqtt.Client:
    """Connect and block until the broker accepts the session (CONNACK).

    The broker silently drops messages published before the session is
    established, so returning early would lose the caller's first publishes
    (heartbeats, alerts). If the broker is not reachable within ``timeout``
    seconds a TimeoutError is raised; the caller's restart policy retries.
    """
    host = os.getenv("MQTT_HOST", "mosquitto")
    port = int(os.getenv("MQTT_PORT", "8883"))
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"{service}-{os.getpid()}")
    client.username_pw_set(os.getenv("MQTT_USER", service), os.environ["MQTT_PASSWORD"])
    # Verifies the broker certificate against our local CA and presents our
    # client certificate (the broker requires mutual TLS; the CN is the user).
    certfile = os.getenv("MQTT_CLIENT_CERT") or None
    keyfile = os.getenv("MQTT_CLIENT_KEY") or None
    client.tls_set(
        ca_certs=os.getenv("MQTT_CA_FILE", "/certs/ca.crt"),
        certfile=certfile,
        keyfile=keyfile,
    )
    client.reconnect_delay_set(min_delay=1, max_delay=30)

    ready = threading.Event()

    def on_connect(c: mqtt.Client, userdata: object, flags: object, reason_code: object,
                   properties: object = None) -> None:
        if not getattr(reason_code, "is_failure", False):
            ready.set()

    client.on_connect = on_connect
    # connect_async + loop_start: retries until the broker is up
    client.connect_async(host, port)
    client.loop_start()
    if not ready.wait(timeout):
        client.disconnect()
        client.loop_stop()
        raise TimeoutError(f"MQTT broker at {host}:{port} refused connection within {timeout}s")
    return client


def start_heartbeat(client: mqtt.Client, service: str, interval: float = 5.0) -> threading.Thread:
    topic = topics.heartbeat(service)

    def run() -> None:
        while True:
            client.publish(topic, json.dumps({"service": service, "ts": time.time()}), qos=0)
            time.sleep(interval)

    t = threading.Thread(target=run, daemon=True, name=f"heartbeat-{service}")
    t.start()
    return t
