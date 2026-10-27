"""ips_transport.py - how the IPS helper scripts talk to the stack.

  docker (default) : the real compose stack, exactly like scripts/demo_incident.py (mosquitto_pub inside the broker
                     container as admin, HTTPS API on https://localhost:8443 verified against our CA)
  local            : direct MQTT (paho, mutual TLS) and API URL, for a stack that is not run by docker compose
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Optional, Tuple

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))        # scripts/ (demo_incident.py, ws_listen.py)


def add_transport_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--mode", choices=["docker", "local"], default=os.getenv("IPS_MODE", "docker"))
    p.add_argument("--base", default=os.getenv("IPS_API_BASE", "https://localhost:8443"), help="API base URL (no /api prefix)")
    p.add_argument("--ca", default=str(ROOT / "infra" / "certs" / "ca.crt"))
    p.add_argument("--api-user", default=os.getenv("API_USER"))
    p.add_argument("--api-password", default=os.getenv("API_PASSWORD"))
    g = p.add_argument_group("local mode only")
    g.add_argument("--mqtt-host", default="localhost")
    g.add_argument("--mqtt-port", type=int, default=8883)
    g.add_argument("--mqtt-user", default="admin")
    g.add_argument("--mqtt-password", default=os.getenv("MQTT_PASSWORD_ADMIN"))
    g.add_argument("--mqtt-cert", default=str(ROOT / "infra" / "certs" / "clients" / "admin.crt"))
    g.add_argument("--mqtt-key", default=str(ROOT / "infra" / "certs" / "clients" / "admin.key"))


class ApiMixin:
    base: str
    ctx: Optional[ssl.SSLContext]
    user: str
    password: str
    token: Optional[str] = None

    def _request(self, method: str, path: str, body: Any = None, token: Optional[str] = None) -> Tuple[int, Any]:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(self.base + path, method=method, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=15) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read() or b"null")
            except ValueError:
                return exc.code, None
        except (urllib.error.URLError, OSError) as exc:
            sys.exit("cannot reach the API at %s (%s). Is the stack up?" % (self.base, getattr(exc, "reason", exc)))

    def api(self, method: str, path: str, body: Any = None, params: Optional[dict] = None) -> Tuple[int, Any]:
        if self.token is None:
            status, data = self._request("POST", "/auth/login", {"username": self.user, "password": self.password})
            if status != 200 or not data:
                sys.exit("API login failed (HTTP %s). Check the user and password." % status)
            self.token = data["access_token"]
        if params:
            path += "?" + urllib.parse.urlencode(params)
        return self._request(method, path, body, self.token)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class LocalTransport(ApiMixin):
    def __init__(self, a: argparse.Namespace) -> None:
        import paho.mqtt.client as mqtt
        self.base = a.base.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=a.ca) if self.base.startswith("https") else None
        self.user, self.password = a.api_user or "admin", a.api_password or ""
        if not a.mqtt_password:
            sys.exit("local mode needs --mqtt-password (or MQTT_PASSWORD_ADMIN)")
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="ips-tools-%d" % os.getpid())
        self.client.username_pw_set(a.mqtt_user, a.mqtt_password)
        self.client.tls_set(ca_certs=a.ca, certfile=a.mqtt_cert, keyfile=a.mqtt_key)
        self.client.connect(a.mqtt_host, a.mqtt_port)
        self.client.loop_start()
        time.sleep(0.5)

    def publish(self, topic: str, payload: dict) -> None:
        info = self.client.publish(topic, json.dumps(payload), qos=1)
        info.wait_for_publish(10)
        if not info.is_published():
            sys.exit("MQTT publish to %s was not confirmed" % topic)

    def close(self) -> None:
        self.client.loop_stop()
        self.client.disconnect()


def make_transport(a: argparse.Namespace):
    if a.mode == "local":
        return LocalTransport(a)
    from demo_incident import DockerTransport     # same transport the project's own demo uses
    t = DockerTransport(a.base.rstrip("/"), a.ca)
    if a.api_user:
        t.user, t.password = a.api_user, a.api_password or t.password
    return t
