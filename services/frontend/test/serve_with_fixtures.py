# ruff: noqa: E501
#!/usr/bin/env python3
"""Serves the dashboard with the recorded API responses (fixtures.json), no Docker needed.
    python services/frontend/test/serve_with_fixtures.py            # http://localhost:8099, login: admin / admin
Useful to look at the dashboard, and to try screenshots.py without the stack:
    python services/frontend/test/screenshots.py --base http://localhost:8099 --user admin --password admin
There is no WebSocket here, so nothing updates live."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

HERE = Path(__file__).resolve().parent
FX = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
HTML = (HERE.parent / "index.html").read_bytes()


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = unquote(urlparse(self.path).path)
        if path in ("/", "/index.html"):
            return self._send(200, HTML, "text/html; charset=utf-8")
        if path == "/favicon.ico":
            return self._send(204, b"")
        routes = {
            "/api/zones": FX["zones"],
            "/api/devices": FX["devices"],
            "/api/events": FX["events"],
            "/api/incidents": FX["incidents"],
            "/api/risk": FX["risk"],
        }
        if path in routes:
            return self._send(200, routes[path])
        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[:2] == ["api", "incidents"] and parts[3] == "events":
            return self._send(200, FX["incident_events"].get(parts[2], []))
        self._send(404, {"detail": "Not Found"})

    def do_POST(self):
        if urlparse(self.path).path == "/api/auth/login":
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            if body.get("username") == "admin" and body.get("password") == "admin":
                return self._send(200, {"access_token": "fixture-token", "token_type": "bearer"})
            return self._send(401, {"detail": "Invalid credentials"})
        self._send(404, {"detail": "Not Found"})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    a = ap.parse_args()
    print("dashboard on http://localhost:%d  (login admin / admin)" % a.port)
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()
