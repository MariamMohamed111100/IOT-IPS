"""Demo victim: a fake smart-lock web login for the attacker container to brute-force.

It also plays the part of the firewall in the simulated stack: sources listed in the shared
block-list file (written by the cyber service) are refused before a byte of HTTP is read. That is
the "block-list API" simulation of the IPS. With CYBER_FIREWALL=iptables on a real gateway the
packets would never reach this process at all.
"""
from __future__ import annotations

import hmac
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

BLOCKLIST = Path(os.getenv("BLOCKLIST_FILE", "/data/blocklist.json"))
PASSWORD = os.getenv("LOCK_PASSWORD", "Sm4rtL0ck!demo")     # not in the attacker's wordlist
PORT = int(os.getenv("PORT", "8080"))
MAX_BODY = 1024


class Blocklist:
    """Reads the file on every request; a missing or broken file blocks nobody.

    No mtime cache: the file lives on a bind mount whose timestamp granularity can be coarser
    than a second (Docker Desktop on Windows), so an unblock followed by a re-block within the
    same second used to keep serving a stale "blocked" answer. The file is tiny; one read per
    request is cheap and always correct.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def is_blocked(self, ip: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        try:
            doc = json.loads(self.path.read_text())
            ips = {b["ip"]: float(b["expires_at"]) for b in doc.get("blocks", [])}
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return False
        return ips.get(ip, 0.0) > now


def check_login(user: str, password: str) -> bool:
    return hmac.compare_digest(user.encode(), b"admin") & \
        hmac.compare_digest(password.encode(), PASSWORD.encode())


class Handler(BaseHTTPRequestHandler):
    blocklist = Blocklist(BLOCKLIST)
    server_version = "SmartLock/1.0"

    def setup(self) -> None:
        super().setup()
        if self.blocklist.is_blocked(self.client_address[0]):
            self.rfile.close()
            self.wfile.close()
            self.close_connection = True

    def handle(self) -> None:
        if self.rfile.closed:
            return                                   # blocked: refuse before reading anything
        super().handle()

    def _reply(self, code: int, text: str) -> None:
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._reply(200, "SmartLock v1 - POST /login user=...&pass=...")

    def do_POST(self) -> None:
        if self.path != "/login":
            self._reply(404, "not found")
            return
        try:
            length = min(int(self.headers.get("Content-Length", "0")), MAX_BODY)
        except ValueError:
            length = 0
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        user, password = form.get("user", [""])[0], form.get("pass", [""])[0]
        if check_login(user, password):
            self._reply(200, "unlocked")
        else:
            self._reply(401, "denied")

    def log_message(self, fmt: str, *args: object) -> None:       # one line per request
        print(f"[smartlock] {self.client_address[0]} {fmt % args}", flush=True)


if __name__ == "__main__":
    print(f"smartlock listening on :{PORT}, block-list {BLOCKLIST}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
