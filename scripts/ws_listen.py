#!/usr/bin/env python3
"""Print the dashboard's live WebSocket feed in the terminal (debug tool for API + simulators).

    python scripts/ws_listen.py                       # uses API_USERS from .env
    python scripts/ws_listen.py --user admin --password '...'

Needs:  pip install websockets
The API certificate is verified against the local CA (never disable verification).
"""
import argparse
import json
import os
import pathlib
import ssl
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _env_value(key: str) -> str | None:
    raw = os.getenv(key)
    if raw:
        return raw
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
    return None


def default_credentials() -> tuple[str, str]:
    password = _env_value("API_ADMIN_PASSWORD")
    users = _env_value("API_USERS") or ""
    user = users.split(",")[0].split(":")[0] if users else "admin"
    if not password:
        sys.exit("No credentials: pass --user/--password or set API_ADMIN_PASSWORD in .env")
    return user, password


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--base", default="https://localhost:8443")
    ap.add_argument("--ca", default=str(ROOT / "infra/certs/ca.crt"))
    ap.add_argument("--user")
    ap.add_argument("--password")
    args = ap.parse_args()
    user, password = (args.user, args.password) if args.user else default_credentials()

    try:
        from websockets.sync.client import connect
    except ImportError:
        sys.exit("pip install websockets")

    ctx = ssl.create_default_context(cafile=args.ca)
    request = urllib.request.Request(
        args.base + "/auth/login",
        data=json.dumps({"username": user, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, context=ctx, timeout=10) as response:
        token = json.load(response)["access_token"]

    url = args.base.replace("https://", "wss://") + "/ws/events"
    print(f"connected to {args.base}/ws/events as {user} (Ctrl+C to stop)")
    with connect(url, ssl=ctx, subprotocols=["bearer." + token]) as ws:
        for message in ws:
            print(json.dumps(json.loads(message), separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
