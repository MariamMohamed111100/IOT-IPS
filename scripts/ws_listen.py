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


def default_credentials() -> tuple[str, str]:
    raw = os.getenv("API_USERS")
    env_file = ROOT / ".env"
    if not raw and env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("API_USERS="):
                raw = line.split("=", 1)[1].strip()
    if not raw:
        sys.exit("No credentials: pass --user/--password or run ./scripts/setup.sh first")
    user, _, password = raw.split(",")[0].partition(":")
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

    url = args.base.replace("https://", "wss://") + "/ws/events?token=" + token
    print(f"connected to {args.base}/ws/events as {user} (Ctrl+C to stop)")
    with connect(url, ssl=ctx) as ws:
        for message in ws:
            print(json.dumps(json.loads(message), separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
