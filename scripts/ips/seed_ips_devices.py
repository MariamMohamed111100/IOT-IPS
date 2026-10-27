#!/usr/bin/env python3
"""Registers the IoT-IPS devices (config/ips_devices.json) in the SmartSecure backend so they appear in the dashboard.

    python scripts/ips/seed_ips_devices.py                                              (docker stack)
    python scripts/ips/seed_ips_devices.py --mode local --base http://localhost:8000 ...

Safe to run again: devices that already exist are skipped (HTTP 409). Exit code 0 = every device present.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ips_to_backend as m  # noqa: E402
from ips_transport import add_transport_args, make_transport  # noqa: E402


def load_profiles(path: Path) -> list:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    items = data.get("devices", []) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ValueError("devices.json must be a list or {\"devices\": [...]}")
    return [d for d in items if isinstance(d, dict) and d.get("device_id")]


def device_payload(profile: dict, zones=()) -> dict:
    ips_id = str(profile["device_id"])
    zone = profile.get("zone") if profile.get("zone") in zones or not zones else "network"
    return {
        "device_id": m.backend_device_id(ips_id, profile),
        "name": ("%s (%s)" % (str(profile.get("device_type", "device")).replace("_", " ").title(), ips_id))[:100],
        "device_type": str(profile.get("backend_type") or m.token(profile.get("device_type"))),
        "zone": str(zone or "network"),
        "online": True,
        "state": {k: v for k, v in {"ip": profile.get("ip"), "trust_score": 90, "ips_device_id": ips_id,
                                    "criticality": profile.get("criticality")}.items() if v is not None},
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    add_transport_args(p)
    p.add_argument("--devices", default=str(Path(__file__).resolve().parent.parent.parent / "config" / "ips_devices.json"),
                   help="device list (default: config/ips_devices.json)")
    p.add_argument("--dry-run", action="store_true", help="print what would be created")
    a = p.parse_args(argv)
    try:
        profiles = load_profiles(Path(a.devices))
    except (OSError, ValueError) as exc:
        print("cannot read %s: %s" % (a.devices, exc))
        return 2
    t = None if a.dry_run else make_transport(a)
    zones = ()
    if t:
        status, zs = t.api("GET", "/zones")
        zones = [z["name"] for z in zs] if status == 200 and isinstance(zs, list) else ()
    created = existing = failed = 0
    for prof in profiles:
        body = device_payload(prof, zones)
        if a.dry_run:
            print("would create", json.dumps(body))
            continue
        status, resp = t.api("POST", "/devices", body)
        if status == 201:
            created += 1
            print("created  %-12s -> %s (%s, zone %s)" % (prof["device_id"], body["device_id"], body["device_type"], body["zone"]))
        elif status == 409:
            existing += 1
            print("exists   %-12s -> %s" % (prof["device_id"], body["device_id"]))
        else:
            failed += 1
            print("FAILED   %-12s HTTP %s %s" % (prof["device_id"], status, resp))
    print("done: %d created, %d already there, %d failed" % (created, existing, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
