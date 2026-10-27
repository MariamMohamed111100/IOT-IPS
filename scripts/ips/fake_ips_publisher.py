#!/usr/bin/env python3
"""Publishes realistic IoT-IPS detections (contract v1.2 events on security/alerts/cyber) into the stack.
Uses ips_to_backend.py, the same adapter the real IPS pipeline will use. The backend `engine` turns the events into
incidents; use --standalone only when no engine is running (it then also publishes risk and incident messages).

    python scripts/ips/fake_ips_publisher.py                       # every sample detection (docker stack)
    python scripts/ips/fake_ips_publisher.py --only brute_force --now --repeat 3
    python scripts/ips/fake_ips_publisher.py --standalone --now    # demo without the engine
    python scripts/ips/fake_ips_publisher.py --list

--now      use the current time instead of the sample's own time (so the dashboard shows "just now")
--repeat N the same detection N times (new event ids each time)
"""
import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ips_to_backend as m  # noqa: E402
from ips_transport import add_transport_args, make_transport  # noqa: E402

SAMPLES = Path(__file__).resolve().parent / "ips_samples.json"


def load_samples() -> list:
    return json.loads(SAMPLES.read_text(encoding="utf-8"))


def plan(samples, only=None, now=False, repeat=1, step=20.0, standalone=False):
    """All (topic, payload) pairs to publish, in order. Pure function: used by the tests."""
    base = datetime.now(timezone.utc) if now else None
    out = []
    for n, s in enumerate(samples):
        if only and s["name"] not in only:
            continue
        for r in range(repeat):
            ts = (base + timedelta(seconds=n * 3 + r * step)) if base else (
                datetime.fromisoformat(m.iso(s["incident"].get("timestamp"))) + timedelta(seconds=r * step))
            msgs = m.build_events(s["incident"], s["event"], s["report"], s["profile"], ts=ts, seq=r)
            if standalone and r == 0:
                msgs += m.standalone_messages(s["incident"], msgs[0][1])
            for topic, payload in msgs:
                m.check_message(topic, payload)
                out.append((topic, payload))
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    add_transport_args(p)
    p.add_argument("--only", action="append", help="sample name (repeatable); see --list")
    p.add_argument("--list", action="store_true")
    p.add_argument("--now", action="store_true")
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--delay", type=float, default=1.0, help="seconds between incidents")
    p.add_argument("--dry-run", action="store_true", help="validate and print, do not publish")
    p.add_argument("--standalone", action="store_true", help="also publish risk and incident messages (no engine running)")
    a = p.parse_args(argv)
    samples = load_samples()
    if a.list:
        for s in samples:
            i = s["incident"]
            print("%-26s %-9s IPS %3s  %s" % (s["name"], i["level"], i["score"], i["attack_type"]))
        return 0
    known = {s["name"] for s in samples}
    if a.only and not set(a.only) <= known:
        print("unknown sample(s): %s (see --list)" % ", ".join(sorted(set(a.only) - known)))
        return 2
    msgs = plan(samples, a.only, a.now, max(1, a.repeat), standalone=a.standalone)
    if a.dry_run:
        for topic, payload in msgs:
            print(topic, json.dumps(payload)[:140])
        print("%d messages valid" % len(msgs))
        return 0
    t = make_transport(a)
    for topic, payload in msgs:
        t.publish(topic, payload)
        if payload.get("type", "").startswith("cyber.") and not payload["type"].startswith("cyber.block"):
            d = payload["data"]
            print("%-26s %-8s %s -> %s  IPS %d (%s)" % (payload["type"], payload["severity_hint"], d["src_ip"], d["device_id"],
                                                       d["details"]["ips_score"], d["details"]["ips_level"]))
            time.sleep(a.delay)
    if hasattr(t, "close"):
        t.close()
    print("published %d messages" % len(msgs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
