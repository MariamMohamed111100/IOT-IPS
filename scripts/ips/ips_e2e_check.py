#!/usr/bin/env python3
"""Checks, through the API, that IPS detections reached the backend with their reports (run after fake_ips_publisher.py).
Exit code 0 = all checks passed.   python scripts/ips/ips_e2e_check.py [--expect 7]"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ips_transport import add_transport_args, make_transport  # noqa: E402


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    add_transport_args(p)
    p.add_argument("--expect", type=int, default=7, help="minimum number of IPS detections expected")
    p.add_argument("--sensor-only", action="store_true",
                   help="count only alerts of the real sensor services/ips_cyber (they carry data.ips_device_id), not the fake publisher")
    p.add_argument("--standalone", action="store_true", help="also check incidents and risk (publisher ran with --standalone)")
    a = p.parse_args(argv)
    t = make_transport(a)
    bad = []

    def check(ok, text):
        print(("PASS  " if ok else "FAIL  ") + text)
        if not ok:
            bad.append(text)
    _, devices = t.api("GET", "/devices")
    ids = {d["device_id"] for d in devices or []}
    check({"cam_001", "thermo_001"} <= ids, "IPS devices are registered (%d devices)" % len(ids))
    # Filter by source: the live vision feed can add more than the 500-row page limit in a minute,
    # which would push the IPS events off an unfiltered "newest 500" query.
    _, events = t.api("GET", "/events", params={"limit": 500, "source": "cyber"})
    dets = [e for e in events or [] if e["type"] in ("cyber.port_scan", "cyber.brute_force", "cyber.dos", "cyber.unexpected_traffic")
            and "details" in (e.get("data") or {})]
    if a.sensor_only:
        dets = [e for e in dets if "ips_device_id" in e["data"]]
    sensor = [e for e in events or [] if "ips_device_id" in (e.get("data") or {}) and e["type"] in (
        "cyber.port_scan", "cyber.brute_force", "cyber.dos", "cyber.unexpected_traffic")]
    check(all("details" in e["data"] for e in sensor) and (bool(sensor) or not a.sensor_only),
          "every alert of the real sensor (ips_cyber) carries data.details (%d alerts)" % len(sensor))
    check(len(dets) >= a.expect, "at least %d IPS detections stored with details (found %d)" % (a.expect, len(dets)))
    for e in dets[:a.expect]:
        d, det = e["data"], e["data"]["details"]
        ok = all(det.get("reports", {}).get(k) for k in ("technical", "executive")) and det.get("mitre_technique") and d.get("device_id")
        check(bool(ok), "%s on %s: MITRE %s, IPS %s (%s), both reports present" % (e["type"], d.get("device_id"),
              det.get("mitre_technique"), det.get("ips_score"), det.get("ips_level")))
    blocks = [e for e in events or [] if e["type"] in ("cyber.block_applied", "cyber.block_refused")]
    check(any(b["data"].get("dry_run") is True for b in blocks), "dry-run block results are stored (%d)" % len(blocks))
    if a.standalone:
        _, incs = t.api("GET", "/incidents", params={"limit": 100})
        check(len(incs or []) >= a.expect, "standalone incidents exist (%d)" % len(incs or []))
        _, risk = t.api("GET", "/risk")
        check(any(r["level"] in ("high", "critical") for r in risk or []), "a high or critical risk is published")
    print("\n%s" % ("ALL CHECKS PASSED" if not bad else "%d CHECK(S) FAILED" % len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
