"""demo_chain.py - a hand-written scenario chain (NOT the project samples; those come from make_samples.py).

Runs the chain event -> detection -> risk -> policy -> actions -> incident -> reports on five scripted
events and writes the reports to output/demo_chain/. Run:  python scripts/demo_chain.py
"""
import json
import warnings

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
try:
    import iot_ips  # noqa: F401  (installed with: pip install -e .)
except ImportError:
    sys.path.insert(0, str(ROOT / "src"))

from iot_ips import policy, risk  # noqa: E402
from iot_ips.actions import ActionExecutor  # noqa: E402
from iot_ips.paths import DEFAULT_DEVICES_PATH  # noqa: E402
from iot_ips.report import build_incident, make_report  # noqa: E402

warnings.simplefilter("ignore")


def _load_devices():
    data = json.loads(DEFAULT_DEVICES_PATH.read_text(encoding="utf-8"))   # config/devices.json
    return {x["device_id"]: x for x in (data["devices"] if isinstance(data, dict) else data)}   # a list, or {"devices": [...]}


DEV = _load_devices()   # the one device list of the project (config/devices.json)
A = lambda t, c: {"label": "ATTACK", "attack_type": t, "confidence": c}
SCENARIOS = [  # (device, detection, event)
 ("BULB-001", A("port_scan", .55), {"timestamp": "2026-10-18T09:12:40Z", "src_ip": "192.168.1.20", "dst_port": 80, "connection_attempts": 3, "protocol": "TCP", "duration": "6 seconds"}),
 ("TEMP-001", A("unexpected_protocol", .82), {"timestamp": "2026-10-18T13:47:05Z", "src_ip": "192.168.1.77", "dst_port": 4444, "connection_attempts": 9, "protocol": "TCP", "duration": "3 minutes"}),
 ("CAM-001", A("dos", .91), {"timestamp": "2026-10-19T02:31:18Z", "src_ip": "192.168.1.134", "dst_port": 554, "connection_attempts": 48200, "protocol": "TCP", "duration": "90 seconds"}),
 ("CAM-001", A("brute_force", .94), {"timestamp": "2026-10-19T21:05:52Z", "src_ip": "192.168.1.100", "dst_port": 22, "failed_attempts": 431, "protocol": "TCP", "duration": "4 minutes"}),
 ("CAM-001", A("brute_force", .94), {"timestamp": "2026-10-20T08:20:10Z", "src_ip": "192.168.1.10", "dst_port": 22, "failed_attempts": 431, "protocol": "TCP", "duration": "4 minutes"}),  # allow-listed source
]
if __name__ == "__main__":
    out = ROOT / "output" / "demo_chain"; out.mkdir(parents=True, exist_ok=True)
    pol = policy.load_policy(); ex = ActionExecutor.from_policy(pol, log_path=str(out / "action_log.jsonl"))
    built = []
    for i, (dev, det, ev) in enumerate(SCENARIOS, 28):
        prof = DEV[dev]; ev = dict(ev, dst_ip=prof["ip"])
        rk = risk.assess(det, ev, prof)
        dc = policy.decide(rk, det, ev, prof, pol); ex.run(dc)
        inc = build_incident(ev, det, rk, dc, prof, incident_id=f"INC-{i:05d}")
        built.append(inc)
        r = make_report(inc); tag = f"{inc['id']}_{inc['level'].lower()}"
        (out / f"{tag}_technical.md").write_text(r["technical"], encoding="utf-8", newline="\n")
        (out / f"{tag}_executive.md").write_text(r["executive"], encoding="utf-8", newline="\n")
        if r["notification"]: (out / f"{tag}_notification.txt").write_text(r["notification"], encoding="utf-8", newline="\n")
        print(inc["id"], inc["level"], inc["score"], dc["action"], "| skipped:", dc["skipped"])
    # the merged incidents, so `python report.py <file>` can rebuild the same reports from them
    (out / "demo_chain_incidents.json").write_text(json.dumps(built, indent=2, default=str), encoding="utf-8", newline="\n")
    print("wrote output/demo_chain/demo_chain_incidents.json")
