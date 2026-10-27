"""Write data/sample_events.csv, 14 believable events for the pipeline demo and tests.

    python scripts/data/make_sample_events.py        # after prepare_data.py

Each event = one REAL CICIoT2023 row from the test part (all 39 feature columns, never used for
training) + context fields that CICIoT2023 does not have, written by hand so the event tells a
story: device_id, timestamp, src_ip, dst_ip, dst_port, protocol, failed_attempts,
connection_attempts, unique_dst_ports, unique_dst_ips. Every row is picked so its real numbers fit the story (an SSH brute force
uses a row with SSH traffic, a UDP flood a row that is ~100% UDP, Mirai a GRE row, ...).
The expected_* columns say what the detector should answer; detectors must not read them.
"""
import json
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "data"
INTERIM = ROOT / "data" / "interim"
SEED = 7

# Sample devices (the ids/IPs match config/devices.json)
CAM, THERMO, PLUG = ("CAM-001", "192.168.1.50"), ("THERMO-001", "192.168.1.51"), \
    ("PLUG-001", "192.168.1.52")
PHONE, LAPTOP = "192.168.1.20", "192.168.1.21"
ROUTER, CLOUD, OUTSIDE = "192.168.1.1", "52.29.14.7", "203.0.113.45"
ROGUE, BOTNET = "192.168.1.66", "198.51.100.23"

# (original label, row filter, device, src, dst, port, protocol, failed, attempts, story)
# unique_dst_ports / unique_dst_ips: 1 and 1 for every event except the two scans (see SCANS)
SCANS = {4: (1000, 1), 5: (15, 1)}   # event index -> (unique_dst_ports, unique_dst_ips)
EVENTS = [
    ("BENIGN", lambda r: (r.TCP >= 0.9) & (r.HTTPS == 0) & (r.HTTP == 0),
     CAM, PHONE, CAM[1], 554, "TCP", 0, 1,
     "The owner's phone watches the camera's live video over RTSP."),
    ("BENIGN", lambda r: (r.HTTPS >= 0.8) & (r.TCP >= 0.9),
     CAM, CAM[1], CLOUD, 443, "TCP", 0, 1,
     "The camera uploads a recorded clip to its cloud service over HTTPS."),
    ("BENIGN", lambda r: (r.DNS > 0.5) & (r.UDP > 0.5),
     THERMO, THERMO[1], ROUTER, 53, "UDP", 0, 1,
     "The thermostat looks up its update server's address (DNS)."),
    ("BENIGN", lambda r: (r.HTTPS >= 0.5) & (r.TCP >= 0.8),
     PLUG, LAPTOP, PLUG[1], 443, "TCP", 1, 2,
     "The owner mistypes the smart plug's password once, then logs in."),
    ("RECON-PORTSCAN", lambda r: r.syn_count >= 1,
     CAM, ROGUE, CAM[1], 8000, "TCP", 985, 1000,
     ("An unknown laptop on the Wi-Fi probes 1,000 ports of the camera in 40 s (dst_port is the "
      "last port probed; the 985 failed attempts are refused connections to closed ports).")),
    ("RECON-PORTSCAN", lambda r: r.syn_count >= 1,
     CAM, ROGUE, CAM[1], 8080, "TCP", 14, 15,
     "Slow scan (evasion test): 15 ports probed over 30 minutes, under any rate threshold."),
    ("VULNERABILITYSCAN", lambda r: r.HTTP > 0,
     PLUG, ROGUE, PLUG[1], 80, "TCP", 120, 450,
     "A vulnerability scanner requests 450 known-weak URLs on the plug's web page."),
    ("DICTIONARYBRUTEFORCE", lambda r: r.SSH > 0,
     CAM, OUTSIDE, CAM[1], 22, "TCP", 300, 300,
     "300 failed SSH logins on the camera from an external address in 4 minutes."),
    ("DICTIONARYBRUTEFORCE", lambda r: r.SSH > 0,
     CAM, OUTSIDE, CAM[1], 22, "TCP", 6, 6,
     "Low-rate brute force (evasion test): 6 SSH password guesses spread over an hour."),
    ("DDOS-SYN_FLOOD", lambda r: (r.TCP >= 0.99) & (r.syn_count >= 50),
     CAM, OUTSIDE, CAM[1], 554, "TCP", 24500, 25000,
     "Many machines send 25,000 half-open TCP connections to the camera's video port."),
    ("DOS-UDP_FLOOD", lambda r: r.UDP >= 0.99,
     CAM, OUTSIDE, CAM[1], 5000, "UDP", 0, 18000,
     "One machine floods the camera with 18,000 UDP packets per second."),
    ("MITM-ARPSPOOFING", lambda r: (r.HTTPS >= 0.5) & (r.TCP >= 0.8),
     CAM, ROGUE, CLOUD, 443, "TCP", 0, 3,
     ("A rogue device poses as the router (ARP spoofing); the camera's cloud upload now "
     "passes through it.")),
    ("COMMANDINJECTION", lambda r: r.TCP >= 0.5,
     PLUG, ROGUE, PLUG[1], 80, "TCP", 3, 12,
     "Malicious requests try to run system commands through the plug's web form."),
    ("MIRAI-GREETH_FLOOD", lambda r: r["Protocol Type"] >= 40,
     CAM, CAM[1], BOTNET, 0, "GRE", 0, 9000,
     "The camera is infected with Mirai and floods an outside server with GRE packets."),
]


def _device_ips() -> dict:
    path = Path(__file__).resolve().parents[2] / "config" / "devices.json"
    return {d["device_id"]: d.get("ip") for d in json.loads(path.read_text(encoding="utf-8"))["devices"]}


DEVICE_IPS = _device_ips()


def main() -> None:
    test = pd.read_csv(INTERIM / "_test_full.csv")
    features = [c for c in test.columns if c not in ("label", "group", "Label", "source_file")]
    rows, used = [], set()
    start = pd.Timestamp("2026-10-21T09:00:00Z")
    for i, (lab, keep, dev, src, dst, port, proto, failed, tries, story) in enumerate(EVENTS):
        pool = test[(test["Label"] == lab) & keep(test) & ~test.index.isin(used)]
        if pool.empty:
            raise SystemExit(f"no test row of {lab} fits event {i + 1}: {story}")
        row = pool.sample(1, random_state=SEED + i).iloc[0]
        used.add(row.name)
        rows.append({
            "event_id": f"EVT-{i + 1:03d}", "device_id": dev[0],
            "timestamp": (start + pd.Timedelta(seconds=45 * i)).isoformat().replace("+00:00", "Z"),
            "src_ip": src, "dst_ip": dst, "dst_port": port, "protocol": proto,
            # towards the device or from it: the unexpected-port rule only judges inbound traffic
            "direction": "outbound" if src == DEVICE_IPS.get(dev[0]) else "inbound",
            "failed_attempts": failed, "connection_attempts": tries,
            "unique_dst_ports": SCANS.get(i, (1, 1))[0], "unique_dst_ips": SCANS.get(i, (1, 1))[1],
            **{f: row[f] for f in features},
            "expected_label": row["label"], "expected_attack_type": row["group"],
            "original_label": lab, "story": story})
    out = pd.DataFrame(rows)
    out.to_csv(OUT / "sample_events.csv", index=False)
    print(out[["event_id", "device_id", "dst_port", "protocol", "failed_attempts",
               "expected_label", "expected_attack_type"]].to_string(index=False))


if __name__ == "__main__":
    main()
