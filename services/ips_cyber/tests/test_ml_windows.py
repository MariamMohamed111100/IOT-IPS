"""Live ML windows (Task 6 wiring): 10-packet windows -> model -> gated alert, on a synthetic capture.

Needs the ML package (the CI jobs ips-cyber and ml install it). The capture is built with dpkt here, so no file is needed.
"""
import json
import pathlib
import random
import socket
import tempfile
import unittest

import dpkt
from ips_cyber import service

from ids_ml.extractor import read_pcap
from ids_ml.live import WindowBuffer

ROOT = pathlib.Path(__file__).resolve().parents[3]
DEVICES = json.loads((ROOT / "lab" / "ips_devices.json").read_text())["devices"]
CAMERA, ATTACKER, CLIENT = "10.77.0.10", "10.77.0.66", "10.77.0.20"


def frame(src, dst, sport, dport, flags, payload=b""):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=random.randrange(2 ** 32), win=1024)
    tcp.data = payload
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=6, ttl=64)
    ip.data = tcp
    ip.len = 20 + len(bytes(tcp))
    eth = dpkt.ethernet.Ethernet(dst=b"\0" * 6, src=b"\1" * 6, type=dpkt.ethernet.ETH_TYPE_IP)
    eth.data = ip
    return bytes(eth)


def syn_flood(n=300, t0=1_800_000_000.0):
    random.seed(1)
    return [(t0 + i * 0.0002, frame(ATTACKER, CAMERA, random.randrange(1024, 65535), 443, dpkt.tcp.TH_SYN)) for i in range(1, n + 1)]


def write(pkts):
    f = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    w = dpkt.pcap.Writer(f)
    for ts, fr in pkts:
        w.writepkt(fr, ts=ts)
    f.close()
    return f.name


class Collect:
    def __init__(self):
        self.sent = []

    def publish(self, topic, payload):
        self.sent.append(payload)

    def close(self):
        pass


def run(pkts, **kw):
    path = write(pkts)
    pub = Collect()
    config = service.load_service_config()
    from iot_ips import detector

    from ids_ml.combined import make_detect
    svc = service.IpsCyberService(DEVICES, pub, config, detect_fn=make_detect(
        rules=lambda ev, prof=None: detector.detect(ev, prof)), **kw)
    from ips_cyber import sources
    svc.run(sources.pcap_source(path, DEVICES, config["flow_engine"], ml_windows=True), "lab.pcap")
    return svc, pub.sent


class WindowEventTests(unittest.TestCase):
    def test_a_flood_window_names_device_source_and_port(self):
        events = WindowBuffer(DEVICES).feed(read_pcap(write(syn_flood())))
        self.assertEqual(len(events), 30)
        e = events[0]
        self.assertEqual((e["device_id"], e["src_ip"], e["dst_ip"], e["dst_port"], e["protocol"], e["direction"]),
                         ("CAM-001", ATTACKER, CAMERA, 443, "TCP", "inbound"))
        self.assertEqual(e["syn_count"], 10)

    def test_traffic_between_other_hosts_makes_no_event(self):
        pk = [(1_800_000_000.0 + i * 0.01, frame("10.9.0.1", "10.9.0.2", 1000, 80, dpkt.tcp.TH_ACK)) for i in range(40)]
        self.assertEqual(WindowBuffer(DEVICES).feed(read_pcap(write(pk))), [])

    def test_a_part_window_waits_for_the_next_feed(self):
        packets = read_pcap(write(syn_flood(25)))
        buf = WindowBuffer(DEVICES)
        self.assertEqual(len(buf.feed(packets[:15])), 1)
        self.assertEqual(len(buf.feed(packets[15:])), 1)           # 5 waiting + 10 new -> window 2; 5 still wait

    def test_outbound_direction_when_the_device_speaks_first(self):
        pk = [(1_800_000_000.0 + i * 0.001, frame(CAMERA, "10.77.0.99", 40000 + i, 443, dpkt.tcp.TH_SYN)) for i in range(20)]
        e = WindowBuffer(DEVICES).feed(read_pcap(write(pk)))[0]
        self.assertEqual((e["direction"], e["src_ip"], e["dst_ip"]), ("outbound", CAMERA, "10.77.0.99"))


class PipelineTests(unittest.TestCase):
    def test_a_syn_flood_raises_one_dos_alert_with_details(self):
        svc, sent = run(syn_flood())
        dos = [a for a in sent if a["type"] == "cyber.dos"]
        self.assertEqual(len(dos), 1)                                # 30 windows, one alert
        self.assertEqual(dos[0]["data"]["src_ip"], ATTACKER)
        self.assertEqual(dos[0]["data"]["detector"], "ml")           # the rules saw nothing; the model did
        self.assertIn("details", dos[0]["data"])
        self.assertGreater(svc.stats["window_alerts_suppressed"], 0)

    def test_one_flagged_window_is_not_enough(self):
        svc, sent = run(syn_flood(10))                               # exactly one window
        self.assertEqual([a for a in sent if a["data"].get("src_ip") == ATTACKER], [])

    def test_confirmation_can_be_set(self):
        _, sent = run(syn_flood(10), ml_confirm=1)
        self.assertEqual(len([a for a in sent if a["type"] == "cyber.dos"]), 1)

    def test_cooldown_lets_a_later_attack_through(self):
        late = [(ts + 100, fr) for ts, fr in syn_flood()]
        _, sent = run(syn_flood() + late)
        self.assertEqual(len([a for a in sent if a["type"] == "cyber.dos"]), 2)


if __name__ == "__main__":
    unittest.main()
