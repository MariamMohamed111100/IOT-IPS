"""The extractor on a small hand-made capture whose features are known exactly."""
import math
import socket
import sys
from pathlib import Path

import dpkt
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ids_ml.extractor import FEATURES, extract, read_pcap

CAM, PHONE = "192.168.1.50", "192.168.1.20"


def eth(payload, ip_type=dpkt.ethernet.ETH_TYPE_IP):
    return bytes(dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6, type=ip_type,
                                        data=payload))


def ipv4(src, dst, seg, proto, ttl=64):
    pkt = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=proto, ttl=ttl,
                     data=seg)
    pkt.len = len(bytes(pkt))
    return pkt


def tcp(src, dst, sport, dport, flags, opts=b"", payload=b"", ttl=64):
    seg = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, opts=opts, data=payload)
    seg.off = (20 + len(opts)) // 4
    return eth(ipv4(src, dst, seg, dpkt.ip.IP_PROTO_TCP, ttl))


def udp(src, dst, sport, dport, payload=b"x" * 10, ttl=64):
    seg = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    seg.ulen = 8 + len(payload)
    return eth(ipv4(src, dst, seg, dpkt.ip.IP_PROTO_UDP, ttl))


def arp():
    return eth(dpkt.arp.ARP(), dpkt.ethernet.ETH_TYPE_ARP)


@pytest.fixture
def capture(tmp_path):
    frames = [  # 10 packets = one window
        tcp(PHONE, CAM, 50000, 22, dpkt.tcp.TH_SYN, opts=b"\x01" * 12, ttl=64),
        tcp(CAM, PHONE, 22, 50000, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, opts=b"\x01" * 12),
        tcp(PHONE, CAM, 50000, 22, dpkt.tcp.TH_ACK),
        tcp(PHONE, CAM, 50000, 22, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=b"p" * 40),
        tcp(CAM, PHONE, 22, 50000, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=b"q" * 80),
        tcp(PHONE, CAM, 50000, 22, dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK),
        udp(CAM, "192.168.1.1", 40000, 53, ttl=128),
        udp("192.168.1.1", CAM, 53, 40000, ttl=128),
        arp(),
        tcp(PHONE, CAM, 50001, 443, dpkt.tcp.TH_RST),
    ]
    path = tmp_path / "t.pcap"
    with path.open("wb") as f:
        w = dpkt.pcap.Writer(f)
        for i, fr in enumerate(frames):
            w.writepkt(fr, ts=1000.0 + 0.5 * i)
    return path, frames


def test_one_window_with_exact_values(capture):
    path, frames = capture
    rows = extract(read_pcap(str(path)), window=10)
    assert len(rows) == 1 and list(rows[0]) == FEATURES
    r = rows[0]
    lengths = [len(f) for f in frames]
    assert r["Number"] == 10
    assert r["Tot sum"] == sum(lengths) and r["Min"] == min(lengths) and r["Max"] == max(lengths)
    assert math.isclose(r["AVG"], sum(lengths) / 10) and r["Tot size"] == r["AVG"]
    assert math.isclose(r["Variance"], r["Std"] ** 2)
    mean_len = sum(lengths) / 10                             # sample std: divide by n - 1
    assert math.isclose(r["Std"], math.sqrt(sum((x - mean_len) ** 2 for x in lengths) / 9))
    assert r["TCP"] == 0.7 and r["UDP"] == 0.2 and r["ARP"] == 0.1
    assert r["IPv"] == r["LLC"] == 0.9                       # IPv = LLC = 1 - ARP
    assert r["SSH"] == 0.6 and r["DNS"] == 0.2 and r["HTTPS"] == 0.1 and r["HTTP"] == 0
    assert r["Protocol Type"] == 6                           # majority TCP
    # TCP: 2 x 32-byte headers (options) + 5 x 20; UDP 2 x 8; ARP 0  -> mean over 10
    assert math.isclose(r["Header_Length"], (2 * 32 + 5 * 20 + 2 * 8) / 10)
    assert math.isclose(r["Time_To_Live"], (7 * 64 + 2 * 128) / 10)
    assert r["syn_flag_number"] == 0.2 and r["syn_count"] == 2
    assert r["ack_flag_number"] == 0.5 and r["ack_count"] == 5
    assert r["fin_count"] == 1 and r["rst_count"] == 1 and r["psh_flag_number"] == 0.2


def test_counts_equal_flag_share_times_number(capture):
    r = extract(read_pcap(str(capture[0])), window=10)[0]
    for k in ("ack", "syn", "fin", "rst"):
        assert math.isclose(r[f"{k}_count"], r[f"{k}_flag_number"] * r["Number"])


def test_windows_split_and_last_window_is_shorter(capture):
    rows = extract(read_pcap(str(capture[0])), window=4)
    assert [r["Number"] for r in rows] == [4, 4, 2]


def test_iat_and_rate_over_the_whole_capture(capture):
    r = extract(read_pcap(str(capture[0])), window=10)[0]
    assert math.isclose(r["IAT"], 0.5 * 9 / 10)              # 9 gaps of 0.5 s, first is 0
    assert math.isclose(r["Rate"], 10 / 4.5)                 # packets / (last - first time)


def write(path, frames, step=1.0):
    with path.open("wb") as f:
        w = dpkt.pcap.Writer(f)
        for i, fr in enumerate(frames):
            w.writepkt(fr, ts=1000.0 + step * i)
    return str(path)


def test_ipv6_and_other_frames_are_skipped_and_do_not_count_for_iat(tmp_path):
    ip6 = dpkt.ip6.IP6(src=b"\x00" * 16, dst=b"\x00" * 16, nxt=17, hlim=64,
                       data=dpkt.udp.UDP(sport=1, dport=2))
    frames = [udp(CAM, PHONE, 1, 2), eth(ip6, dpkt.ethernet.ETH_TYPE_IP6),
              eth(b"\x00" * 40, 0x88CC), udp(CAM, PHONE, 1, 2)]      # IPv6, LLDP in between
    packets = read_pcap(write(tmp_path / "s.pcap", frames))
    assert len(packets) == 2
    assert extract(packets)[0]["IAT"] == (0 + 3.0) / 2        # gap to the previous KEPT packet


def test_port_rules_of_the_dataset(tmp_path):
    frames = [tcp(PHONE, CAM, 40000, 21, dpkt.tcp.TH_ACK),          # IRC means port 21 there
              tcp(PHONE, CAM, 40000, 53, dpkt.tcp.TH_ACK),          # DNS only over UDP
              udp(PHONE, CAM, 40000, 25),                           # SMTP only over TCP
              udp(PHONE, CAM, 68, 67), udp(PHONE, CAM, 68, 5000),   # DHCP only 67 <-> 68
              tcp(PHONE, CAM, 40000, 8080, dpkt.tcp.TH_ACK)]        # HTTP only port 80
    r = extract(read_pcap(write(tmp_path / "p.pcap", frames)))[0]
    assert r["IRC"] == 1 / 6 and r["DNS"] == 0 and r["SMTP"] == 0 and r["HTTP"] == 0
    assert r["DHCP"] == 1 / 6


def test_protocol_type_tie_takes_the_smallest_number(tmp_path):
    frames = [udp(PHONE, CAM, 1, 2), tcp(PHONE, CAM, 1, 2, dpkt.tcp.TH_ACK), arp(), arp(),
              udp(PHONE, CAM, 1, 2), tcp(PHONE, CAM, 1, 2, dpkt.tcp.TH_ACK)]
    assert extract(read_pcap(write(tmp_path / "t.pcap", frames)))[0]["Protocol Type"] == 0


def test_cutting_like_tcpdump_restarts_windows_and_iat(tmp_path):
    frames = [tcp(PHONE, CAM, 40000, 80, dpkt.tcp.TH_ACK) for _ in range(30)]
    assert len(frames[0]) == 54          # file grows 16 + 54 = 70 bytes per packet after 24
    packets = read_pcap(write(tmp_path / "c.pcap", frames), split_mb=0.001)   # 1,000 bytes
    # 24 + 14 * 70 = 1,004 > 1,000, so every piece holds 14 packets: 14, 14, 2
    assert [sum(p.piece == k for p in packets) for k in range(3)] == [14, 14, 2]
    rows = extract(packets)
    assert [r["Number"] for r in rows] == [10, 4, 10, 4, 2]
    assert rows[2]["IAT"] == 0.9                             # first gap of a piece is 0
    assert [r["Number"] for r in extract(read_pcap(str(tmp_path / "c.pcap")))] == [10, 10, 10]


def test_incomplete_packets_are_skipped(tmp_path):
    path = tmp_path / "bad.pcap"
    with path.open("wb") as f:
        w = dpkt.pcap.Writer(f)
        w.writepkt(b"\x00" * 5, ts=1.0)                        # too short for Ethernet
        w.writepkt(udp(CAM, PHONE, 1, 53), ts=2.0)
    assert len(read_pcap(str(path))) == 1
