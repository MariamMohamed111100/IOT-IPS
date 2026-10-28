"""Flow extractor: packets (a PCAP file, or live) -> CICIoT2023 feature rows.

    python extractor.py capture.pcap out.csv                  # live-style: one stream
    python extractor.py capture.pcap out.csv --split-mb 10    # exactly like the dataset

Follows the dataset authors' own converter (CICIoT2023 "Supplementary Materials/pcap2csv",
Feature_extraction.py), rule by rule:
- only IPv4 and ARP packets make rows; IPv6, other Ethernet types and unreadable frames are
  skipped and do not count for IAT
- per packet: IAT = time since the previous kept packet (0 for the first); ports decide
  HTTP 80, HTTPS 443, SSH 22, Telnet 23, IRC 21, SMTP 25 (TCP only), DNS 53 (UDP only),
  DHCP 67<->68 (UDP only); Header_Length = TCP 20 + options or UDP 8, else 0; ARP rows have
  Protocol Type, TTL, IPv and LLC = 0; LLC = 1 for every IPv4 packet (as in their code)
- per window of 10 consecutive kept packets: means of the per-packet values; Protocol Type =
  most common (smallest on a tie); flag counts = sums; Tot sum, Min, Max, AVG = Tot size, Std
  and Variance (sample, n-1) of the frame lengths; Number = packets; Rate = Number / (last
  time - first time)
- the dataset first cut each capture into 10 MB pieces (tcpdump -C 10) and converted each piece
  on its own, so windows and IAT restart at every piece; --split-mb 10 does the same
check_definitions.py and compare_pcap.py confirm these rules on the dataset's CSV and PCAP.
"""
from __future__ import annotations

import argparse
import math
import statistics
from collections import Counter
from dataclasses import dataclass
from itertools import pairwise

import dpkt

# Column order of the CICIoT2023 CSV files.
FEATURES = [
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate", "fin_flag_number",
    "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number",
    "ece_flag_number", "cwr_flag_number", "ack_count", "syn_count", "fin_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP", "ARP", "ICMP",
    "IGMP", "IPv", "LLC", "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number",
    "Variance"]
TCP_PORTS = {"HTTP": 80, "HTTPS": 443, "SSH": 22, "Telnet": 23, "IRC": 21, "SMTP": 25}
LAYERS = ["HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP", "ARP",
          "ICMP", "IGMP", "IPv", "LLC"]
FLAGS = {"fin": dpkt.tcp.TH_FIN, "syn": dpkt.tcp.TH_SYN, "rst": dpkt.tcp.TH_RST,
         "psh": dpkt.tcp.TH_PUSH, "ack": dpkt.tcp.TH_ACK, "ece": dpkt.tcp.TH_ECE,
         "cwr": dpkt.tcp.TH_CWR}
PCAP_HEADER, RECORD_HEADER = 24, 16        # bytes, for cutting like tcpdump -C


@dataclass
class Packet:
    """What one packet contributes (DPKT fields)."""
    ts: float
    length: int                    # bytes of the captured Ethernet frame
    proto: int                     # IP protocol number, 0 for ARP
    ttl: int
    header_len: int
    flags: dict
    layers: dict                   # LAYERS -> 0/1
    piece: int = 0                 # which 10 MB piece of the capture (see --split-mb)


def parse(ts: float, frame: bytes) -> Packet | None:
    """One packet, or None when the dataset's converter skips it."""
    try:
        eth = dpkt.ethernet.Ethernet(frame)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return None
    layers = dict.fromkeys(LAYERS, 0)
    flags = dict.fromkeys(FLAGS, 0)
    if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
        layers["ARP"] = 1
        return Packet(ts, len(frame), 0, 0, 0, flags, layers)
    ip = eth.data
    if eth.type != dpkt.ethernet.ETH_TYPE_IP or not isinstance(ip, dpkt.ip.IP):
        return None
    layers["IPv"] = layers["LLC"] = 1
    header_len = 0
    seg = ip.data
    if isinstance(seg, dpkt.tcp.TCP):
        layers["TCP"] = 1
        header_len = seg.__hdr_len__ + len(seg.opts)
        flags = {k: int(bool(seg.flags & bit)) for k, bit in FLAGS.items()}
        for name, port in TCP_PORTS.items():
            layers[name] = int(port in (seg.sport, seg.dport))
    elif isinstance(seg, dpkt.udp.UDP):
        layers["UDP"] = 1
        header_len = 8
        layers["DNS"] = int(53 in (seg.sport, seg.dport))
        layers["DHCP"] = int({seg.sport, seg.dport} == {67, 68})
    layers["ICMP"] = int(ip.p == 1)
    layers["IGMP"] = int(ip.p == 2)
    return Packet(ts, len(frame), ip.p, ip.ttl, header_len, flags, layers)


def read_pcap(path: str, split_mb: float | None = None) -> list[Packet]:
    """Kept packets of a pcap/pcapng file. split_mb numbers the pieces tcpdump -C would cut."""
    limit = split_mb * 1_000_000 if split_mb else math.inf
    with open(path, "rb") as f:
        try:
            reader = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)
        out, piece, size = [], 0, PCAP_HEADER
        for ts, frame in reader:
            if size > limit:                   # tcpdump starts a new file before this packet
                piece, size = piece + 1, PCAP_HEADER
            size += RECORD_HEADER + len(frame)
            p = parse(float(ts), frame)
            if p is not None:
                p.piece = piece
                out.append(p)
    return out


def window_row(win: list[Packet], gaps: list[float]) -> dict:
    n = len(win)
    lengths = [p.length for p in win]
    total = sum(lengths)
    mean = lambda values: sum(values) / n
    counts = Counter(p.proto for p in win)
    top = max(counts.values())
    duration = win[-1].ts - win[0].ts
    row = {"Header_Length": mean([p.header_len for p in win]),
           "Protocol Type": min(k for k, c in counts.items() if c == top),
           "Time_To_Live": mean([p.ttl for p in win]),
           "Rate": n / duration if duration > 0 else math.inf}
    for k in FLAGS:
        row[f"{k}_flag_number"] = mean([p.flags[k] for p in win])
    for k in ("ack", "syn", "fin", "rst"):
        row[f"{k}_count"] = sum(p.flags[k] for p in win)
    for k in LAYERS:
        row[k] = mean([p.layers[k] for p in win])
    std = statistics.stdev(lengths) if n > 1 else math.nan    # sample std, as pandas .std()
    row.update({"Tot sum": total, "Min": min(lengths), "Max": max(lengths), "AVG": total / n,
                "Std": std, "Tot size": total / n, "IAT": mean(gaps), "Number": n,
                "Variance": std ** 2})
    return {f: row[f] for f in FEATURES}


def extract(packets: list[Packet], window: int = 10) -> list[dict]:
    """Feature rows, one per `window` packets of each piece (a piece's last window may be
    shorter). A 1-packet window has Std = NaN and Rate = inf, as in the dataset's converter."""
    rows, start = [], 0
    while start < len(packets):
        end = start
        while end < len(packets) and packets[end].piece == packets[start].piece:
            end += 1
        piece = packets[start:end]
        gaps = [0.0] + [b.ts - a.ts for a, b in pairwise(piece)]
        for i in range(0, len(piece), window):
            rows.append(window_row(piece[i:i + window], gaps[i:i + window]))
        start = end
    return rows


if __name__ == "__main__":
    import csv
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("out")
    ap.add_argument("--window", type=int, default=10)
    ap.add_argument("--split-mb", type=float, default=None,
                    help="cut the capture like the dataset did (10)")
    args = ap.parse_args()
    rows = extract(read_pcap(args.pcap, args.split_mb), args.window)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FEATURES)
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows):,} rows -> {args.out}")
