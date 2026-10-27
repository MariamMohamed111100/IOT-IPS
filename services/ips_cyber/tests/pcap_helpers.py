"""Builds small synthetic PCAPs for the flow-engine tests (needs scapy)."""
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

CAMERA = "192.168.1.50"
BULB = "192.168.1.60"
ATTACKER = "192.168.1.100"
CLIENT = "192.168.1.20"
CLOUD = "34.120.0.5"
NTP = "162.159.200.1"


def _mac(ip):
    """A stable synthetic MAC per IPv4 address.

    Ether() must be fully specified: without a destination MAC scapy tries to resolve it
    with an ARP request, which blocks packet building (and therefore the whole suite) on
    hosts with no answer.
    """
    try:
        octets = [int(part) for part in ip.split(".")]
    except (AttributeError, ValueError):
        octets = [0, 0, 0, 0]
    octets = (octets + [0, 0, 0, 0])[:4]
    return "02:00:%02x:%02x:%02x:%02x" % tuple(octets)


def _pkt(t, src, dst, sport, dport, flags=None, proto="TCP", payload=b""):
    if proto == "TCP":
        l4 = TCP(sport=sport, dport=dport, flags=flags or "A")
    elif proto == "UDP":
        l4 = UDP(sport=sport, dport=dport)
    else:
        l4 = ICMP()
    p = Ether(src=_mac(src), dst=_mac(dst)) / IP(src=src, dst=dst) / l4 / payload
    p.time = t
    return p


def refused(t, src, dst, sport, dport):
    """SYN answered by RST: a closed port / failed probe."""
    return [_pkt(t, src, dst, sport, dport, "S"), _pkt(t + 0.01, dst, src, dport, sport, "RA")]


def failed_login(t, src, dst, sport, dport):
    """Full handshake, a few packets, closed within a fraction of a second."""
    return [_pkt(t, src, dst, sport, dport, "S"),
            _pkt(t + 0.01, dst, src, dport, sport, "SA"),
            _pkt(t + 0.02, src, dst, sport, dport, "A"),
            _pkt(t + 0.05, src, dst, sport, dport, "PA", payload=b"x" * 40),
            _pkt(t + 0.08, dst, src, dport, sport, "PA", payload=b"y" * 20),
            _pkt(t + 0.1, dst, src, dport, sport, "FA"),
            _pkt(t + 0.11, src, dst, sport, dport, "FA")]


def long_session(t, src, dst, sport, dport, seconds=5.0, packets=14):
    """A normal viewing session: handshake, steady data, orderly close."""
    out = [_pkt(t, src, dst, sport, dport, "S"),
           _pkt(t + 0.01, dst, src, dport, sport, "SA"),
           _pkt(t + 0.02, src, dst, sport, dport, "A")]
    gap = seconds / packets
    for i in range(packets):
        out.append(_pkt(t + 0.1 + i * gap, dst, src, dport, sport, "PA", payload=b"v" * 200))
    out += [_pkt(t + seconds + 0.2, src, dst, sport, dport, "FA"),
            _pkt(t + seconds + 0.21, dst, src, dport, sport, "FA")]
    return out


def syn_only(t, src, dst, sport, dport):
    return [_pkt(t, src, dst, sport, dport, "S")]


def udp_exchange(t, src, dst, sport, dport):
    return [_pkt(t, src, dst, sport, dport, proto="UDP", payload=b"q"),
            _pkt(t + 0.02, dst, src, dport, sport, proto="UDP", payload=b"r")]


def icmp_ping(t, src, dst):
    return [_pkt(t, src, dst, 0, 0, proto="ICMP")]


def write(path, packets):
    packets = sorted(packets, key=lambda p: p.time)
    wrpcap(path, packets)
    return path
