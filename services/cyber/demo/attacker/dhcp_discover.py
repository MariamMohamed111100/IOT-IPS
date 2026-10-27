"""Play a rogue device asking the network for a DHCP lease.

Sends a full DORA exchange (DISCOVER -> OFFER -> REQUEST -> ACK) from a chosen MAC.
Suricata only writes a `dhcp` record once it sees the ACK that pins a MAC to an IP
(that is what "just enough information to map a MAC address to an IP" means with
`extended: no`), so a lone DISCOVER is invisible to the rogue-device detector.

There is no DHCP server on the demo bridge, so this script also plays one: the
OFFER/ACK packets are valid BOOTREPLYs for a made-up 192.168.1.0/24 network.

Pure standard library, needs root (UDP ports 67 and 68).
Usage: dhcp_discover.py <mac> [hostname]
"""
from __future__ import annotations

import os
import socket
import sys
import time

MAGIC = bytes([99, 130, 83, 99])
SERVER_IP = "192.168.1.1"
LEASE_IP = "192.168.1.77"
BROADCAST = ("255.255.255.255", 67)
CLIENT_PORT = 68
SERVER_PORT = 67


def _mac(mac: str) -> bytes:
    hw = bytes(int(part, 16) for part in mac.split(":"))
    if len(hw) != 6:
        raise ValueError("MAC must have six octets")
    return hw


def _bootp(op: int, hw: bytes, xid: int, *, yiaddr: str = "0.0.0.0",
           siaddr: str = "0.0.0.0") -> bytes:
    return (
        bytes([op, 1, 6, 0])                       # op, ethernet, hlen 6, hops 0
        + xid.to_bytes(4, "big")
        + bytes(2) + (0x8000).to_bytes(2, "big")   # secs, flags = broadcast
        + socket.inet_aton("0.0.0.0")              # ciaddr
        + socket.inet_aton(yiaddr)
        + socket.inet_aton(siaddr)
        + socket.inet_aton("0.0.0.0")              # giaddr
        + hw + bytes(10) + bytes(64) + bytes(128)  # chaddr (16), sname, file
        + MAGIC
    )


def build_discover(mac: str, hostname: str = "rogue-demo", xid: int | None = None) -> bytes:
    hw = _mac(mac)
    xid = int.from_bytes(os.urandom(4), "big") if xid is None else xid
    name = hostname.encode("ascii", "ignore")[:63]
    packet = _bootp(1, hw, xid)                    # BOOTREQUEST
    packet += bytes([53, 1, 1])                    # option 53: DHCPDISCOVER
    packet += bytes([12, len(name)]) + name        # option 12: hostname
    packet += bytes([55, 3, 1, 3, 6])              # option 55: parameter request list
    return packet + bytes([255])


def build_request(mac: str, hostname: str = "rogue-demo", xid: int = 0,
                  requested_ip: str = LEASE_IP, server_ip: str = SERVER_IP) -> bytes:
    hw = _mac(mac)
    name = hostname.encode("ascii", "ignore")[:63]
    packet = _bootp(1, hw, xid)                    # BOOTREQUEST
    packet += bytes([53, 1, 3])                    # option 53: DHCPREQUEST
    packet += bytes([50, 4]) + socket.inet_aton(requested_ip)   # requested IP
    packet += bytes([54, 4]) + socket.inet_aton(server_ip)      # server identifier
    packet += bytes([12, len(name)]) + name
    return packet + bytes([255])


def build_reply(kind: str, mac: str, xid: int, *, yiaddr: str = LEASE_IP,
                server_ip: str = SERVER_IP, hostname: str = "rogue-demo") -> bytes:
    """A BOOTREPLY from the pretend server: kind is "offer" or "ack"."""
    hw = _mac(mac)
    name = hostname.encode("ascii", "ignore")[:63]
    packet = _bootp(2, hw, xid, yiaddr=yiaddr, siaddr=server_ip)
    packet += bytes([53, 1, 2 if kind == "offer" else 5])       # DHCPOFFER / DHCPACK
    packet += bytes([54, 4]) + socket.inet_aton(server_ip)      # server identifier
    packet += bytes([51, 4]) + (3600).to_bytes(4, "big")        # lease time
    packet += bytes([1, 4]) + socket.inet_aton("255.255.255.0")  # subnet mask
    packet += bytes([3, 4]) + socket.inet_aton(server_ip)       # router
    packet += bytes([12, len(name)]) + name
    return packet + bytes([255])


def _udp(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("127.0.0.1", port))  # nosec B104
    return sock


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    mac = argv[1]
    hostname = argv[2] if len(argv) > 2 else "rogue-demo"
    xid = int.from_bytes(os.urandom(4), "big")

    with _udp(CLIENT_PORT) as client, _udp(SERVER_PORT) as server:
        def to_client(packet: bytes) -> None:
            server.sendto(packet, ("255.255.255.255", CLIENT_PORT))

        client.sendto(build_discover(mac, hostname, xid), BROADCAST)
        time.sleep(0.2)
        to_client(build_reply("offer", mac, xid, hostname=hostname))
        time.sleep(0.2)
        client.sendto(build_request(mac, hostname, xid), BROADCAST)
        time.sleep(0.2)
        to_client(build_reply("ack", mac, xid, hostname=hostname))

    print(f"sent DHCP DISCOVER/OFFER/REQUEST/ACK as {mac} -> lease {LEASE_IP}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
