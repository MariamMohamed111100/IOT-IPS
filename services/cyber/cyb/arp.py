"""Read the kernel ARP table (opt-in rogue-device source for a real gateway / the Pi)."""
from __future__ import annotations

from pathlib import Path

from .util import valid_ip, valid_mac


def read_arp(path: str | Path = "/proc/net/arp") -> list[tuple[str, str]]:
    """[(ip, mac)] for complete entries. Format: IP address, HW type, Flags, HW address, ..."""
    try:
        lines = Path(path).read_text(encoding="ascii", errors="replace").splitlines()[1:]
    except OSError:
        return []
    out: list[tuple[str, str]] = []
    for line in lines:
        cols = line.split()
        if len(cols) < 4 or cols[2] == "0x0":
            continue
        ip, mac = valid_ip(cols[0]), valid_mac(cols[3])
        if ip and mac:
            out.append((ip, mac))
    return out
