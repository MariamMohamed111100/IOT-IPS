"""Strict parsers for values that come from the network or from MQTT (all of them untrusted)."""
from __future__ import annotations

import ipaddress
import math
import re

_MAC = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$", re.IGNORECASE)
_UNSAFE = re.compile(r"[^A-Za-z0-9 /_.:@-]")

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def valid_ip(value: object) -> str | None:
    """A single, normalised IP address, or None. Never accepts CIDRs, scopes or hostnames."""
    if not isinstance(value, str) or len(value) > 45 or "%" in value or "/" in value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def is_blockable(ip: str) -> bool:
    """False for addresses that must never be handed to a firewall."""
    addr = ipaddress.ip_address(ip)
    return not (addr.is_loopback or addr.is_unspecified or addr.is_multicast
                or addr.is_link_local or addr.is_reserved)


def valid_mac(value: object) -> str | None:
    """Lower-case, colon-separated MAC, or None (also for the all-zero and broadcast MAC)."""
    if not isinstance(value, str) or not _MAC.match(value.strip()):
        return None
    mac = value.strip().lower().replace("-", ":")
    return None if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") else mac


def valid_port(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 1 <= value <= 65535 else None


def finite_number(value: object) -> float | None:
    """A real, finite number (bool, NaN, inf and strings are all rejected), or None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) else None


def clean_text(value: object, limit: int) -> str:
    """Printable, bounded text safe to put in logs and events (no control characters)."""
    return _UNSAFE.sub("_", str(value))[:limit]


def parse_networks(csv: str) -> tuple[IPNetwork, ...]:
    """'10.0.0.0/8, 192.168.1.5' -> networks. A bad entry raises ValueError (fail at startup)."""
    out: list[IPNetwork] = []
    for part in csv.split(","):
        part = part.strip()
        if part:
            out.append(ipaddress.ip_network(part, strict=False))
    return tuple(out)
