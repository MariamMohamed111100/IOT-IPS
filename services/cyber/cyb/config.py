"""All cyber settings come from environment variables (same code in Docker and on the Pi)."""
from __future__ import annotations

import math
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .util import IPNetwork, parse_networks

# Suricata signature ids of services/cyber/suricata/smartsecure.rules (the only ones we act on)
SID_PORT_SCAN = 9000001
SID_HTTP_LOGIN = 9000002
SID_SSH_CONNECT = 9000003

ZONE = "network"
FIREWALLS = ("blocklist", "iptables")
AUTOBLOCKABLE = ("cyber.port_scan", "cyber.brute_force", "cyber.rogue_device")
ALWAYS_PROTECTED = "127.0.0.0/8,::1/128"


def _number(env: Mapping[str, str], name: str, default: float, minimum: float,
            integer: bool = False) -> float:
    raw = env.get(name, "")
    if raw.strip() == "":
        return default
    try:
        value = int(raw) if integer else float(raw)
    except ValueError:
        raise ValueError(f"{name} must be {'an integer' if integer else 'a number'}") from None
    if not math.isfinite(value) or value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value


def _flag(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name, "").strip().lower()
    if raw == "":
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{name} must be true or false")


@dataclass(frozen=True)
class Settings:
    eve_path: Path = Path("/logs/eve.json")
    eve_from_start: bool = False
    state_file: Path = Path("/data/blocklist.json")
    known_devices_file: Path = Path("/app/known_devices.yaml")
    firewall: str = "blocklist"

    portscan_min_targets: int = 15       # distinct (host, port) pairs probed by one source
    portscan_window_s: float = 10.0
    portscan_settle_s: float = 2.0       # keep counting this long so the event carries the totals
    portscan_cooldown_s: float = 60.0

    brute_min_attempts: int = 5
    brute_window_s: float = 60.0
    brute_settle_s: float = 2.0
    brute_cooldown_s: float = 120.0

    rogue_cooldown_s: float = 300.0
    rogue_arp: bool = False              # also read the ARP table (opt-in: noisy inside Docker)
    arp_poll_s: float = 10.0

    autoblock: tuple[str, ...] = ("cyber.port_scan", "cyber.brute_force")
    autoblock_s: float = 600.0
    block_default_s: float = 3600.0      # when a system/block command carries no window
    block_min_s: float = 30.0
    block_max_s: float = 86400.0
    max_blocks: int = 256
    never_block: tuple[IPNetwork, ...] = ()

    max_sources: int = 2048              # bounded detector state (a spoofed flood cannot grow it)
    max_events_per_min: int = 60         # hard cap on what we ever publish

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        firewall = env.get("CYBER_FIREWALL", "blocklist").strip().lower() or "blocklist"
        if firewall not in FIREWALLS:
            raise ValueError(f"CYBER_FIREWALL must be one of {FIREWALLS}")
        autoblock = tuple(p.strip() for p in env.get("CYBER_AUTOBLOCK", ",".join(
            cls.autoblock)).split(",") if p.strip())
        bad = [t for t in autoblock if t not in AUTOBLOCKABLE]
        if bad:
            raise ValueError(f"CYBER_AUTOBLOCK has unknown event types {bad}; use {AUTOBLOCKABLE}")
        networks = parse_networks(ALWAYS_PROTECTED + "," + env.get("CYBER_NEVER_BLOCK", ""))
        s = cls(
            eve_path=Path(env.get("EVE_PATH", str(cls.eve_path))),
            eve_from_start=_flag(env, "EVE_FROM_START", False),
            state_file=Path(env.get("BLOCKLIST_FILE", str(cls.state_file))),
            known_devices_file=Path(env.get("KNOWN_DEVICES_FILE", str(cls.known_devices_file))),
            firewall=firewall,
            portscan_min_targets=int(_number(env, "PORTSCAN_MIN_TARGETS", 15, 2, True)),
            portscan_window_s=_number(env, "PORTSCAN_WINDOW_S", 10.0, 1),
            portscan_settle_s=_number(env, "PORTSCAN_SETTLE_S", 2.0, 0),
            portscan_cooldown_s=_number(env, "PORTSCAN_COOLDOWN_S", 60.0, 0),
            brute_min_attempts=int(_number(env, "BRUTE_MIN_ATTEMPTS", 5, 2, True)),
            brute_window_s=_number(env, "BRUTE_WINDOW_S", 60.0, 1),
            brute_settle_s=_number(env, "BRUTE_SETTLE_S", 2.0, 0),
            brute_cooldown_s=_number(env, "BRUTE_COOLDOWN_S", 120.0, 0),
            rogue_cooldown_s=_number(env, "ROGUE_COOLDOWN_S", 300.0, 0),
            rogue_arp=_flag(env, "ROGUE_ARP", False),
            arp_poll_s=_number(env, "ARP_POLL_S", 10.0, 1),
            autoblock=autoblock,
            autoblock_s=_number(env, "CYBER_AUTOBLOCK_S", 600.0, 1),
            block_default_s=_number(env, "BLOCK_DEFAULT_S", 3600.0, 1),
            block_min_s=_number(env, "BLOCK_MIN_S", 30.0, 1),
            block_max_s=_number(env, "BLOCK_MAX_S", 86400.0, 1),
            max_blocks=int(_number(env, "MAX_BLOCKS", 256, 1, True)),
            never_block=networks,
            max_sources=int(_number(env, "CYBER_MAX_SOURCES", 2048, 1, True)),
            max_events_per_min=int(_number(env, "CYBER_MAX_EVENTS_PER_MIN", 60, 1, True)),
        )
        if s.block_min_s > s.block_max_s:
            raise ValueError("BLOCK_MIN_S must be <= BLOCK_MAX_S")
        return s
