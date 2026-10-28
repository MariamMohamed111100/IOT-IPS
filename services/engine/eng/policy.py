"""config/risk_scores.yaml is the single source of truth for every number the engine uses.

Change scores, levels, correlation bonuses and response lists THERE, not in code. A typo fails
loudly at start-up (and in CI through scripts/validate_contract.py) instead of silently scoring 0.
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

LEVELS = ("low", "medium", "high", "critical")
EVENT_TYPE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
# Every action name the engine knows how to run. A typo in the YAML must not pass silently.
KNOWN_ACTIONS = frozenset(
    {"log", "notify", "lights_on", "siren", "block_ip", "unlock_doors", "close_valve"})

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

# Ranges that are never a legitimate attack source, so the engine must not order a firewall
# drop for them even if a (trivially spoofable) packet header names them. 203.0.113.0/24 and the
# other TEST-NET blocks are deliberately NOT here: the test suite uses them as stand-in
# "external attackers" and blocking a documentation address is harmless.
_NEVER_BLOCK_NETS: tuple[Network, ...] = tuple(
    ipaddress.ip_network(net) for net in (
        "0.0.0.0/8",                # "this network" - only 0.0.0.0 is is_unspecified
        "100.64.0.0/10",            # carrier-grade NAT / ISP infrastructure
        "192.0.0.0/24",             # IETF protocol assignments
        "198.18.0.0/15",            # benchmarking
        "240.0.0.0/4",              # reserved for future use (class E)
        "::/128", "64:ff9b::/96", "2002::/16", "fc00::/7", "ff00::/8",
    )
)


@dataclass(frozen=True)
class Correlation:
    name: str
    requires: tuple[str, ...]
    bonus: int
    within_s: float


@dataclass(frozen=True)
class Policy:
    window_s: float
    repeat_cap: int
    max_score: int
    points: dict[str, int]
    levels: dict[str, int]                       # inclusive lower bound of each level
    responses: dict[str, tuple[str, ...]]
    event_actions: dict[str, tuple[str, ...]]
    life_safety: frozenset[str]                  # events after which doors must be unlockable
    correlations: tuple[Correlation, ...]
    block_window_s: int
    never_block: tuple[Network, ...] = field(default_factory=tuple)

    def level_for(self, score: int) -> str:
        level = "low"
        for name in LEVELS:
            if score >= self.levels[name]:
                level = name
        return level

    @staticmethod
    def rank(level: str) -> int:
        return LEVELS.index(level)


def _networks(values: Any) -> tuple[Network, ...]:
    out: list[Network] = []
    for value in values or []:
        out.append(ipaddress.ip_network(str(value).strip(), strict=False))
    return tuple(out)


def _actions(table: Any, where: str) -> tuple[str, ...]:
    names = tuple(table or ())
    unknown = [n for n in names if n not in KNOWN_ACTIONS]
    if unknown:
        raise ValueError(f"{where}: unknown action(s) {unknown}; known: {sorted(KNOWN_ACTIONS)}")
    return names


def parse_policy(raw: dict[str, Any], extra_never_block: str = "") -> Policy:
    levels = {k: int(v) for k, v in raw["levels"].items()}
    if list(levels) != list(LEVELS):
        raise ValueError("levels must be exactly low, medium, high, critical (in this order)")
    if list(levels.values()) != sorted(levels.values()):
        raise ValueError("level thresholds must ascend")

    points = {str(k): int(v) for k, v in raw["events"].items()}
    for event_type in points:
        if not EVENT_TYPE.match(event_type):
            raise ValueError(f"events: {event_type!r} is not a <domain>.<name> event type")

    if set(raw["responses"]) != set(LEVELS):
        raise ValueError("responses needs one list per level")
    responses = {lvl: _actions(raw["responses"][lvl], f"responses.{lvl}") for lvl in LEVELS}

    event_actions = {t: _actions(a, f"event_actions.{t}")
                     for t, a in (raw.get("event_actions") or {}).items()}

    correlations = []
    for rule in raw.get("correlations") or []:
        requires = tuple(rule["requires"])
        unknown = [t for t in requires if t not in points]
        if len(requires) < 2 or unknown:
            raise ValueError(f"correlation {rule.get('name')!r}: needs 2+ scored event types "
                             f"(unknown: {unknown})")
        correlations.append(Correlation(
            name=str(rule["name"]), requires=requires, bonus=int(rule["bonus"]),
            within_s=float(rule.get("within_minutes", 5)) * 60))

    never = _networks(raw.get("never_block")) + _networks(
        [p for p in extra_never_block.split(",") if p.strip()])
    return Policy(
        window_s=float(raw["decay_minutes"]) * 60,
        repeat_cap=int(raw.get("repeat_cap", 3)),
        max_score=int(raw.get("max_score", 100)),
        points=points, levels=levels, responses=responses, event_actions=event_actions,
        life_safety=frozenset(raw.get("life_safety_events") or ()),
        correlations=tuple(correlations),
        block_window_s=int(float(raw.get("block_minutes", 60)) * 60),
        never_block=never,
    )


def load_policy(path: str | Path | None = None) -> Policy:
    path = Path(path or os.getenv("RISK_SCORES_FILE", "/config/risk_scores.yaml"))
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return parse_policy(raw, os.getenv("ENGINE_NEVER_BLOCK", ""))


def attacker_ip(value: Any, never_block: tuple[Network, ...] = (),
                protected: frozenset[str] | set[str] = frozenset()) -> str | None:
    """A source address that is safe to hand to the firewall, or None.

    The value comes from an MQTT message (packet metadata, so the sender chooses it), which is
    why everything here is a refusal by default:

    * parsed strictly, never passed through as text;
    * loopback / multicast / link-local / reserved / special-purpose ranges refused;
    * ``never_block`` (the operator's infrastructure list) refused;
    * ``protected`` - our own devices - refused, so a spoofed header can never turn the IPS
      against the camera or the lock it is supposed to defend.

    LAN addresses are otherwise allowed on purpose: a rogue or compromised device is usually
    inside the home network.
    """
    if not isinstance(value, str) or "%" in value or len(value) > 45:
        return None
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    # ::ffff:192.168.1.50 is the same address as 192.168.1.50: collapse it before every check,
    # otherwise an IPv4-mapped form would side-step the protected/never-block lists.
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if (addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local
            or addr.is_reserved):
        return None
    text = str(addr)
    if text in protected:
        return None
    if any(addr in net for net in _NEVER_BLOCK_NETS):
        return None
    if any(addr in net for net in never_block):
        return None
    return text
