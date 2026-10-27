"""
actions.py - simulated response actions for the IoT-IPS

Nothing in this module touches a real firewall, runs a program or opens a
network connection. Every action only appends a record to an action log (JSON
Lines, see ACTION_LOG_FORMAT.md). For the actions that would change the network
the record also holds the exact firewall command that WOULD be run, plus the
command that would undo it, so real blocking can be switched on later.

Actions: monitor, log, create_incident, notify_admin (bookkeeping only) and
temporary_block, block_source, isolate_device (network actions).

Security rules enforced here, even if policy.py or the decision was tampered with:
  * only actions from the fixed catalog are accepted;
  * addresses are parsed with `ipaddress`; nothing free-form reaches a command;
  * the allow-list and the "never block" addresses are checked again;
  * the number of active blocks is capped (a flood of spoofed sources cannot
    fill the firewall) and temporary blocks expire;
  * the log is written as one JSON object per line (no log injection), with
    owner-only permissions and size-based rotation;
  * commands are built as argument lists (never shell strings); the printable
    form is only for the log. A future real executor must pass the argument
    list to subprocess without a shell.
"""

from __future__ import annotations

import collections
import ipaddress
import json
import os
import re
import shlex
import threading
import time
from collections.abc import Mapping
from typing import Any, Callable, Dict, List, Optional, Sequence

__all__ = [
    "ACTION_NAMES", "BOOKKEEPING_ACTIONS", "NETWORK_ACTIONS", "SKIP_CODES",
    "ActionExecutor", "build_commands", "format_command", "parse_ip",
    "is_never_block", "is_allow_listed", "undo_argv",
]

BOOKKEEPING_ACTIONS = ("monitor", "log", "create_incident", "notify_admin")
NETWORK_ACTIONS = ("temporary_block", "block_source", "isolate_device")
ACTION_NAMES = BOOKKEEPING_ACTIONS + NETWORK_ACTIONS

# Reasons an action was left out (used in decisions and in the log).
SKIP_CODES = (
    "source_allow_listed", "source_never_block", "source_is_device", "no_valid_source",
    "no_valid_device_ip", "device_ip_not_private", "device_allow_listed",
)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$")
_RULE_RE = re.compile(r"^[a-z0-9_]{1,40}$")
_LEVELS = ("Low", "Medium", "High", "Critical")
_MAX_ACTIONS = 16
_MAX_IP_STR = 64
_COMMENT_PERMANENT = "iot-ips"
_COMMENT_TEMPORARY = "iot-ips-temp"


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------

def parse_ip(value: Any):
    """IPv4/IPv6 address object from a short string, else None.
    IPv4-mapped IPv6 (::ffff:1.2.3.4) is converted to plain IPv4."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > _MAX_IP_STR:
        return None
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip


def is_never_block(ip) -> bool:
    """Addresses that must never be blocked, whatever any config says."""
    return bool(ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_reserved)


def is_allow_listed(ip, networks) -> bool:
    return any(ip in net for net in networks)


# ---------------------------------------------------------------------------
# Firewall commands (built, logged, never executed)
# ---------------------------------------------------------------------------

def _tool(ip) -> str:
    return "iptables" if ip.version == 4 else "ip6tables"


def build_commands(action: str, src_ip=None, device_ip=None) -> List[List[str]]:
    """Argument lists of the firewall commands an action would run.

    `src_ip` / `device_ip` must be ipaddress objects (or None). Bookkeeping
    actions, and anything with a missing address, give an empty list.
    """
    if action in ("block_source", "temporary_block") and src_ip is not None:
        comment = _COMMENT_TEMPORARY if action == "temporary_block" else _COMMENT_PERMANENT
        return [[_tool(src_ip), "-I", "FORWARD", "-s", str(src_ip),
                 "-m", "comment", "--comment", comment, "-j", "DROP"]]
    if action == "isolate_device" and device_ip is not None:
        tool = _tool(device_ip)
        return [
            [tool, "-I", "FORWARD", "-s", str(device_ip), "-m", "comment", "--comment", _COMMENT_PERMANENT, "-j", "DROP"],
            [tool, "-I", "FORWARD", "-d", str(device_ip), "-m", "comment", "--comment", _COMMENT_PERMANENT, "-j", "DROP"],
        ]
    return []


def undo_argv(argv: Sequence[str]) -> List[str]:
    """The command that removes a rule added by build_commands()."""
    return ["-D" if part == "-I" else part for part in argv]


def format_command(argv: Sequence[str]) -> str:
    """Printable, shell-quoted form of an argument list (for logs only)."""
    return shlex.join(list(argv))


# ---------------------------------------------------------------------------
# The simulated executor
# ---------------------------------------------------------------------------

class ActionExecutor:
    """Runs decisions in dry-run mode and writes the action log.

    log_path=None keeps the records in memory only (tests, demos).
    """

    def __init__(self, log_path: Optional[str] = None, allow_list=(), dry_run: bool = True,
                 temporary_block_seconds: int = 600, max_active_blocks: int = 256,
                 max_log_bytes: int = 10 * 1024 * 1024, clock: Callable[[], float] = time.time):
        if dry_run is not True:
            raise ValueError("real execution is not implemented: this version only simulates actions (dry_run=True)")
        if not isinstance(temporary_block_seconds, int) or isinstance(temporary_block_seconds, bool) \
                or not 1 <= temporary_block_seconds <= 86400:
            raise ValueError("temporary_block_seconds must be an integer from 1 to 86400")
        if not isinstance(max_active_blocks, int) or isinstance(max_active_blocks, bool) or not 1 <= max_active_blocks <= 100000:
            raise ValueError("max_active_blocks must be an integer from 1 to 100000")
        if not isinstance(max_log_bytes, int) or isinstance(max_log_bytes, bool) or max_log_bytes < 1024:
            raise ValueError("max_log_bytes must be an integer of at least 1024")
        self.dry_run = True
        self._allow = tuple(allow_list)
        self._ttl = temporary_block_seconds
        self._max_blocks = max_active_blocks
        self._max_log_bytes = max_log_bytes
        self._clock = clock
        self._log_path = None if log_path is None else os.fspath(log_path)
        self._lock = threading.Lock()
        self._seq = 0
        self._blocks: Dict[str, Optional[float]] = {}   # source ip -> expiry time (None = permanent)
        self._isolated: Dict[str, bool] = {}            # device ip -> True
        self.records = collections.deque(maxlen=10000)
        self.log_errors = 0

    @classmethod
    def from_policy(cls, policy: dict, log_path: Optional[str] = None,
                    clock: Callable[[], float] = time.time) -> "ActionExecutor":
        """Build an executor from a validated policy (policy.load_policy())."""
        limits = policy["limits"]
        return cls(log_path=log_path, allow_list=policy["allow_networks"], dry_run=policy["dry_run"],
                   temporary_block_seconds=limits["temporary_block_seconds"],
                   max_active_blocks=limits["max_active_blocks"],
                   max_log_bytes=limits["max_log_bytes"], clock=clock)

    # -- state ---------------------------------------------------------------
    def active_blocks(self) -> Dict[str, Optional[float]]:
        with self._lock:
            return dict(self._blocks)

    def isolated_devices(self) -> List[str]:
        with self._lock:
            return sorted(self._isolated)

    # -- main entry ----------------------------------------------------------
    def run(self, decision: Any) -> List[dict]:
        """Simulate every action of `decision`; return the log records written."""
        with self._lock:
            out: List[dict] = []
            now = self._clock()
            self._expire(now, out)

            if not isinstance(decision, Mapping):
                out.append(self._emit(now, "none", "refused", "invalid_decision"))
                return out

            device_id = self._safe_id(decision.get("targets"), "device_id", _ID_RE, "unknown-device")
            ctx = {
                "device_id": device_id,
                "rule_id": self._safe_text(decision.get("rule_id"), _RULE_RE, "unknown_rule"),
                "level": decision.get("level") if decision.get("level") in _LEVELS else None,
            }
            targets = decision.get("targets") if isinstance(decision.get("targets"), Mapping) else {}
            src = parse_ip(targets.get("src_ip"))
            dev_ip = parse_ip(targets.get("device_ip"))

            raw_actions = decision.get("action")
            if isinstance(raw_actions, str):
                raw_actions = [raw_actions]
            if not isinstance(raw_actions, (list, tuple)):
                raw_actions = []
            seen = set()
            for name in list(raw_actions)[:_MAX_ACTIONS]:
                if not isinstance(name, str) or name not in ACTION_NAMES:
                    out.append(self._emit(now, "none", "refused", "unknown_action", **ctx))
                    continue
                if name in seen:
                    continue
                seen.add(name)
                out.extend(self._do(now, name, src, dev_ip, ctx))

            skipped = decision.get("skipped")
            if isinstance(skipped, (list, tuple)):
                for item in list(skipped)[:_MAX_ACTIONS]:
                    if isinstance(item, Mapping) and item.get("action") in ACTION_NAMES and item.get("why") in SKIP_CODES:
                        out.append(self._emit(now, item["action"], "skipped", item["why"], **ctx))
            return out

    # -- one action ----------------------------------------------------------
    def _do(self, now: float, name: str, src, dev_ip, ctx: dict) -> List[dict]:
        if name in BOOKKEEPING_ACTIONS:
            return [self._emit(now, name, "simulated", "ok", **ctx)]
        if name == "isolate_device":
            return [self._isolate(now, dev_ip, ctx)]
        return [self._block(now, name, src, dev_ip, ctx)]

    def _block(self, now: float, name: str, src, dev_ip, ctx: dict) -> dict:
        if src is None:
            return self._emit(now, name, "skipped", "no_valid_source", **ctx)
        if is_never_block(src):
            return self._emit(now, name, "skipped", "source_never_block", target=str(src), **ctx)
        if is_allow_listed(src, self._allow):
            return self._emit(now, name, "skipped", "source_allow_listed", target=str(src), **ctx)
        if dev_ip is not None and src == dev_ip:
            return self._emit(now, name, "skipped", "source_is_device", target=str(src), **ctx)

        key = str(src)
        temporary = name == "temporary_block"
        existing = key in self._blocks
        if existing:
            current = self._blocks[key]
            if temporary or current is None:
                return self._emit(now, name, "skipped", "already_blocked", target=key, **ctx)
            # a permanent block replaces a temporary one
            self._blocks[key] = None
            note = "upgraded_to_permanent"
        else:
            if len(self._blocks) + len(self._isolated) >= self._max_blocks:
                return self._emit(now, name, "refused", "block_budget_exhausted", target=key, **ctx)
            self._blocks[key] = now + self._ttl if temporary else None
            note = "ok"
        argvs = build_commands(name, src_ip=src)
        return self._emit(now, name, "simulated", note, target=key, argvs=argvs,
                          expires_in_s=self._ttl if temporary else None, **ctx)

    def _isolate(self, now: float, dev_ip, ctx: dict) -> dict:
        if dev_ip is None:
            return self._emit(now, "isolate_device", "skipped", "no_valid_device_ip", **ctx)
        if not dev_ip.is_private or is_never_block(dev_ip):
            return self._emit(now, "isolate_device", "skipped", "device_ip_not_private", target=str(dev_ip), **ctx)
        if is_allow_listed(dev_ip, self._allow):
            return self._emit(now, "isolate_device", "skipped", "device_allow_listed", target=str(dev_ip), **ctx)
        key = str(dev_ip)
        if key in self._isolated:
            return self._emit(now, "isolate_device", "skipped", "already_blocked", target=key, **ctx)
        if len(self._blocks) + len(self._isolated) >= self._max_blocks:
            return self._emit(now, "isolate_device", "refused", "block_budget_exhausted", target=key, **ctx)
        self._isolated[key] = True
        return self._emit(now, "isolate_device", "simulated", "ok", target=key,
                          argvs=build_commands("isolate_device", device_ip=dev_ip), **ctx)

    def _expire(self, now: float, out: List[dict]) -> None:
        for key, expiry in list(self._blocks.items()):
            if expiry is not None and expiry <= now:
                del self._blocks[key]
                ip = parse_ip(key)
                argvs = build_commands("temporary_block", src_ip=ip) if ip is not None else []
                out.append(self._emit(now, "temporary_block", "simulated", "expired", target=key,
                                      argvs=argvs, undo_only=True))

    # -- log records ---------------------------------------------------------
    @staticmethod
    def _safe_text(value: Any, pattern, fallback: str) -> str:
        return value if isinstance(value, str) and pattern.fullmatch(value) else fallback

    @classmethod
    def _safe_id(cls, mapping: Any, key: str, pattern, fallback: str) -> str:
        return cls._safe_text(mapping.get(key) if isinstance(mapping, Mapping) else None, pattern, fallback)

    def _emit(self, now: float, action: str, status: str, note: str, device_id: str = "unknown-device",
              rule_id: str = "unknown_rule", level: Optional[str] = None, target: Optional[str] = None,
              argvs: Optional[List[List[str]]] = None, expires_in_s: Optional[int] = None,
              undo_only: bool = False) -> dict:
        self._seq += 1
        argvs = argvs or []
        if undo_only:   # an expired temporary block: only the undo command is relevant
            commands: List[str] = []
            undo = [format_command(undo_argv(a)) for a in argvs]
        else:
            commands = [format_command(a) for a in argvs]
            undo = [format_command(undo_argv(a)) for a in argvs]
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "seq": self._seq,
            "action": action,
            "status": status,
            "note": note,
            "dry_run": True,
            "device_id": device_id,
            "rule_id": rule_id,
            "level": level,
            "target": target,
            "commands": commands,
            "undo": undo,
            "expires_in_s": expires_in_s,
        }
        self.records.append(record)
        self._write(record)
        return record

    def _write(self, record: dict) -> None:
        if self._log_path is None:
            return
        line = (json.dumps(record, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode("ascii")
        try:
            if os.path.islink(self._log_path):
                # O_NOFOLLOW is not available on every platform (Windows), so refuse explicitly too.
                raise OSError("refusing to write to a symbolic link")
            try:
                if os.path.getsize(self._log_path) >= self._max_log_bytes:
                    os.replace(self._log_path, self._log_path + ".1")
            except FileNotFoundError:
                pass
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(self._log_path, flags, 0o600)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)
        except OSError:
            self.log_errors += 1   # never crash the pipeline because the log is unwritable
