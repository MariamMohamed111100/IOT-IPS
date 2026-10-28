"""IPS: execute block commands safely, expire them, persist them, confirm them.

Commands arrive on `system/block` (engine -> cyber, contract section 1) and from the local
auto-block policy. Every value is untrusted: the IP is parsed strictly, loopback/multicast/
link-local/reserved and `never_block` networks are refused, the duration is clamped, and the number
of simultaneous blocks is capped so spoofed scans cannot fill the firewall.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .firewall import Firewall, FirewallError
from .util import IPNetwork, clean_text, finite_number, is_blockable, valid_ip

log = logging.getLogger("cyber.blocks")
MAX_COMMAND_BYTES = 4096
SEEN_IDS = 4096
Emit = Callable[[str, str, dict], object]


def _device(value: object) -> str:
    """A backend device id (lowercase letters, digits, underscore) or "unknown"."""
    return value if isinstance(value, str) and re.fullmatch(r"[a-z0-9_]{1,50}", value) else "unknown"


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class Block:
    ip: str
    reason: str
    blocked_at: float
    expires_at: float
    by: str
    both: bool = False                  # isolation: drop traffic to the address as well
    device_id: str = "unknown"          # backend id of the device the block protects (reports only)


class BlockManager:
    def __init__(self, firewall: Firewall, state_file: Path, emit: Emit, *, default_s: float,
                 min_s: float, max_s: float, max_blocks: int,
                 never_block: tuple[IPNetwork, ...] = (), report_results: bool = False,
                 clock: Callable[[], float] = time.time) -> None:
        self.fw, self.state_file, self.emit, self.clock = firewall, Path(state_file), emit, clock
        self.default_s, self.min_s, self.max_s = default_s, min_s, max_s
        self.max_blocks, self.never_block = max_blocks, never_block
        self.report_results = report_results     # also publish cyber.block_applied / cyber.block_refused
        self.blocks: dict[str, Block] = {}
        self._seen: OrderedDict[str, None] = OrderedDict()

    # ------------------------------------------------------------------ startup
    def restore(self) -> None:
        """Prepare the firewall and re-apply unexpired blocks from the last run."""
        self.fw.setup()
        now = self.clock()
        try:
            doc = json.loads(self.state_file.read_text(encoding="utf-8"))
            entries = doc["blocks"]
        except (OSError, ValueError, KeyError, TypeError):
            entries = []
        for item in entries if isinstance(entries, list) else []:
            try:
                ip = valid_ip(item["ip"])
                expires = finite_number(item["expires_at"])
                if ip is None or expires is None or expires <= now or not self._allowed(ip):
                    continue
                both = item.get("both") is True
                self.fw.block(ip, expires - now, both)
                self.blocks[ip] = Block(ip, clean_text(item.get("reason", "restored"), 64),
                                        float(item.get("blocked_at", now)), expires,
                                        clean_text(item.get("by", "restored"), 32), both,
                                        _device(item.get("device_id")))
            except (KeyError, TypeError, ValueError, AttributeError, FirewallError) as exc:
                log.warning("skipped an unusable saved block: %s", exc)
        if len(self.blocks) > self.max_blocks:
            for ip in sorted(self.blocks, key=lambda i: self.blocks[i].expires_at)[
                    :len(self.blocks) - self.max_blocks]:
                self._drop(ip)
        self._save()
        if self.blocks:
            log.warning("restored %d active block(s)", len(self.blocks))

    # ------------------------------------------------------------------ commands
    def handle_command(self, payload: bytes | str) -> bool:
        """One `system/block` message. Never raises. True if it was (or already is) in effect."""
        raw = payload.encode() if isinstance(payload, str) else bytes(payload)
        if len(raw) > MAX_COMMAND_BYTES:
            log.warning("dropped an oversized block command")
            return False
        try:
            body = json.loads(raw)
        except ValueError:
            log.warning("dropped a block command that is not JSON")
            return False
        if not isinstance(body, dict):
            return False
        cid = body.get("id")
        if cid is not None and not (isinstance(cid, str) and 1 <= len(cid) <= 64):
            log.warning("dropped a block command with an invalid id")
            return False
        if cid in self._seen:                      # QoS 1 may deliver twice
            return True
        action = body.get("action", "block")
        ip = valid_ip(body.get("ip"))
        if action not in ("block", "unblock") or ip is None:
            log.warning("dropped an invalid block command (action=%r)", clean_text(action, 16))
            return False
        if action == "unblock":
            ok = self.unblock(ip, "manual unblock")
        else:
            seconds = finite_number(body.get("window_seconds"))
            reason = clean_text(body.get("reason") or "unspecified", 64)
            direction = body.get("direction", "in")
            if direction not in ("in", "both"):
                log.warning("dropped a block command with an invalid direction")
                return False
            ok = self.block(ip, self.default_s if seconds is None else seconds, reason, "engine",
                            both=direction == "both", device_id=_device(body.get("device_id")),
                            windowed=seconds is not None)
        if ok and cid is not None:                 # only a command that worked is "seen"
            self._seen[cid] = None
            while len(self._seen) > SEEN_IDS:
                self._seen.popitem(last=False)
        return ok

    def block(self, ip: str, seconds: float, reason: str, by: str, *, both: bool = False,
              device_id: str = "unknown", windowed: bool = True) -> bool:
        """Block `ip` (both=True: isolate a device, so nothing reaches it either). Re-checks every safety rule here."""
        addr = valid_ip(ip)
        action = "isolate_device" if both else ("temporary_block" if windowed else "block_source")
        if addr is None:
            log.warning("refused to block %r (not an IP address)", clean_text(ip, 45))
            return False
        why = self._refusal(addr, both)
        if why:
            log.warning("refused to block %s (%s)", addr, why)
            self._result("cyber.block_refused", addr, action, device_id, why)
            return False
        now = self.clock()
        seconds = min(max(seconds, self.min_s), self.max_s)
        expires = now + seconds
        current = self.blocks.get(addr)
        if current is not None:                                   # already blocked: only extend
            # Renew first, extend the recorded expiry only if the kernel accepted it. The backend
            # removes the element before re-adding it, so a failure here means the block is GONE:
            # extending our own state would report a block that no longer exists.
            try:
                self.fw.block(addr, expires - now, current.both or both)
            except FirewallError as exc:
                log.error("could not renew the block of %s: %s", addr, exc)
                self._result("cyber.block_refused", addr, action, device_id, "firewall_error")
                return False
            current.expires_at = max(current.expires_at, expires)
            current.both = current.both or both
            self._save()
            return True
        if len(self.blocks) >= self.max_blocks:
            log.error("refused to block %s: MAX_BLOCKS (%d) reached", addr, self.max_blocks)
            self._result("cyber.block_refused", addr, action, device_id, "max_blocks_reached")
            return False
        try:
            self.fw.block(addr, seconds, both)
        except FirewallError as exc:
            log.error("could not block %s: %s", addr, exc)
            self._result("cyber.block_refused", addr, action, device_id, "firewall_error")
            return False
        self.blocks[addr] = Block(addr, reason, now, expires, by, both, device_id)
        self._save()
        log.warning("%s %s until %s (%s, by %s)", "ISOLATED" if both else "BLOCKED", addr, iso(expires), reason, by)
        self.emit("cyber.ip_blocked", "high", {
            "ip": addr, "reason": reason, "expires_at": iso(expires), "blocked_by": by,
            "window_s": int(seconds)})
        self._result("cyber.block_applied", addr, action, device_id, reason, expires)
        return True

    def _refusal(self, addr: str, both: bool) -> str | None:
        """Why this address must not be blocked, as a code, or None."""
        if not self._allowed(addr):
            return "source_never_block"
        if both and not ipaddress.ip_address(addr).is_private:
            return "device_ip_not_private"          # only a device inside the home is ever isolated
        return None

    def _result(self, type_: str, ip: str, action: str, device_id: str, reason: str,
                expires: float | None = None) -> None:
        """The IPS block result of contract 3.1 (never scored, never re-blocked: it uses `ip`, not `src_ip`)."""
        if not self.report_results:
            return
        data = {"ip": ip, "action": action, "device_id": device_id,
                "reason": re.sub(r"[^a-z0-9]+", "_", reason.lower()).strip("_")[:64] or "unspecified",
                "dry_run": bool(getattr(self.fw, "dry_run", False))}
        if expires is not None:
            data["expires_at"] = iso(expires)
        self.emit(type_, "info", data)

    def unblock(self, ip: str, why: str) -> bool:
        addr = valid_ip(ip)
        if addr is None or addr not in self.blocks:
            return False
        try:
            self.fw.unblock(addr)
        except FirewallError as exc:
            log.error("could not unblock %s (will retry): %s", addr, exc)
            return False
        del self.blocks[addr]
        self._save()
        log.warning("UNBLOCKED %s (%s)", addr, why)
        self.emit("cyber.ip_unblocked", "info", {"ip": addr, "reason": clean_text(why, 64)})
        return True

    def tick(self, now: float | None = None) -> None:
        now = self.clock() if now is None else now
        for ip, blk in list(self.blocks.items()):
            if blk.expires_at <= now:
                self.unblock(ip, "block expired")

    # ------------------------------------------------------------------ internals
    def _allowed(self, ip: str) -> bool:
        if not is_blockable(ip):
            return False
        addr = ipaddress.ip_address(ip)
        return not any(addr in net for net in self.never_block)

    def _drop(self, ip: str) -> None:
        try:
            self.fw.unblock(ip)
        except FirewallError as exc:
            log.warning("could not remove %s: %s", ip, exc)
        self.blocks.pop(ip, None)

    def _save(self) -> None:
        """Atomic write; world-readable on purpose (the demo victim reads it as another user)."""
        doc = {"version": 1, "blocks": [asdict(b) for b in self.blocks.values()]}
        tmp = self.state_file.with_name(self.state_file.name + ".tmp")
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(doc), encoding="utf-8")
            os.chmod(tmp, 0o644)
            os.replace(tmp, self.state_file)
        except OSError as exc:
            log.error("cannot persist the block list to %s: %s", self.state_file, exc)
