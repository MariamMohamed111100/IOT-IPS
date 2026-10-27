"""Turn raw sightings (one packet alert, one DHCP lease) into at most ONE event per incident.

The engine counts every event, so a scan that made 400 Suricata alerts must reach it as a single
`cyber.port_scan` (25 points), not 400. Each detector therefore aggregates, then stays quiet for a
cooldown. All of them take `now` as an argument (tests need no real clock) and all state is
bounded: a spoofed-source flood cannot grow memory without limit.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .allowlist import Allowlist
from .util import clean_text, valid_ip, valid_mac

MAX_TARGETS_PER_SOURCE = 2048       # distinct (host, port) pairs remembered per scanning source
MAX_REPORTED_PORTS = 50
MAX_ATTEMPTS_KEPT = 1000


@dataclass
class Detection:
    type: str                        # contract event type, e.g. "cyber.port_scan"
    severity: str                    # advisory severity_hint (only the engine scores)
    data: dict = field(default_factory=dict)


class _Cooldown:
    """Bounded `key -> quiet until` map."""

    def __init__(self, seconds: float, max_keys: int) -> None:
        self.seconds, self.max_keys = seconds, max_keys
        self._until: dict = {}

    def active(self, key: object, now: float) -> bool:
        until = self._until.get(key)
        return until is not None and now < until

    def start(self, key: object, now: float) -> None:
        if len(self._until) >= self.max_keys:
            self._until = {k: u for k, u in self._until.items() if u > now}
            if len(self._until) >= self.max_keys:
                self._until.pop(min(self._until, key=self._until.__getitem__))
        self._until[key] = now + self.seconds


class _Scan:
    __slots__ = ("targets", "armed_at", "pruned_at", "last_seen")

    def __init__(self, now: float) -> None:
        self.targets: dict[tuple[str, int], float] = {}
        self.armed_at: float | None = None
        self.pruned_at = self.last_seen = now


class PortScanDetector:
    """A source probing many distinct (host, port) pairs inside a short window."""

    def __init__(self, min_targets: int, window_s: float, settle_s: float, cooldown_s: float,
                 max_sources: int = 2048) -> None:
        self.min_targets, self.window_s, self.settle_s = min_targets, window_s, settle_s
        self.max_sources = max_sources
        self._scans: dict[str, _Scan] = {}
        self._cool = _Cooldown(cooldown_s, max_sources)

    def observe(self, src: str, dst: str, port: int, now: float) -> None:
        if self._cool.active(src, now):
            return
        scan = self._scans.get(src)
        if scan is None:
            if len(self._scans) >= self.max_sources:
                self._scans.pop(next(iter(self._scans)))          # oldest source out
            scan = self._scans[src] = _Scan(now)
        scan.last_seen = now
        key = (dst, port)
        if key in scan.targets or len(scan.targets) < MAX_TARGETS_PER_SOURCE:
            scan.targets[key] = now
        if scan.armed_at is not None:
            return
        if now - scan.pruned_at >= 1.0:       # not on every packet: scans alert thousands of times
            scan.pruned_at = now
            scan.targets = {k: t for k, t in scan.targets.items() if now - t <= self.window_s}
        if len(scan.targets) >= self.min_targets:
            scan.armed_at = now

    def flush(self, now: float) -> list[Detection]:
        out: list[Detection] = []
        for src, scan in list(self._scans.items()):
            if scan.armed_at is None:
                if now - scan.last_seen > self.window_s:
                    del self._scans[src]                           # went quiet: free the memory
                continue
            if now - scan.armed_at < self.settle_s:
                continue
            del self._scans[src]
            self._cool.start(src, now)
            out.append(self._detection(src, scan))
        return out

    def _detection(self, src: str, scan: _Scan) -> Detection:
        per_host: dict[str, set[int]] = {}
        for host, port in scan.targets:
            per_host.setdefault(host, set()).add(port)
        main = max(per_host, key=lambda h: (len(per_host[h]), h))
        ports = sorted({p for _, p in scan.targets})
        return Detection("cyber.port_scan", "medium", {
            "src_ip": src, "dst_ip": main, "ports": ports[:MAX_REPORTED_PORTS],
            "port_count": len(ports), "hosts_probed": len(per_host),
            "window_s": self.window_s})


class _Attempts:
    __slots__ = ("times", "armed_at")

    def __init__(self) -> None:
        self.times: deque[float] = deque(maxlen=MAX_ATTEMPTS_KEPT)
        self.armed_at: float | None = None


class BruteForceDetector:
    """Many login attempts from one source against one service inside a window."""

    def __init__(self, min_attempts: int, window_s: float, settle_s: float, cooldown_s: float,
                 max_sources: int = 2048) -> None:
        self.min_attempts, self.window_s, self.settle_s = min_attempts, window_s, settle_s
        self.max_sources = max_sources
        self._tries: dict[tuple, _Attempts] = {}
        self._cool = _Cooldown(cooldown_s, max_sources)

    def observe(self, src: str, dst: str, port: int, protocol: str, now: float) -> None:
        key = (src, dst, port, protocol)
        if self._cool.active(key, now):
            return
        tries = self._tries.get(key)
        if tries is None:
            if len(self._tries) >= self.max_sources:
                self._tries.pop(next(iter(self._tries)))
            tries = self._tries[key] = _Attempts()
        tries.times.append(now)
        if tries.armed_at is None:
            while tries.times and now - tries.times[0] > self.window_s:
                tries.times.popleft()
            if len(tries.times) >= self.min_attempts:
                tries.armed_at = now

    def flush(self, now: float) -> list[Detection]:
        out: list[Detection] = []
        for key, tries in list(self._tries.items()):
            if tries.armed_at is None:
                if not tries.times or now - tries.times[-1] > self.window_s:
                    del self._tries[key]
                continue
            if now - tries.armed_at < self.settle_s:
                continue
            del self._tries[key]
            self._cool.start(key, now)
            src, dst, port, protocol = key
            out.append(Detection("cyber.brute_force", "high", {
                "src_ip": src, "dst_ip": dst, "target": f"{dst}:{port}", "protocol": protocol,
                "attempts": len(tries.times), "window_s": self.window_s}))
        return out


class RogueDeviceDetector:
    """A MAC address that asks for a lease (or shows up in ARP) but is not on the allowlist."""

    def __init__(self, allowlist: Allowlist, cooldown_s: float, max_macs: int = 1024) -> None:
        self.allowlist = allowlist
        self._cool = _Cooldown(cooldown_s, max_macs)

    def observe(self, mac: object, ip: object, via: str, hostname: object,
                now: float) -> Detection | None:
        if not self.allowlist.enabled:
            return None
        mac = valid_mac(mac)
        if mac is None or self.allowlist.known(mac) or self._cool.active(mac, now):
            return None
        self._cool.start(mac, now)
        addr = valid_ip(ip)
        has_lease = addr not in (None, "0.0.0.0")
        data = {"mac": mac, "ip": addr if has_lease else "0.0.0.0", "seen_via": via}
        if hostname:
            data["hostname"] = clean_text(hostname, 63)
        if has_lease:
            data["src_ip"] = addr        # lets the engine/IPS block a device that has a lease
        return Detection("cyber.rogue_device", "medium", data)
