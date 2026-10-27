"""Wires Suricata records, detectors, the block manager and the event sink together."""
from __future__ import annotations

import logging
import threading
import time
from collections import Counter, deque
from collections.abc import Callable
from typing import Protocol

from smartsecure_common import Event, make_event

from .allowlist import Allowlist
from .arp import read_arp
from .blocks import BlockManager
from .config import SID_HTTP_LOGIN, SID_PORT_SCAN, SID_SSH_CONNECT, ZONE, Settings
from .detectors import BruteForceDetector, Detection, PortScanDetector, RogueDeviceDetector
from .eve import EveTailer
from .firewall import Firewall, make_firewall
from .util import valid_ip, valid_port

log = logging.getLogger("cyber")
SOURCE = "cyber"


class EventSink(Protocol):
    def publish(self, event: Event) -> None: ...


class CyberService:
    def __init__(self, settings: Settings, sink: EventSink,
                 clock: Callable[[], float] = time.time, firewall: Firewall | None = None,
                 allowlist: Allowlist | None = None,
                 arp_reader: Callable[[], list[tuple[str, str]]] = read_arp) -> None:
        s = self.s = settings
        self.sink, self.clock, self.arp_reader = sink, clock, arp_reader
        self.lock = threading.RLock()
        self.allowlist = allowlist or Allowlist(s.known_devices_file)
        self.scan = PortScanDetector(s.portscan_min_targets, s.portscan_window_s,
                                     s.portscan_settle_s, s.portscan_cooldown_s, s.max_sources)
        self.brute = BruteForceDetector(s.brute_min_attempts, s.brute_window_s,
                                        s.brute_settle_s, s.brute_cooldown_s, s.max_sources)
        self.rogue = RogueDeviceDetector(self.allowlist, s.rogue_cooldown_s)
        self.blocks = BlockManager(
            firewall or make_firewall(s.firewall), s.state_file, self._emit,
            default_s=s.block_default_s, min_s=s.block_min_s, max_s=s.block_max_s,
            max_blocks=s.max_blocks, never_block=s.never_block, clock=clock)
        self.tailer = EveTailer(s.eve_path, s.eve_from_start)
        self.stats: Counter = Counter()
        self._sent: deque[float] = deque()
        self._last_drop_log = float("-inf")
        self._last_arp = float("-inf")

    # ------------------------------------------------------------------ input
    def restore(self) -> None:
        with self.lock:
            self.blocks.restore()

    def process_record(self, rec: dict, now: float | None = None) -> None:
        """One eve.json record. Never raises: a bad record is dropped."""
        now = self.clock() if now is None else now
        try:
            with self.lock:
                kind = rec.get("event_type")
                if kind == "alert":
                    self._on_alert(rec, now)
                elif kind == "dhcp":
                    self._on_dhcp(rec, now)
        except Exception:
            log.exception("could not process an eve record")

    def _on_alert(self, rec: dict, now: float) -> None:
        alert = rec.get("alert")
        sid = alert.get("signature_id") if isinstance(alert, dict) else None
        src, dst, port = valid_ip(rec.get("src_ip")), valid_ip(rec.get("dest_ip")), \
            valid_port(rec.get("dest_port"))
        if src is None or dst is None or port is None:
            return
        if sid == SID_PORT_SCAN:
            self.scan.observe(src, dst, port, now)
        elif sid == SID_HTTP_LOGIN:
            self.brute.observe(src, dst, port, "http", now)
        elif sid == SID_SSH_CONNECT:
            self.brute.observe(src, dst, port, "ssh", now)

    def _on_dhcp(self, rec: dict, now: float) -> None:
        dhcp = rec.get("dhcp")
        if not isinstance(dhcp, dict):
            return
        ip = dhcp.get("assigned_ip") or dhcp.get("client_ip")
        det = self.rogue.observe(dhcp.get("client_mac"), ip, "dhcp", dhcp.get("hostname"), now)
        if det:
            self._detected(det)

    def handle_block(self, payload: bytes | str) -> bool:
        """A `system/block` message from the engine."""
        with self.lock:
            return self.blocks.handle_command(payload)

    # ------------------------------------------------------------------ time
    def tick(self, now: float | None = None) -> None:
        now = self.clock() if now is None else now
        with self.lock:
            for det in self.scan.flush(now) + self.brute.flush(now):
                self._detected(det)
            self.blocks.tick(now)
            self.allowlist.refresh()
            if self.s.rogue_arp and now - self._last_arp >= self.s.arp_poll_s:
                self._last_arp = now
                for ip, mac in self.arp_reader():
                    det = self.rogue.observe(mac, ip, "arp", None, now)
                    if det:
                        self._detected(det)

    # ------------------------------------------------------------------ output
    def _detected(self, det: Detection) -> None:
        self.stats[det.type] += 1
        self._emit(det.type, det.severity, det.data)
        ip = det.data.get("src_ip")
        if det.type in self.s.autoblock and ip:
            self.blocks.block(ip, self.s.autoblock_s, det.type, "cyber")

    def _emit(self, type_: str, severity: str, data: dict) -> bool:
        """Publish one event, unless we are over the hard per-minute cap."""
        now = self.clock()
        while self._sent and self._sent[0] <= now - 60:
            self._sent.popleft()
        if len(self._sent) >= self.s.max_events_per_min:
            self.stats["dropped"] += 1
            if now - self._last_drop_log >= 60:
                self._last_drop_log = now
                log.error("event rate cap (%d/min) reached: dropping %s",
                          self.s.max_events_per_min, type_)
            return False
        self._sent.append(now)
        try:
            self.sink.publish(make_event(SOURCE, type_, ZONE, severity, **data))
        except Exception:
            log.exception("could not publish %s", type_)
            return False
        return True

    # ------------------------------------------------------------------ threads
    def start(self, stop: threading.Event) -> list[threading.Thread]:
        """Reader (eve.json) and ticker (flush, expiry) threads; both stop on `stop`."""
        def read() -> None:
            while not stop.is_set():
                try:
                    for rec in self.tailer.poll():
                        self.process_record(rec)
                except Exception:
                    log.exception("eve reader failed")
                stop.wait(0.25)

        def ticker() -> None:
            while not stop.is_set():
                try:
                    self.tick()
                except Exception:
                    log.exception("tick failed")
                stop.wait(1.0)

        threads = [threading.Thread(target=read, name="eve-reader", daemon=True),
                   threading.Thread(target=ticker, name="ticker", daemon=True)]
        for t in threads:
            t.start()
        return threads
