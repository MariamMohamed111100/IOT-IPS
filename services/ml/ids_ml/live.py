"""Live windows: 10-packet feature rows that name a device and a remote address, so the model can raise alerts.

`extractor.extract` gives feature rows without addresses (the dataset has none). The pipeline needs to know WHO
(source) attacked WHICH device, so here each window of 10 consecutive packets is tied to the device it mostly
talks to and to the other end of that talk. The 16 model features are computed exactly as in `extractor.py`.

    buffer = WindowBuffer(devices)
    for event in buffer.feed(packets):      # packets: extractor.Packet objects; a part-window waits for the next call
        ...                                 # event = features + device_id, timestamp, src_ip, dst_ip, dst_port, protocol, direction, event_ref

A window is skipped when fewer than `min_device_packets` of its packets involve a known device (traffic between
other hosts is not ours to judge), when it lasts 0 seconds (Rate would be infinite) or when no IP protocol fits the contract.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from itertools import pairwise

from .extractor import Packet, window_row

WINDOW = 10
PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP", 47: "GRE"}      # IP protocol number -> contract name


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds")


def window_event(win: list[Packet], gaps: list[float], by_ip: dict, min_device_packets: int = 6) -> dict | None:
    """One feature row plus addresses for one full window, or None when the window is not about a device."""
    if len(win) < 2 or win[-1].ts - win[0].ts <= 0:
        return None
    touching = Counter()
    for p in win:
        for ip in (p.src, p.dst):
            if ip in by_ip:
                touching[ip] += 1
    if not touching:
        return None
    device_ip, n = max(sorted(touching.items()), key=lambda kv: kv[1])
    if n < min_device_packets:
        return None
    mine = [p for p in win if device_ip in (p.src, p.dst)]
    others = Counter(p.dst if p.src == device_ip else p.src for p in mine)
    remote = max(sorted(others.items()), key=lambda kv: kv[1])[0]
    if remote is None or remote == device_ip:
        return None
    first = next(p for p in mine if remote in (p.src, p.dst))
    inbound = first.src == remote                  # whoever speaks first started the conversation
    src, dst = (remote, device_ip) if inbound else (device_ip, remote)
    sent = [p for p in mine if p.src == src]
    dport = Counter(p.dport for p in sent if p.dport).most_common(1)
    proto = Counter(p.proto for p in sent).most_common(1)[0][0] if sent else 0
    if proto not in PROTOCOLS:
        return None
    ts = win[-1].ts
    event = window_row(win, gaps)
    event.update({
        "device_id": by_ip[device_ip]["device_id"], "timestamp": _iso(ts), "src_ip": src, "dst_ip": dst,
        "dst_port": dport[0][0] if dport else 0, "protocol": PROTOCOLS[proto],
        "direction": "inbound" if inbound else "outbound",
        "event_ref": "win:%d:%s:%s" % (int(ts * 1000), by_ip[device_ip]["device_id"], src),
    })
    return event


class WindowBuffer:
    """Cuts a stream of packets into windows of 10; the packets of a part-window wait for the next `feed`."""

    def __init__(self, devices, window: int = WINDOW, min_device_packets: int = 6, max_wait: int = 1000) -> None:
        self.by_ip = {str(d["ip"]): d for d in devices if d.get("ip") and d.get("device_id")}
        self.window, self.min_device_packets = window, min_device_packets
        self.max_wait = max_wait
        self._rest: list[Packet] = []
        self._last_ts: float | None = None

    def feed(self, packets: list[Packet]) -> list[dict]:
        pkts = self._rest + list(packets)
        events = []
        full = len(pkts) - len(pkts) % self.window
        for i in range(0, full, self.window):
            win = pkts[i:i + self.window]
            before = self._last_ts if self._last_ts is not None else win[0].ts
            gaps = [win[0].ts - before] + [b.ts - a.ts for a, b in pairwise(win)]
            self._last_ts = win[-1].ts
            e = window_event(win, gaps, self.by_ip, self.min_device_packets)
            if e is not None:
                events.append(e)
        self._rest = pkts[full:][-self.max_wait:]
        return events
