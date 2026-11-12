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


def window_event(win: list[Packet], gaps: list[float], by_ip: dict, min_device_packets: int = 6,
                 state: dict | None = None) -> dict | None:
    """One feature row plus addresses for one full window, or None when the window is not about a device.

    `state` maps (device_ip, remote_ip, remote_service_port, proto) -> earliest timestamp the device
    sent to that remote port. A window that starts with the remote is only a reply when such a state
    entry exists and is earlier; otherwise it is an unsolicited inbound window.
    """
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
    original_inbound = first.src == remote          # whoever speaks first started the conversation
    inbound = original_inbound
    # state-based correction: a window that starts with the remote is a reply only if the
    # device sent to that same remote service port earlier
    if original_inbound:
        remote_sent = [p for p in mine if p.src == remote]
        remote_service_port = Counter(p.sport for p in remote_sent if p.sport).most_common(1)
        remote_service_port = remote_service_port[0][0] if remote_service_port else 0
        remote_proto = Counter(p.proto for p in remote_sent).most_common(1)
        remote_proto = remote_proto[0][0] if remote_proto else 0
        key = (device_ip, remote, remote_service_port, remote_proto)
        earliest = (state or {}).get(key)
        if earliest is not None and win[0].ts > earliest:
            inbound = False
    src, dst = (remote, device_ip) if inbound else (device_ip, remote)
    # features come from the packets actually present from the original sender
    feature_src = remote if original_inbound else device_ip
    sent = [p for p in mine if p.src == feature_src]
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
    # record state when the device speaks first (an outbound window)
    if state is not None and not inbound:
        dev_sent = [p for p in mine if p.src == device_ip]
        dev_service_port = Counter(p.dport for p in dev_sent if p.dport).most_common(1)
        dev_service_port = dev_service_port[0][0] if dev_service_port else 0
        dev_proto = Counter(p.proto for p in dev_sent).most_common(1)
        dev_proto = dev_proto[0][0] if dev_proto else 0
        key = (device_ip, remote, dev_service_port, dev_proto)
        if key not in state or win[0].ts < state[key]:
            state[key] = win[0].ts
    return event


class WindowBuffer:
    """Cuts a stream of packets into windows of 10; the packets of a part-window wait for the next `feed`."""

    def __init__(self, devices, window: int = WINDOW, min_device_packets: int = 6, max_wait: int = 1000) -> None:
        self.by_ip = {str(d["ip"]): d for d in devices if d.get("ip") and d.get("device_id")}
        self.window, self.min_device_packets = window, min_device_packets
        self.max_wait = max_wait
        self._rest: list[Packet] = []
        self._last_ts: float | None = None
        self._state: dict = {}

    def feed(self, packets: list[Packet]) -> list[dict]:
        pkts = self._rest + list(packets)
        events = []
        full = len(pkts) - len(pkts) % self.window
        for i in range(0, full, self.window):
            win = pkts[i:i + self.window]
            before = self._last_ts if self._last_ts is not None else win[0].ts
            gaps = [win[0].ts - before] + [b.ts - a.ts for a, b in pairwise(win)]
            self._last_ts = win[-1].ts
            e = window_event(win, gaps, self.by_ip, self.min_device_packets, self._state)
            if e is not None:
                events.append(e)
        self._rest = pkts[full:][-self.max_wait:]
        return events