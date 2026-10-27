"""
baseline.py - normal-traffic generator for the simulated camera (calibration, Task 7).

    from iot_ips.baseline import generate, Assumptions
    events = list(generate(hours=24, seed=1))

Produces what a healthy camera (CAM-001) does all day, as events in the same format the
detector reads (the CSV contract of docs/pipeline.md), so the same events can be written to a
CSV and replayed through `python -m iot_ips run`. Nothing here sends a packet.

Kinds of traffic (every number is in `Assumptions`, nothing is hidden in the code):
  recorder_stream   the Raspberry Pi pulls the video over RTSP (port 554), all day
  live_view         an owner's phone watches the live video, in sessions, more in the evening
  cloud_upload      the camera uploads a clip after motion (HTTPS, port 443), more by day
  cloud_keepalive   a small HTTPS heartbeat to the vendor cloud every few minutes
  dns               DNS lookups to the router (port 53)
  ntp               clock sync (port 123)
  password_typo     the owner mistypes the camera's web password 1-3 times

HOW REAL IS IT? Not very, and the report says so. The CICIoT2023 data has only 4 real benign
rows with all the fields the detector reads (Rate 31 / 73 / 61 / 1040 packets per second).
The medians below are put near those rows and the spread is a guess, so the generator is a
tool for finding which rules are fragile (see `rate_spread` in Assumptions and the
sensitivity table in docs/calibration-report.md), not a measurement of a real home. Run the same
calibration on benign lab traffic (Task 8) before trusting an absolute false-alarm count.

Deterministic: the same seed always gives the same events. Python 3.10+, standard library only.
"""

from __future__ import annotations

import csv
import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterator, List, Tuple

__all__ = ["Assumptions", "generate", "write_csv", "FIELDS", "KINDS"]

KINDS = ("recorder_stream", "live_view", "cloud_upload", "cloud_keepalive", "dns", "ntp", "password_typo")

FIELDS = ("event_id", "device_id", "timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "direction",
          "failed_attempts", "connection_attempts", "unique_dst_ports", "unique_dst_ips",
          "Rate", "syn_count", "Number", "traffic_kind")

DEFAULT_START = datetime(2026, 10, 26, 0, 0, 0, tzinfo=timezone.utc)   # a Monday


@dataclass(frozen=True)
class Assumptions:
    """Everything the generator assumes. Change a number here to ask a "what if" question."""

    device_id: str = "CAM-001"
    camera_ip: str = "192.168.1.50"
    router_ip: str = "192.168.1.1"            # DNS resolver
    recorder_ip: str = "192.168.1.2"          # the Raspberry Pi pulls the stream
    owner_phones: Tuple[str, ...] = ("192.168.1.20", "192.168.1.21")
    cloud_ips: Tuple[str, ...] = ("52.29.14.7", "52.29.14.8")
    ntp_ip: str = "129.6.15.28"

    # Rate (packets per second inside one 10-packet window) = lognormal(median, sigma * rate_spread).
    # Medians sit near the real benign rows: stream 31, DNS 73, upload 1040 (a short burst).
    rate_spread: float = 1.0                  # 1.0 = the guess below; 2.0 = twice as heavy a tail
    stream_rate: Tuple[float, float] = (35.0, 0.5)       # (median, sigma)
    upload_rate: Tuple[float, float] = (350.0, 0.7)      # EVT-002 (1040) is ~1.5 sigma above this
    keepalive_rate: Tuple[float, float] = (25.0, 0.4)
    dns_rate: Tuple[float, float] = (70.0, 0.5)
    ntp_rate: Tuple[float, float] = (20.0, 0.3)

    # Events per minute / period.
    recorder_period_s: int = 60               # one 60 s window of the recording stream
    dns_period_s: int = 300                   # a lookup about every 5 minutes
    ntp_period_s: int = 1024                  # the usual NTP poll interval
    keepalive_period_s: int = 600

    # Poisson arrivals per hour of the day (0-23).
    view_sessions_per_hour: Tuple[float, ...] = field(default_factory=lambda: (
        0.0, 0.0, 0.0, 0.0, 0.0, 0.1, 0.4, 0.8, 0.6, 0.2, 0.2, 0.3,
        0.4, 0.3, 0.2, 0.2, 0.3, 0.6, 1.0, 1.2, 1.2, 1.0, 0.6, 0.1))
    uploads_per_hour: Tuple[float, ...] = field(default_factory=lambda: (
        0.3, 0.2, 0.2, 0.2, 0.3, 1.0, 3.0, 4.0, 3.0, 2.0, 2.0, 2.5,
        3.0, 2.5, 2.0, 2.0, 3.0, 4.0, 4.0, 3.0, 2.5, 2.0, 1.0, 0.5))
    typos_per_hour: Tuple[float, ...] = field(default_factory=lambda: (
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.02, 0.02, 0.0, 0.0, 0.0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.03, 0.05, 0.06, 0.06, 0.05, 0.02, 0.0))
    view_minutes: Tuple[int, int] = (2, 15)    # length of a live-view session
    upload_windows: Tuple[int, int] = (1, 4)   # windows (30 s apart) per uploaded clip


def _poisson(rng: random.Random, mean: float) -> int:
    limit, k, p = math.exp(-mean), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def _rate(rng: random.Random, median_sigma: Tuple[float, float], spread: float) -> float:
    median, sigma = median_sigma
    return round(median * math.exp(rng.gauss(0.0, sigma * spread)), 3)


def _arrivals(rng: random.Random, per_hour: Tuple[float, ...], start: datetime, hours: int) -> Iterator[float]:
    """Times (seconds since start) of a Poisson process whose rate changes with the hour of the day."""
    peak = max(per_hour) / 3600.0
    if peak <= 0:
        return
    t, end = 0.0, hours * 3600.0
    while True:
        t += rng.expovariate(peak)
        if t >= end:
            return
        hour = (start + timedelta(seconds=t)).hour
        if rng.random() < per_hour[hour] / 3600.0 / peak:
            yield t


def generate(hours: float = 24, seed: int = 1, assumptions: Assumptions | None = None,
             start: datetime = DEFAULT_START) -> Iterator[dict]:
    """Yield the events of `hours` hours of normal traffic, in time order, as plain dicts."""
    if not isinstance(hours, (int, float)) or isinstance(hours, bool) or not 0 < hours <= 24 * 366:
        raise ValueError("hours must be a number between 0 and 8784")
    a = assumptions or Assumptions()
    if not 0 < a.rate_spread <= 20:
        raise ValueError("rate_spread must be between 0 and 20")
    rng = random.Random(seed)
    span = int(math.ceil(hours))
    horizon = hours * 3600.0
    cam = a.camera_ip
    rows: List[Tuple[float, int, dict]] = []     # (time, tie-breaker, event)

    def add(t: float, kind: str, src: str, dst: str, port: int, proto: str, rate_cfg, *,
            failed=0, attempts=1, dst_ips=1, syn_mean=0.0, spread=a.rate_spread):
        if t >= horizon:
            return
        rows.append((t, len(rows), {
            "device_id": a.device_id,
            "timestamp": (start + timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": src, "dst_ip": dst, "dst_port": port, "protocol": proto,
            "direction": "outbound" if src == cam else "inbound",
            "failed_attempts": failed, "connection_attempts": attempts,
            "unique_dst_ports": 1, "unique_dst_ips": dst_ips,
            "Rate": _rate(rng, rate_cfg, spread), "syn_count": _poisson(rng, syn_mean), "Number": 10,
            "traffic_kind": kind}))

    # The Pi pulls the stream: one window per period, all day.
    t = rng.uniform(0, a.recorder_period_s)
    while t < horizon:
        add(t, "recorder_stream", a.recorder_ip, cam, 554, "TCP", a.stream_rate, syn_mean=0.1)
        t += a.recorder_period_s

    # Live view: sessions, one window per minute.
    for t0 in _arrivals(rng, a.view_sessions_per_hour, start, span):
        phone = rng.choice(a.owner_phones)
        minutes = rng.randint(*a.view_minutes)
        for m in range(minutes):
            add(t0 + 60 * m, "live_view", phone, cam, 554, "TCP", a.stream_rate, syn_mean=1.0 if m == 0 else 0.1)

    # Clip uploads after motion.
    for t0 in _arrivals(rng, a.uploads_per_hour, start, span):
        cloud = rng.choice(a.cloud_ips)
        for w in range(rng.randint(*a.upload_windows)):
            add(t0 + 30 * w, "cloud_upload", cam, cloud, 443, "TCP", a.upload_rate,
                attempts=rng.randint(1, 3), dst_ips=rng.randint(1, 2), syn_mean=0.5)

    # Fixed-period traffic with a random start and +-10 % jitter.
    def periodic(kind, period, dst, port, proto, rate_cfg, attempts=(1, 1), syn_mean=0.0):
        t = rng.uniform(0, period)
        while t < horizon:
            add(t, kind, cam, dst, port, proto, rate_cfg, attempts=rng.randint(*attempts), syn_mean=syn_mean)
            t += period * rng.uniform(0.9, 1.1)

    periodic("dns", a.dns_period_s, a.router_ip, 53, "UDP", a.dns_rate, attempts=(1, 2))
    periodic("ntp", a.ntp_period_s, a.ntp_ip, 123, "UDP", a.ntp_rate)
    periodic("cloud_keepalive", a.keepalive_period_s, a.cloud_ips[0], 443, "TCP", a.keepalive_rate, syn_mean=0.3)

    # The owner mistypes the web password.
    for t0 in _arrivals(rng, a.typos_per_hour, start, span):
        wrong = rng.randint(1, 3)
        add(t0, "password_typo", rng.choice(a.owner_phones), cam, 443, "TCP", a.stream_rate,
            failed=wrong, attempts=wrong + 1, syn_mean=1.0)

    rows.sort(key=lambda r: (r[0], r[1]))
    for number, (_, _, event) in enumerate(rows, 1):
        event["event_id"] = "BASE-%06d" % number
        yield {key: event[key] for key in FIELDS}


def write_csv(path: str, events) -> int:
    """Write events to a CSV file that `python -m iot_ips run` can replay. Returns the row count."""
    count = 0
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for event in events:
            writer.writerow(event)
            count += 1
    return count
