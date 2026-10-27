import json
import pathlib
import sys
from dataclasses import replace

import pytest

SERVICE = pathlib.Path(__file__).resolve().parent.parent
REPO = SERVICE.parent.parent
sys.path.insert(0, str(SERVICE))

from cyb.config import SID_PORT_SCAN, Settings  # noqa: E402
from cyb.service import CyberService  # noqa: E402


class FakeClock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class FakeSink:
    def __init__(self) -> None:
        self.events = []

    def publish(self, event) -> None:
        self.events.append(event)

    def types(self) -> list[str]:
        return [e.type for e in self.events]


def alert(sid: int, src: str = "192.168.1.15", dst: str = "192.168.1.10", port: int = 80) -> dict:
    """A Suricata eve.json alert record (only the fields the service reads)."""
    return {"timestamp": "2026-10-11T10:00:00.000000+0000", "event_type": "alert",
            "src_ip": src, "src_port": 40000, "dest_ip": dst, "dest_port": port, "proto": "TCP",
            "alert": {"signature_id": sid, "signature": "test", "severity": 2}}


def dhcp(mac: str, assigned_ip: str = "0.0.0.0", hostname: str | None = None) -> dict:
    body = {"type": "request", "client_mac": mac, "assigned_ip": assigned_ip}
    if hostname:
        body["hostname"] = hostname
    return {"event_type": "dhcp", "src_ip": "0.0.0.0", "dest_ip": "255.255.255.255", "dhcp": body}


def write_lines(path: pathlib.Path, *records: dict, raw: str = "", mode: str = "a") -> None:
    with open(path, mode, encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
        fh.write(raw)


def feed_scan(svc, clock, src: str = "192.168.1.15", ports=range(1, 30)) -> None:
    for p in ports:
        svc.process_record(alert(SID_PORT_SCAN, src=src, port=p), clock())
    clock.advance(3)
    svc.tick(clock())


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def sink():
    return FakeSink()


@pytest.fixture
def known_file(tmp_path):
    path = tmp_path / "known.yaml"
    path.write_text('devices:\n  - mac: "aa:bb:cc:00:00:01"\n    name: lock\n', encoding="utf-8")
    return path


@pytest.fixture
def settings(tmp_path, known_file):
    return replace(Settings(), eve_path=tmp_path / "eve.json", state_file=tmp_path / "bl.json",
                   known_devices_file=known_file)


@pytest.fixture
def service(settings, sink, clock):
    svc = CyberService(settings, sink, clock=clock)
    svc.restore()
    return svc
