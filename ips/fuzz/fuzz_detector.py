"""Atheris fuzz harness for the rule-based detector (``iot_ips.detector.detect``).

OpenSSF Scorecard's "Fuzzing" check looks for a Python Atheris integration
(``import atheris``); this is the project's fuzz target for the IPS detector.

The detector is the component that consumes untrusted input (packet/flow events
arriving over MQTT), so it is the most valuable place to fuzz: for any input it
must answer with a valid detection message instead of crashing.

Run it locally (Atheris needs a C/C++ toolchain and ``clang``):

    pip install -e ".[dev,fuzz]"
    python fuzz/fuzz_detector.py -max_total_time=60

It is not wired into CI yet (Atheris is built from source), so run it before
releases or from a dedicated fuzzing workflow.
"""
from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from iot_ips.detector import detect

_PROTOCOLS = ("TCP", "UDP", "ICMP", "IGMP", "GRE", "ARP", "ICMPV6", "SCTP", "RTSP", "HTTPS")
_DIRECTIONS = ("inbound", "outbound", "")
_PROFILE = {
    "ip": "10.0.0.42",
    "expected_ports": [22, 80, 443, 554, 1883],
    "expected_protocols": ["RTSP", "HTTPS", "MQTT"],
}


def build_event(fdp: atheris.FuzzedDataProvider) -> dict:
    """Turn the fuzzer's bytes into an event with the detector's feature names."""
    event = {
        "direction": fdp.PickValueInList(list(_DIRECTIONS)),
        "src_ip": fdp.ConsumeUnicodeNoSurrogates(16),
        "dst_ip": fdp.ConsumeUnicodeNoSurrogates(16),
        "protocol": fdp.PickValueInList(list(_PROTOCOLS)),
        "dst_port": fdp.ConsumeIntInRange(0, 65535),
        "connection_attempts": fdp.ConsumeIntInRange(0, 10_000),
        "Rate": fdp.ConsumeIntInRange(0, 100_000),
        "syn_count": fdp.ConsumeIntInRange(0, 10_000),
        "failed_attempts": fdp.ConsumeIntInRange(0, 10_000),
        "unique_dst_ports": fdp.ConsumeIntInRange(0, 10_000),
        "unique_dst_ips": fdp.ConsumeIntInRange(0, 10_000),
    }
    # Occasionally drop a field or inject a non-numeric value: the detector must
    # tolerate empty, missing and malformed features.
    if fdp.ConsumeBool():
        event.pop(fdp.PickValueInList(list(event)), None)
    if fdp.ConsumeBool():
        event["Rate"] = fdp.ConsumeUnicodeNoSurrogates(8)
    if fdp.ConsumeBool():
        event["SSH"] = fdp.ConsumeIntInRange(0, 1)
    return event


def TestOneInput(data: bytes) -> None:
    """Atheris entry point: feed one byte string to the detector."""
    fdp = atheris.FuzzedDataProvider(data)
    event = build_event(fdp)
    profile = _PROFILE if fdp.ConsumeBool() else None
    detect(event, profile)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
