"""sources.py - where the cyber service gets events from.

Every source yields (event_ref, event_dict). event_ref is a stable text that identifies the event
(file row or flow window), so the alert id is the same every time the same input is replayed.
"""
import csv
import logging
import os

from .flow_engine import FlowEngine

log = logging.getLogger("ips_cyber.sources")


def csv_source(path, max_field_bytes=1_000_000):
    """Replay events from a CSV (Person 2's sample_events.csv): one event per row.
    Empty cells are dropped; every other column is passed through unchanged (as text).

    A row that breaks the CSV parser (an unterminated quote, an oversized field) is counted and
    skipped: it must not abort a whole replay, and `csv.Error` is not a `ValueError` so the
    caller's guard would not have caught it.
    """
    previous_limit = csv.field_size_limit(max_field_bytes)
    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            n = 1
            while True:
                try:
                    row = next(reader)
                except StopIteration:
                    return
                except csv.Error as exc:
                    log.warning("%s: skipping unreadable row %d: %s", path, n + 1, exc)
                    n += 1
                    continue
                n += 1
                event = {}
                for key, value in row.items():
                    if key is None:                                    # more cells than headers
                        continue
                    value = (value or "").strip()
                    if value != "":
                        event[key.strip()] = value
                yield "row%d" % n, event
    finally:
        csv.field_size_limit(previous_limit)


def _window_buffer(devices):
    """The 10-packet windows of the ML model (needs `pip install -e services/ml`)."""
    try:
        from ids_ml.live import WindowBuffer
    except ImportError as exc:
        raise ValueError("--ml-windows needs the ML package: pip install -e services/ml (%s)" % exc) from None
    return WindowBuffer(devices)


def pcap_source(path, devices, flow_config=None, ml_windows=False):
    """Extract flows from a PCAP and yield one event per (window, source, device).
    With ml_windows, the 10-packet windows of the ML model follow (event_ref starts with "win:")."""
    buffer = _window_buffer(devices) if ml_windows else None      # fail before reading the file
    engine = FlowEngine(devices, flow_config)
    for event in engine.events_from_pcap(path):
        yield event["event_ref"], event
    if buffer is not None:
        from ids_ml.extractor import read_pcap
        for event in buffer.feed(read_pcap(path)):
            yield event["event_ref"], event


def live_source(iface, devices, flow_config=None, chunk_seconds=10, max_chunks=None, ml_windows=False):
    """Capture live traffic in chunks (needs root). Not unit-tested: it needs a real interface.
    With ml_windows the same packets also feed the 10-packet windows of the ML model."""
    import time
    buffer = _window_buffer(devices) if ml_windows else None
    engine = FlowEngine(devices, flow_config)
    n = 0
    while max_chunks is None or n < max_chunks:
        packets = engine.sniff_packets(iface, chunk_seconds)
        engine.add_flows(engine.flows_from_packets(packets))
        for event in engine.tick(time.time()):
            yield event["event_ref"], event
        if buffer is not None:
            for event in buffer.feed(_to_packets(packets)):
                yield event["event_ref"], event
        n += 1


def _to_packets(scapy_packets):
    """scapy packets -> the extractor's Packet objects (frames the dataset's converter skips are dropped)."""
    from ids_ml.extractor import parse
    out = []
    for p in scapy_packets:
        parsed = parse(float(p.time), bytes(p))
        if parsed is not None:
            out.append(parsed)
    return out


def source_name(path):
    return os.path.basename(path) if path else "live"
