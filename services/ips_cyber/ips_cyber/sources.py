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


def pcap_source(path, devices, flow_config=None):
    """Extract flows from a PCAP and yield one event per (window, source, device)."""
    engine = FlowEngine(devices, flow_config)
    for event in engine.events_from_pcap(path):
        yield event["event_ref"], event


def live_source(iface, devices, flow_config=None, chunk_seconds=10, max_chunks=None):
    """Capture live traffic in chunks (needs root). Not unit-tested: it needs a real interface."""
    import time
    engine = FlowEngine(devices, flow_config)
    n = 0
    while max_chunks is None or n < max_chunks:
        engine.add_flows(engine.sniff_chunk(iface, chunk_seconds))
        for event in engine.tick(time.time()):
            yield event["event_ref"], event
        n += 1


def source_name(path):
    return os.path.basename(path) if path else "live"
