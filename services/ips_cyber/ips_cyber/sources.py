"""sources.py - where the cyber service gets events from.

Every source yields (event_ref, event_dict). event_ref is a stable text that identifies the event
(file row or flow window), so the alert id is the same every time the same input is replayed.
"""
import csv
import os

from .flow_engine import FlowEngine


def csv_source(path):
    """Replay events from a CSV (Person 2's sample_events.csv): one event per row.
    Empty cells are dropped; every other column is passed through unchanged (as text)."""
    with open(path, newline="", encoding="utf-8-sig") as f:
        for n, row in enumerate(csv.DictReader(f), start=2):      # row 1 is the header
            event = {}
            for key, value in row.items():
                if key is None:                                    # row with more cells than headers
                    continue
                value = (value or "").strip()
                if value != "":
                    event[key.strip()] = value
            yield "row%d" % n, event


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
