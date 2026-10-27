"""YAML scenarios: a timed list of stimuli injected into simulated sensors.

A scenario only says what HAPPENS in the house. It never turns on sirens or lights: that is the
engine's job, and showing the engine do it is the whole point of the demo.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

import yaml

from smartsecure_common import topics

from . import catalog

SCENARIO_DIR = Path(__file__).resolve().parent.parent / "scenarios"


def list_scenarios() -> list[str]:
    return sorted(p.stem for p in SCENARIO_DIR.glob("*.yaml"))


def load_scenario(name_or_path: str) -> dict[str, Any]:
    path = Path(name_or_path)
    if not path.exists():
        path = SCENARIO_DIR / f"{name_or_path}.yaml"
    if not path.exists():
        raise FileNotFoundError(
            f"scenario {name_or_path!r} not found. Available: {list_scenarios()}")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def validate(scenario: dict[str, Any], devices_cfg: dict[str, Any]) -> list[str]:
    """Return a list of problems (empty = valid). Run BEFORE publishing anything."""
    errors: list[str] = []
    kinds = {d["id"]: d["kind"] for d in devices_cfg["devices"]}
    if not scenario.get("name"):
        errors.append("missing 'name'")
    steps = scenario.get("steps")
    if not isinstance(steps, list) or not steps:
        return errors + ["'steps' must be a non-empty list"]
    for i, step in enumerate(steps, 1):
        where = f"step {i}"
        dev, event = step.get("device"), step.get("event")
        if dev not in kinds:
            errors.append(f"{where}: unknown device {dev!r}")
            continue
        if (kinds[dev], event) not in catalog.STIMULI:
            errors.append(f"{where}: {dev} ({kinds[dev]}) cannot '{event}'; "
                          f"valid: {catalog.stimuli_for(kinds[dev])}")
        delay = step.get("delay", 0)
        if not isinstance(delay, (int, float)) or delay < 0:
            errors.append(f"{where}: 'delay' must be a number >= 0")
        if not isinstance(step.get("data", {}), dict):
            errors.append(f"{where}: 'data' must be a mapping")
    return errors


def run(scenario: dict[str, Any], bus, *, sleep: Callable[[float], None] = time.sleep,
        speed: float = 1.0, out: Callable[[str], None] = print, wait: bool = False) -> int:
    """Publish the scenario's stimuli. Returns the number of steps sent."""
    out(f"=== {scenario['name']} ===")
    if scenario.get("description"):
        out(str(scenario["description"]).strip())
    count = 0
    for step in scenario["steps"]:
        delay = float(step.get("delay", 0)) / speed
        if delay > 0:
            out(f"  ... wait {delay:g}s")
            sleep(delay)
        msg = {"device": step["device"], "event": step["event"], "data": step.get("data") or {}}
        note = step.get("comment", "")
        out(f"  -> {step['device']}.{step['event']} {msg['data'] or ''}  # {note}")
        bus.publish(topics.SIM_INJECT, json.dumps(msg), qos=1, wait=wait)
        count += 1
    out(f"=== done: {count} stimuli. Expected result: {scenario.get('expect', '(not specified)')}")
    return count
