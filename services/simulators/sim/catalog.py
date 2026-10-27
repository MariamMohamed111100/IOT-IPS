"""What every device kind can do. This file is the single place that maps device behaviour
to the event registry in docs/CONTRACT.md section 3 (a test keeps both in sync).

Terms
- stimulus : something that happens TO a sensor (motion, door opens...). In simulation it is
             injected; on the Pi it comes from a GPIO edge. Same code path either way.
- action   : a command sent TO an actuator over MQTT (.../cmd): on, off, lock, unlock, open, close.
- emit     : an (event_type, data) pair that becomes a contract event on .../event.
"""
from __future__ import annotations

from typing import Any, Callable

Emit = tuple[str, dict[str, Any]]

SENSOR_KINDS = {"pir", "door", "window", "smoke", "gas", "water_leak", "temperature", "camera"}
ACTUATOR_KINDS = {"bulb", "siren", "lock", "valve"}
KINDS = SENSOR_KINDS | ACTUATOR_KINDS

# Initial device state. Keys follow the status payload in CONTRACT 4.2 (power / lock / open ...).
INITIAL: dict[str, dict[str, Any]] = {
    "pir": {"motion": False},
    "door": {"open": False},
    "window": {"open": False},
    "smoke": {"smoke": False},
    "gas": {"gas": False, "ppm": 0},
    "water_leak": {"leak": False},
    "temperature": {"temperature_c": 22.0},
    "camera": {"stream": "up"},
    "bulb": {"power": "off"},
    "siren": {"power": "off"},
    "lock": {"lock": "locked"},
    "valve": {"open": True},
}

# Commands accepted on .../cmd -> state change.
ACTIONS: dict[str, dict[str, dict[str, Any]]] = {
    "bulb": {"on": {"power": "on"}, "off": {"power": "off"}},
    "siren": {"on": {"power": "on"}, "off": {"power": "off"}},
    "lock": {"lock": {"lock": "locked"}, "unlock": {"lock": "unlocked"}},
    "valve": {"open": {"open": True}, "close": {"open": False}},
}

# Hint only: the engine decides the real severity (CONTRACT section 2).
SEVERITY = {
    "motion.night": "medium", "motion.outdoor": "low", "door.open": "medium",
    "window.open": "medium", "smoke.detected": "critical", "gas.detected": "high",
    "water.leak": "high", "temperature.abnormal": "high", "valve.closed": "info",
    "lock.login_failed": "medium", "camera.disconnected": "medium",
}


def _num(data: dict, key: str, default: float | None = None) -> float:
    if key not in data and default is not None:
        return default
    try:
        return float(data[key])
    except (KeyError, TypeError, ValueError):
        raise ValueError(f"'{key}' must be a number") from None


def temperature_update(dev: Any, value: float) -> tuple[dict, list[Emit]]:
    """New reading -> state patch, plus ONE temperature.abnormal when the threshold is crossed."""
    value = round(value, 1)
    threshold = float(dev.options.get("threshold_c", 50.0))
    emits: list[Emit] = []
    if value > threshold and not dev.alarmed:
        dev.alarmed = True
        emits.append(("temperature.abnormal",
                      {"sensor_id": dev.id, "value_c": value, "threshold_c": threshold}))
    elif value <= threshold:
        dev.alarmed = False  # re-arm
    return {"temperature_c": value}, emits


def _motion(dev: Any, data: dict) -> tuple[dict, list[Emit]]:
    dev.hold_until = dev.now() + float(dev.options.get("hold_s", 5.0))
    # CONTRACT section 1: outdoor zones emit motion.outdoor instead of motion.night.
    event = "motion.outdoor" if dev.outdoor else "motion.night"
    return {"motion": True}, [(event, {"sensor_id": dev.id})]


def _temp_set(dev: Any, data: dict) -> tuple[dict, list[Emit]]:
    dev.pinned = _num(data, "value_c")
    return temperature_update(dev, dev.pinned)


def _gas_detect(dev: Any, data: dict) -> tuple[dict, list[Emit]]:
    ppm = int(_num(data, "ppm", 400))
    return {"gas": True, "ppm": ppm}, [("gas.detected", {"sensor_id": dev.id, "ppm": ppm})]


def _login_failed(dev: Any, data: dict) -> tuple[dict, list[Emit]]:
    attempts = int(_num(data, "attempts", 1))
    return {}, [("lock.login_failed", {"lock_id": dev.id, "attempts": attempts})]


Handler = Callable[[Any, dict], tuple[dict, list[Emit]]]

STIMULI: dict[tuple[str, str], Handler] = {
    ("pir", "motion"): _motion,
    ("pir", "still"): lambda d, _: ({"motion": False}, []),
    ("door", "open"): lambda d, _: ({"open": True}, [("door.open", {"door_id": d.id})]),
    ("door", "close"): lambda d, _: ({"open": False}, []),
    ("window", "open"): lambda d, _: ({"open": True}, [("window.open", {"window_id": d.id})]),
    ("window", "close"): lambda d, _: ({"open": False}, []),
    ("smoke", "detect"): lambda d, _: ({"smoke": True}, [("smoke.detected", {"sensor_id": d.id})]),
    ("smoke", "clear"): lambda d, _: ({"smoke": False}, []),
    ("gas", "detect"): _gas_detect,
    ("gas", "clear"): lambda d, _: ({"gas": False, "ppm": 0}, []),
    ("water_leak", "leak"): lambda d, _: ({"leak": True}, [("water.leak", {"sensor_id": d.id})]),
    ("water_leak", "clear"): lambda d, _: ({"leak": False}, []),
    ("temperature", "set"): _temp_set,
    ("camera", "disconnect"):
        lambda d, _: ({"stream": "down"}, [("camera.disconnected", {"camera_id": d.id})]),
    ("camera", "connect"): lambda d, _: ({"stream": "up"}, []),
    ("lock", "login_failed"): _login_failed,
}

# Events an actuator produces as a consequence of a command (confirmation for the engine).
ACTION_EVENTS: dict[tuple[str, str], Callable[[Any], list[Emit]]] = {
    ("valve", "close"): lambda d: [("valve.closed", {"valve_id": d.id})],
}


def stimuli_for(kind: str) -> list[str]:
    return sorted(name for (k, name) in STIMULI if k == kind)
