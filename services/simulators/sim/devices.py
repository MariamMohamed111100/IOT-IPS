"""Builds the device objects from devices.yaml, choosing simulator or real driver per device."""
from __future__ import annotations

import random
import time
from pathlib import Path
from typing import Any, Callable

import yaml

from . import catalog
from .hal import Device, SimActuator, SimSensor

DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "devices.yaml"
_RESERVED = {"id", "kind", "zone", "gpio_pin"}


def load_config(path: Path | str = DEFAULT_CONFIG) -> dict[str, Any]:
    cfg = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    ids = [d["id"] for d in cfg["devices"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate device ids in devices.yaml")
    for d in cfg["devices"]:
        if d["kind"] not in catalog.KINDS:
            raise ValueError(f"{d['id']}: unknown kind {d['kind']!r}")
    return cfg


def build_devices(cfg: dict[str, Any], driver: str = "sim", *,
                  clock: Callable[[], float] = time.monotonic,
                  rng: random.Random | None = None, temp_interval: float = 10.0,
                  pin_factory: Any = None) -> dict[str, Device]:
    """driver='sim': everything simulated. driver='gpio': devices that have `gpio_pin` use real
    hardware, the rest stay simulated (so the Pi can be brought up one device at a time)."""
    if driver not in ("sim", "gpio"):
        raise ValueError("HAL_DRIVER must be 'sim' or 'gpio'")
    outdoor = set(cfg.get("outdoor_zones", []))
    devices: dict[str, Device] = {}
    for d in cfg["devices"]:
        opts = {k: v for k, v in d.items() if k not in _RESERVED}
        common = dict(options=opts, outdoor=d["zone"] in outdoor)
        kind, is_sensor = d["kind"], d["kind"] in catalog.SENSOR_KINDS
        if driver == "gpio" and "gpio_pin" in d:
            from .hal_gpio import GpioSensor, RelayActuator
            cls = GpioSensor if is_sensor else RelayActuator
            dev: Device = cls(d["id"], kind, d["zone"], pin=d["gpio_pin"],
                              pin_factory=pin_factory, **common)
        elif is_sensor:
            dev = SimSensor(d["id"], kind, d["zone"], clock=clock, rng=rng,
                            temp_interval=temp_interval, **common)
        else:
            dev = SimActuator(d["id"], kind, d["zone"], clock=clock, **common)
        devices[d["id"]] = dev
    return devices
