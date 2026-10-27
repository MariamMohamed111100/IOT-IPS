"""Hardware Abstraction Layer.

The rest of the system only ever sees Sensor and Actuator. Only the driver changes:

    simulation (M1)      SimSensor / SimActuator           (this file)
    Raspberry Pi (M4)    GpioSensor / RelayActuator        (sim/hal_gpio.py)

Rules that make the swap safe
1. Sensors never receive commands. They produce events (poll) - exactly like real hardware.
2. Actuators receive validated actions only, and report the state they ended up in.
3. Event content comes from catalog.py for BOTH drivers, so a real PIR and a simulated PIR
   publish identical events.
4. Only simulated devices can be injected; real hardware refuses (PermissionError).
"""
from __future__ import annotations

import random
import time
from abc import ABC, abstractmethod
from typing import Any, Callable

from . import catalog
from .catalog import Emit


class Device:
    source_prefix = "sim"      # "hw" for real drivers; becomes event.source e.g. "sim.pir"
    injectable = False

    def __init__(self, device_id: str, kind: str, zone: str, outdoor: bool = False,
                 options: dict[str, Any] | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if kind not in catalog.KINDS:
            raise ValueError(f"unknown device kind {kind!r}")
        self.id, self.kind, self.zone, self.outdoor = device_id, kind, zone, outdoor
        self.options = dict(options or {})
        self._clock = clock
        self._state: dict[str, Any] = dict(catalog.INITIAL[kind])
        if kind == "temperature":
            self._state["temperature_c"] = float(self.options.get("base_c", 22.0))
        # simulation scratch values used by catalog handlers
        self.hold_until = 0.0
        self.pinned: float | None = None
        self.alarmed = False

    def now(self) -> float:
        return self._clock()

    @property
    def source(self) -> str:
        return f"{self.source_prefix}.{self.kind}"

    def state(self) -> dict[str, Any]:
        return dict(self._state)

    def stimulate(self, name: str, data: dict | None = None) -> list[Emit]:
        handler = catalog.STIMULI.get((self.kind, name))
        if handler is None:
            raise ValueError(f"{self.kind} '{self.id}' has no stimulus {name!r}; "
                             f"valid: {catalog.stimuli_for(self.kind)}")
        patch, emits = handler(self, data or {})
        self._state.update(patch)
        return emits

    def inject(self, name: str, data: dict | None = None) -> list[Emit]:
        if not self.injectable:
            raise PermissionError(f"'{self.id}' is real hardware: injection is disabled")
        return self.stimulate(name, data)


class Sensor(Device, ABC):
    @abstractmethod
    def poll(self) -> list[Emit]:
        """Called every tick. Return the events that happened since the last call."""

    def was_sampled(self) -> bool:
        """True when poll() just took a periodic reading (e.g. a temperature sample)."""
        return False


class Actuator(Device, ABC):
    def apply(self, action: str) -> list[Emit]:
        spec = catalog.ACTIONS[self.kind]
        if action not in spec:
            raise ValueError(f"{self.kind} '{self.id}' cannot '{action}'; valid: {sorted(spec)}")
        self._drive(action)                 # idempotent: same action twice = same state
        self._state.update(spec[action])
        maker = catalog.ACTION_EVENTS.get((self.kind, action))
        return maker(self) if maker else []

    @abstractmethod
    def _drive(self, action: str) -> None:
        """Make the physical (or simulated) change."""


class SimSensor(Sensor):
    injectable = True

    def __init__(self, *args: Any, temp_interval: float = 10.0,
                 rng: random.Random | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._rng = rng or random.Random()
        self._temp_interval = temp_interval
        self._next_temp = self.now() + temp_interval
        self._sampled_this_poll = False

    def poll(self) -> list[Emit]:
        emits: list[Emit] = []
        self._sampled_this_poll = False
        now = self.now()
        if self.kind == "pir" and self._state["motion"] and now >= self.hold_until:
            self.stimulate("still")                       # motion flag clears by itself
        if self.kind == "temperature" and now >= self._next_temp:
            self._next_temp = now + self._temp_interval
            self._sampled_this_poll = True
            base = float(self.options.get("base_c", 22.0))
            value = self.pinned if self.pinned is not None else base + self._rng.uniform(-0.4, 0.4)
            patch, emits = catalog.temperature_update(self, value)
            self._state.update(patch)
        return emits

    def was_sampled(self) -> bool:
        return self._sampled_this_poll


class SimActuator(Actuator):
    injectable = True       # lets scenarios inject lock.login_failed

    def _drive(self, action: str) -> None:
        return None
