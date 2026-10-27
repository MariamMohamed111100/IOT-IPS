"""Real Raspberry Pi drivers (gpiozero). Used when HAL_DRIVER=gpio and a device has `gpio_pin`.

They implement the exact same Sensor/Actuator interface as the simulators, so nothing above
the HAL changes. gpiozero is imported lazily, so laptops without it keep working.

Status: unit-tested with gpiozero's mock pins only. Real wiring, pull-up/down, debounce and
relay polarity must be validated on the Pi in milestone M4.
"""
from __future__ import annotations

from typing import Any

from .catalog import Emit
from .hal import Actuator, Sensor

# kind -> (stimulus when pin goes active, stimulus when pin goes inactive)
EDGES = {
    "pir": ("motion", "still"),
    "door": ("open", "close"),
    "window": ("open", "close"),
    "smoke": ("detect", "clear"),
    "water_leak": ("leak", "clear"),
}
# De-energised relay = the initial state in catalog.INITIAL (bulb off, siren off, locked, open).
ENERGIZE = {"bulb": "on", "siren": "on", "lock": "unlock", "valve": "close"}


class GpioSensor(Sensor):
    source_prefix = "hw"

    def __init__(self, device_id: str, kind: str, zone: str, *, pin: int, outdoor: bool = False,
                 options: dict[str, Any] | None = None, pin_factory: Any = None) -> None:
        if kind not in EDGES:
            raise NotImplementedError(
                f"'{kind}' needs an ADC/I2C/camera driver (M4); GPIO supports {sorted(EDGES)}")
        super().__init__(device_id, kind, zone, outdoor, options)
        from gpiozero import DigitalInputDevice  # lazy: only on the Pi
        opts = self.options
        self._pin = DigitalInputDevice(pin, pull_up=opts.get("pull_up", False),
                                       bounce_time=opts.get("bounce_s"), pin_factory=pin_factory)
        self._last = False

    def poll(self) -> list[Emit]:
        active = bool(self._pin.value)
        if active == self._last:
            return []
        self._last = active
        return self.stimulate(EDGES[self.kind][0 if active else 1])


class RelayActuator(Actuator):
    source_prefix = "hw"

    def __init__(self, device_id: str, kind: str, zone: str, *, pin: int, outdoor: bool = False,
                 options: dict[str, Any] | None = None, pin_factory: Any = None) -> None:
        if kind not in ENERGIZE:
            raise NotImplementedError(f"no relay mapping for '{kind}'")
        super().__init__(device_id, kind, zone, outdoor, options)
        from gpiozero import DigitalOutputDevice  # lazy: only on the Pi
        self._energize = self.options.get("energize_action", ENERGIZE[kind])
        self._out = DigitalOutputDevice(pin, active_high=self.options.get("active_high", True),
                                        initial_value=False, pin_factory=pin_factory)

    def _drive(self, action: str) -> None:
        if action == self._energize:
            self._out.on()
        else:
            self._out.off()
