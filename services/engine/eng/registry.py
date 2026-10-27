"""Which devices exist, learned from the retained `.../status` messages (no hard-coded IDs)."""
from __future__ import annotations

NON_PHYSICAL_ZONES = frozenset({"network"})


class DeviceRegistry:
    def __init__(self, limit: int = 500) -> None:
        self.limit = limit
        self.devices: dict[tuple[str, str], tuple[str, bool]] = {}    # (type, id) -> (zone, online)

    def update(self, zone: str, device_type: str, device_id: str, online: bool) -> None:
        key = (device_type, device_id)
        if key not in self.devices and len(self.devices) >= self.limit:
            return                                       # bounded: a flood of fake IDs is ignored
        self.devices[key] = (zone, online)

    def find(self, device_type: str, zone: str | None = None) -> list[tuple[str, str, str]]:
        """(zone, type, id) of the reachable devices of that type.

        With a zone: that zone's devices; if it has none, every device of the type EXCEPT for the
        network zone, where "the lights in the network" is meaningless.
        """
        every = sorted((z, device_type, i) for (t, i), (z, online) in self.devices.items()
                       if t == device_type and online)
        if zone is None:
            return every
        here = [d for d in every if d[0] == zone]
        if here or zone in NON_PHYSICAL_ZONES:
            return here
        return every
