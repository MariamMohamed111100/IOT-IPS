"""Single source of truth for MQTT topic names. See docs/CONTRACT.md."""
import re

_TOKEN = re.compile(r"^[a-z0-9_]+$")
ALERT_SOURCES = ("vision", "cyber", "engine")


def _t(*parts: str) -> str:
    for p in parts:
        if not _TOKEN.match(p):
            raise ValueError(f"invalid topic token {p!r}: use lowercase a-z, 0-9, underscore")
    return "/".join(parts)


def sensor_event(zone: str, device_type: str, device_id: str) -> str:
    return _t("home", zone, device_type, device_id, "event")


def device_cmd(zone: str, device_type: str, device_id: str) -> str:
    return _t("home", zone, device_type, device_id, "cmd")


def device_status(zone: str, device_type: str, device_id: str) -> str:
    return _t("home", zone, device_type, device_id, "status")


def alert(source: str) -> str:
    if source not in ALERT_SOURCES:
        raise ValueError(f"unknown alert source {source!r}, expected one of {ALERT_SOURCES}")
    return f"security/alerts/{source}"


def heartbeat(service: str) -> str:
    return _t("system", "heartbeat", service)


RISK = "security/risk"
INCIDENTS = "security/incidents"
# One-way command channel: engine @P1/P6 instructs cyber to drop an IP.
BLOCK = "system/block"
# Simulation only: the scenario runner asks the simulators to make something "happen".
# Never subscribed to on real hardware (SIM_ALLOW_INJECT=false).
SIM_INJECT = "system/sim/inject"
