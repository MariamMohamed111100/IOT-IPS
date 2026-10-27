"""Per-zone risk score: decay window, per-type repeat cap and correlation bonuses.

A zone's score counts the events of THAT zone plus the network events (a port scan is about the
whole house). A leak in the kitchen therefore never adds to an intruder in the garage.
"""
from __future__ import annotations

from dataclasses import dataclass

from .policy import Policy

NON_PHYSICAL_ZONES = frozenset({"network"})


@dataclass
class Contribution:
    kind: str            # "event" | "correlation"
    type: str            # event type, or the correlation rule name
    points: int
    ts: float            # when the engine received it (the engine's own clock decides decay)
    zone: str
    event_id: str = ""


class Scorer:
    """Hard decay: an event counts in full until it is `window_s` old, then not at all."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.contribs: list[Contribution] = []
        self.seen: list[tuple[float, str, str]] = []     # (ts, type, zone) of every scored event

    def purge(self, now: float) -> None:
        cutoff = now - self.policy.window_s
        self.contribs = [c for c in self.contribs if c.ts > cutoff]
        self.seen = [s for s in self.seen if s[0] > cutoff]

    def _view(self, zone: str) -> list[Contribution]:
        return [c for c in self.contribs if c.zone == zone or c.zone in NON_PHYSICAL_ZONES]

    def physical_zones(self, now: float) -> list[str]:
        self.purge(now)
        return sorted({c.zone for c in self.contribs if c.zone not in NON_PHYSICAL_ZONES})

    def zones(self, now: float) -> list[str]:
        """Zones with live risk: every physical zone, plus `network` when only the network
        (a scan, a brute-force, a rogue device) is under way with no physical event."""
        found = self.physical_zones(now)
        if any(c.zone in NON_PHYSICAL_ZONES for c in self.contribs):
            found.append("network")
        return found

    def add_event(self, event_type: str, zone: str, event_id: str, now: float
                  ) -> Contribution | None:
        self.purge(now)
        points = self.policy.points.get(event_type, 0)
        if points <= 0:
            return None
        same = sum(1 for c in self.contribs
                   if c.kind == "event" and c.type == event_type and c.zone == zone)
        if same >= self.policy.repeat_cap:
            return None
        self.seen.append((now, event_type, zone))
        contrib = Contribution("event", event_type, points, now, zone, event_id)
        self.contribs.append(contrib)
        return contrib

    def correlate(self, now: float) -> list[Contribution]:
        """Per zone: a rule adds its bonus once while its inputs are recent and it is not alive."""
        fired: list[Contribution] = []
        for zone in self.zones(now):
            for rule in self.policy.correlations:
                if any(c.kind == "correlation" and c.type == rule.name and c.zone == zone
                       for c in self.contribs):
                    continue
                recent = {t for ts, t, z in self.seen
                          if (z == zone or z in NON_PHYSICAL_ZONES) and now - ts <= rule.within_s}
                if all(t in recent for t in rule.requires):
                    bonus = Contribution("correlation", rule.name, rule.bonus, now, zone)
                    self.contribs.append(bonus)
                    fired.append(bonus)
        return fired

    def score(self, now: float, zone: str) -> int:
        self.purge(now)
        return min(self.policy.max_score, sum(c.points for c in self._view(zone)))

    def factors(self, zone: str, limit: int = 8) -> list[dict]:
        ranked = sorted(self._view(zone), key=lambda c: (-c.points, c.ts))
        return [{"type": ("correlation." + c.type) if c.kind == "correlation" else c.type,
                 "weight": c.points} for c in ranked[:limit]]

    def event_ids(self, zone: str) -> list[str]:
        return [c.event_id for c in sorted(self._view(zone), key=lambda c: c.ts)
                if c.kind == "event" and c.event_id]
