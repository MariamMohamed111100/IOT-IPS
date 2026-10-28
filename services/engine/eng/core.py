"""The engine: events in -> risk score, correlation, incident, automated response out.

The class knows nothing about MQTT. It is fed `on_message(topic, payload)` and calls
`publish(topic, payload_dict, retain)`, so tests (and the in-process demo) drive it with no broker.

What it publishes (CONTRACT sections 1, 4.1, 4.3, 4.4):
    security/risk       retained snapshot, whenever score / level / zone / actions change
    security/incidents  the incident, re-sent with the same id whenever it changes
    home/<z>/<t>/<id>/cmd   commands to devices (on/off/lock/unlock/open/close)
    system/block        block an attacker IP at the firewall (cyber executes it)
"""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import ValidationError

from smartsecure_common import Event, topics

from .ips import IPS_TYPES, IpsEnricher, clean_details
from .notify import Notifier
from .policy import LEVELS, Policy, attacker_ip
from .registry import DeviceRegistry
from .scoring import NON_PHYSICAL_ZONES, Scorer

log = logging.getLogger("engine")

Publish = Callable[[str, dict, bool], None]
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_INCIDENT_EVENTS = 200
SEEN_IDS = 4096
SEEN_DETAILS = 512
ALERT_SOURCES = ("vision", "cyber")           # security/alerts/<source> the engine listens to


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class Incident:
    id: str
    opened: float
    trigger: str
    peak: int = 0
    event_ids: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)       # distinct action names, in order
    notes: list[str] = field(default_factory=list)         # what was done to which device
    closed: bool = False
    details: dict | None = None                            # IPS details (docs/IPS_INTEGRATION.md)
    published: tuple | None = None


@dataclass
class Episode:
    """Everything the engine tracks for one zone while it has live risk."""
    zone: str
    incident: Incident | None = None
    done: set = field(default_factory=set)                 # actions already taken here
    sirens_on: list = field(default_factory=list)
    life_safety: bool = False
    risk_sent: tuple | None = None


class Engine:
    def __init__(self, policy: Policy, publish: Publish, notifier: Notifier | None = None,
                 clock: Callable[[], float] = time.time, ips: IpsEnricher | None = None,
                 protected_ips: Iterable[str] | None = None) -> None:
        self.policy, self._publish, self.clock = policy, publish, clock
        self.notifier = notifier or Notifier()
        self.scorer = Scorer(policy)
        self.registry = DeviceRegistry()
        self.lock = threading.RLock()
        self.episodes: dict[str, Episode] = {}
        self.attackers: dict[str, tuple[str, str]] = {}     # ip -> (event type, zone that named it)
        self.blocked: set[str] = set()
        self._baseline = False
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._details: OrderedDict[str, dict] = OrderedDict()   # event id -> IPS details
        # Our own devices. A packet's source address is chosen by the sender, so without this a
        # spoofed header would make the engine firewall off the very device being attacked.
        self.protected_ips: set[str] = set()
        if protected_ips is not None:
            self.protected_ips |= {str(ip).strip() for ip in protected_ips if isinstance(ip, str)}
        self.ips = ips          # the setter also merges the IPs of ips.profiles into protected_ips

    @property
    def ips(self) -> IpsEnricher | None:
        return self._ips

    @ips.setter
    def ips(self, value: IpsEnricher | None) -> None:
        """Setting the enricher also protects the IPs of its device profiles from being blocked."""
        self._ips = value
        self.protected_ips |= self._ips_device_ips(value)

    @staticmethod
    def _ips_device_ips(ips: IpsEnricher | None) -> set[str]:
        if ips is None:
            return set()
        try:
            return {p["ip"] for p in ips.profiles.values() if isinstance(p.get("ip"), str)}
        except (AttributeError, TypeError):
            return set()

    # ------------------------------------------------------------------ intake
    def on_message(self, topic: str, payload: bytes | str) -> None:
        """Entry point for every MQTT message. Never raises: a bad message is dropped."""
        try:
            self._route(topic, payload)
        except Exception:
            log.exception("could not process a message on %s", topic)

    def _route(self, topic: str, payload: bytes | str) -> None:
        parts = topic.split("/")
        is_device = len(parts) == 5 and parts[0] == "home" and parts[4] in ("event", "status")
        is_alert = (len(parts) == 3 and parts[:2] == ["security", "alerts"]
                    and parts[2] in ALERT_SOURCES)
        if not (is_device or is_alert):
            return
        raw = payload.encode() if isinstance(payload, str) else payload
        if len(raw) > MAX_PAYLOAD_BYTES:
            log.warning("dropped an oversized message on %s", topic)
            return
        try:
            body = json.loads(raw)
        except ValueError:
            log.warning("dropped a non-JSON message on %s", topic)
            return
        if not isinstance(body, dict):
            return
        if is_device and parts[4] == "status":
            online = body.get("online")
            if isinstance(online, bool):
                self.registry.update(parts[1], parts[2], parts[3], online)
            return
        try:
            event = Event.model_validate(body)
        except ValidationError as exc:
            log.warning("dropped an invalid event on %s: %s", topic, exc.errors()[:1])
            return
        if is_device and event.zone != parts[1]:           # same rule the API applies
            log.warning("dropped an event whose zone %r does not match its topic", event.zone)
            return
        self.handle_event(event)

    # ------------------------------------------------------------------ one event
    def handle_event(self, event: Event) -> None:
        with self.lock:
            if event.id in self._seen:                      # QoS 1 may deliver twice
                return
            self._seen[event.id] = None
            while len(self._seen) > SEEN_IDS:
                self._seen.popitem(last=False)

            now = self.clock()
            self._remember_details(event)
            contrib = self.scorer.add_event(event.type, event.zone, event.id, now)
            self.scorer.correlate(now)
            if contrib and event.zone in NON_PHYSICAL_ZONES:
                # Only a network-sensor event names an attacker: a physical event (a water leak, a
                # smoke alarm) also carries a src_ip, but that is the sensor, not a source to drop.
                # Only an inbound flow's source may be blocked: an outbound flow's source is one of
                # our own devices. `direction` arrives as data, so normalize it (a raw string
                # compare let "Outbound" through) and keep the cautious reading: not-outbound.
                direction = str(event.data.get("direction") or "").strip().lower()
                src_ip = event.data.get("src_ip")
                spoofed_to_itself = (isinstance(src_ip, str)
                                     and src_ip.strip() == str(event.data.get("dst_ip") or "").strip())
                if direction != "outbound":
                    ip = attacker_ip(src_ip, self.policy.never_block, self.protected_ips)
                    if ip and not spoofed_to_itself:            # a flow to itself is not a source
                        self.attackers.setdefault(ip, (event.type, event.zone))
            physical = event.zone not in NON_PHYSICAL_ZONES
            if physical and event.type in self.policy.life_safety:
                self.episodes.setdefault(event.zone, Episode(event.zone)).life_safety = True

            for zone in self.scorer.zones(now):
                ep = self.episodes.setdefault(zone, Episode(zone))
                score = self.scorer.score(now, zone)
                level = self.policy.level_for(score)
                if ep.incident is None and self.policy.rank(level) >= 1:
                    self._open_incident(ep, event, now)
                inc = ep.incident
                if inc is not None:
                    if contrib and contrib.zone in (zone, "network") \
                            and contrib.event_id not in inc.event_ids:
                        inc.event_ids.append(contrib.event_id)
                        while len(inc.event_ids) > MAX_INCIDENT_EVENTS:
                            inc.event_ids.pop(0)          # a long incident must not grow without bound
                    inc.peak = max(inc.peak, score)
                mine = event if event.zone == zone else None
                self._respond(ep, level if inc else "low", mine,
                              inc.id if inc else f"event:{event.type}")
            self._note_block_result(event)
            self._publish_state(now)

    def _note_block_result(self, event: Event) -> None:
        """Closes the loop: cyber says whether a block we asked for really happened (CONTRACT 3.1)."""
        if event.type not in ("cyber.block_applied", "cyber.block_refused"):
            return
        ip = event.data.get("ip")
        if ip not in self.attackers:
            return
        if event.type == "cyber.block_applied":
            text = f"block confirmed -> {ip}" + (" (dry run, nothing enforced)" if event.data.get("dry_run") else "")
        else:
            text = f"block refused -> {ip} ({str(event.data.get('reason', 'unknown'))[:40]})"
        for ep in self.episodes.values():
            if ep.incident is not None and self._once(ep, "block_result", event.type, ip):
                self._note(ep, "block_ip", text, record=False)

    def _remember_details(self, event: Event) -> None:
        """Keep the IPS details of an alert (sent by the adapter, or built here) until its incident is published."""
        if event.type not in IPS_TYPES:
            return
        details = clean_details(event.data.get("details"))
        if details is None and self.ips is not None:
            details = self.ips.enrich(event)
        if details is not None:
            self._details[event.id] = details
            while len(self._details) > SEEN_DETAILS:
                self._details.popitem(last=False)

    def _incident_details(self, inc: Incident) -> dict | None:
        """The details of the strongest IPS alert in the incident."""
        found = [self._details[i] for i in inc.event_ids if i in self._details]
        return max(found, key=lambda d: d["ips_score"]) if found else None

    def _open_incident(self, ep: Episode, event: Event, now: float) -> None:
        stamp = datetime.fromtimestamp(now, timezone.utc).strftime("%Y%m%d-%H%M%S")
        ep.incident = Incident(id=f"incident-{stamp}-{uuid.uuid4().hex[:4]}", opened=now,
                               trigger=event.type,
                               event_ids=self.scorer.event_ids(ep.zone)[:MAX_INCIDENT_EVENTS])
        self._note(ep, "log", "incident opened")
        log.info("incident %s opened in %s by %s", ep.incident.id, ep.zone, event.type)

    # ------------------------------------------------------------------ responses
    def _respond(self, ep: Episode, level: str, event: Event | None, reason: str) -> None:
        names: list[tuple[str, str]] = []
        for lvl in LEVELS[1:self.policy.rank(level) + 1]:
            names += [(a, lvl) for a in self.policy.responses[lvl]]
        if event is not None:
            names += [(a, "event") for a in self.policy.event_actions.get(event.type, ())]
        names.sort(key=lambda item: item[0] == "notify")        # notify last: it reports the rest
        for name, scope in names:
            getattr(self, f"_do_{name}")(ep, reason, scope, level)

    def _note(self, ep: Episode, action: str, text: str, record: bool = True) -> None:
        inc = ep.incident
        if inc is None:
            return
        if record and action not in inc.actions:
            inc.actions.append(action)
        inc.notes.append(text)

    @staticmethod
    def _once(ep: Episode, *key: str) -> bool:
        if key in ep.done:
            return False
        ep.done.add(key)
        return True

    def _command(self, device: tuple[str, str, str], action: str, reason: str) -> None:
        zone, dtype, did = device
        payload = {"id": uuid.uuid4().hex, "ts": iso(self.clock()), "action": action,
                   "reason": reason, "requested_by": "engine"}
        self._publish(topics.device_cmd(zone, dtype, did), payload, False)

    def _send_to(self, ep: Episode, action_name: str, dtype: str, command: str,
                 zone: str | None, reason: str) -> None:
        targets = self.registry.find(dtype, zone)
        if not targets:
            self._note(ep, action_name, f"{action_name}: no reachable {dtype} known", record=False)
            return
        done_any = []
        for device in targets:
            if self._once(ep, action_name, device[2]):
                self._command(device, command, reason)
                done_any.append(device[2])
                if action_name == "siren":
                    ep.sirens_on.append(device)
        if done_any:
            self._note(ep, action_name, f"{action_name} -> {', '.join(done_any)}")

    def _do_log(self, ep: Episode, reason: str, scope: str, level: str) -> None:
        if ep.incident and "log" not in ep.incident.actions:
            ep.incident.actions.append("log")

    def _do_notify(self, ep: Episode, reason: str, scope: str, level: str) -> None:
        if not ep.incident or not self._once(ep, "notify", level):
            return
        summary = self._summary(ep, ep.incident, level)
        channels = self.notifier.send(f"{level.upper()} risk in {ep.zone}", summary, level)
        self._note(ep, "notify", f"notify via {','.join(channels)} ({level})")

    def _do_lights_on(self, ep: Episode, reason: str, scope: str, level: str) -> None:
        if ep.zone in NON_PHYSICAL_ZONES:       # a network attack has no room to light up
            return
        self._send_to(ep, "lights_on", "bulb", "on", ep.zone, reason)

    def _do_siren(self, ep: Episode, reason: str, scope: str, level: str) -> None:
        if ep.zone in NON_PHYSICAL_ZONES:       # nobody is in the house because of a port scan
            return
        self._send_to(ep, "siren", "siren", "on", None, reason)

    def _do_close_valve(self, ep: Episode, reason: str, scope: str, level: str) -> None:
        self._send_to(ep, "close_valve", "valve", "close", ep.zone, reason)

    def _do_unlock_doors(self, ep: Episode, reason: str, scope: str, level: str) -> None:
        """Only when people may have to get out (fire, smoke, gas). An intruder gets no help:
        for an intrusion at Critical the doors are left exactly as they are."""
        if not ep.life_safety:
            if self._once(ep, "unlock_doors", "skipped"):
                self._note(ep, "unlock_doors", "doors left as they are: no fire/smoke/gas involved",
                           record=False)
            return
        self._send_to(ep, "unlock_doors", "lock", "unlock", None, reason)

    def _do_block_ip(self, ep: Episode, reason: str, scope: str, level: str) -> None:
        # Only the sources that belong to THIS incident's zone (or to the shared network zone) may
        # be dropped: without the filter a kitchen water leak's src_ip got blocked by a later,
        # unrelated network incident and vice versa.
        for ip, (event_type, zone) in self.attackers.items():
            if zone not in (ep.zone, "network"):
                continue
            if ip not in self.blocked:
                self.blocked.add(ip)
                self._publish(topics.BLOCK, {
                    "id": uuid.uuid4().hex, "ts": iso(self.clock()), "ip": ip,
                    "reason": event_type, "window_seconds": self.policy.block_window_s}, False)
            if self._once(ep, "block_ip", ip):             # recorded once per zone's incident
                self._note(ep, "block_ip", f"block_ip -> {ip} ({event_type})")

    # ------------------------------------------------------------------ time
    def reset_zones(self, zones: Iterable[str]) -> None:
        """Publish a retained risk 0 for every known zone (called once at start-up).

        Retained snapshots survive broker restarts, so without this the dashboard keeps showing
        the risk of the previous run until new events arrive for that zone.
        """
        with self.lock:
            now = self.clock()
            for zone in zones:
                self._publish_risk(Episode(zone), 0, "low", now, [], ())
            self._baseline = True

    def tick(self, now: float | None = None) -> None:
        """Called every few seconds: expire old events and close a zone's incident at risk 0."""
        with self.lock:
            now = self.clock() if now is None else now
            live = set(self.scorer.zones(now))
            for zone in list(self.episodes):
                if zone not in live or self.scorer.score(now, zone) == 0:
                    self._close_episode(self.episodes[zone], now)
            self._publish_state(now)

    def _close_episode(self, ep: Episode, now: float) -> None:
        inc = ep.incident
        if inc is not None:
            for device in ep.sirens_on:                     # silence what we started
                self._command(device, "off", inc.id)
            inc.closed = True
            self._note(ep, "log", "incident closed: risk decayed to 0", record=False)
            self._publish_incident(ep, inc, now)
            log.info("incident %s closed", inc.id)
            ep.incident = None
        self._publish_risk(ep, 0, "low", now, [], ())
        del self.episodes[ep.zone]
        if not self.episodes:
            self.attackers.clear()
            self.blocked.clear()

    # ------------------------------------------------------------------ publishing
    def _summary(self, ep: Episode, inc: Incident, level: str) -> str:
        types = list(dict.fromkeys(f["type"] for f in self.scorer.factors(ep.zone, 8)))
        what = ", ".join(types[:6]) or "no live events"
        text = f"{level.capitalize()} risk {inc.peak} in {ep.zone}: {what}."
        acted = [a for a in inc.actions if a not in ("log", "notify")]
        if acted:
            text += " Actions: " + ", ".join(acted) + "."
        done = [n for n in inc.notes if "->" in n]
        if done:
            text += " " + "; ".join(done[-6:]) + "."
        if inc.closed:
            text += " Closed: risk decayed to 0."
        return text[:3900]

    def _publish_incident(self, ep: Episode, inc: Incident, now: float) -> None:
        level = self.policy.level_for(inc.peak)
        inc.details = self._incident_details(inc)
        state = (inc.peak, tuple(inc.event_ids), tuple(inc.actions), inc.closed, len(inc.notes),
                 json.dumps(inc.details, sort_keys=True) if inc.details else None)
        if state == inc.published:
            return
        inc.published = state
        message = {"id": inc.id, "ts": iso(now), "zone": ep.zone, "level": level, "score": inc.peak,
                   "trigger": inc.trigger, "events": inc.event_ids[:MAX_INCIDENT_EVENTS],
                   "actions": list(inc.actions), "summary": self._summary(ep, inc, level)}
        if inc.details:
            message["details"] = inc.details
        self._publish(topics.INCIDENTS, message, False)

    def _publish_risk(self, ep: Episode, score: int, level: str, now: float, factors: list,
                      actions: tuple) -> None:
        state = (score, level, actions)
        if state == ep.risk_sent:
            return
        ep.risk_sent = state
        self._publish(topics.RISK, {"ts": iso(now), "zone": ep.zone, "level": level,
                                    "score": score, "factors": factors,
                                    "actions": list(actions)}, True)

    def _publish_state(self, now: float) -> None:
        if not self.episodes and not self._baseline:        # a first retained "all quiet"
            self._baseline = True
            self._publish(topics.RISK, {"ts": iso(now), "zone": "network", "level": "low",
                                        "score": 0, "factors": [], "actions": []}, True)
        self._baseline = self._baseline or bool(self.episodes)
        for zone, ep in list(self.episodes.items()):
            score = self.scorer.score(now, zone)
            level = self.policy.level_for(score)
            inc = ep.incident
            if inc is not None:
                self._publish_incident(ep, inc, now)
            self._publish_risk(ep, score, level, now, self.scorer.factors(zone),
                               tuple(inc.actions) if inc else ())
