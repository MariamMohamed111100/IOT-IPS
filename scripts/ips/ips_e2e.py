#!/usr/bin/env python3
"""End-to-end test of the simulated IPS lab (Task 8), modeled on scripts/demo_incident.py.

    docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d --build --wait
    python scripts/ips/ips_e2e.py [--attack all]

What it does: listens on the WebSocket, runs the attacker container (nmap port scan, hydra brute force
on RTSP, hping3 SYN flood) against the lab camera, then checks THROUGH THE REST API (after logging in) that
  1. the real sensor (lab_gateway = ips_cyber on live traffic) raised the three alert types for the attacker,
     each with MITRE technique, IPS score and both reports;
  2. the normal client raised no alert (no false alarm);
  3. the engine opened ONE incident in zone `network`, High or Critical, holding those events;
  4. the incident's timeline lists the events;
  5. the WebSocket pushed that incident.
Exit code 0 = everything arrived. No Docker/stack: use the unit tests of this logic (ips/tests/test_lab_e2e_logic.py).
"""
from __future__ import annotations

import argparse
import json
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

ATTACKER, CLIENT, CAMERA = "10.77.0.66", "10.77.0.20", "10.77.0.10"
ALERT_TYPES = ("cyber.port_scan", "cyber.brute_force", "cyber.dos")
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.lab.yml"]


def run_attack(name: str) -> None:
    """Run `attack <name>` in the attacker container (it refuses anything outside the lab network)."""
    r = subprocess.run([*COMPOSE, "exec", "-T", "lab_attacker", "attack", name], cwd=ROOT,
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        sys.exit("attack %s failed (is the lab up?):\n%s" % (name, (r.stdout + r.stderr)[-800:]))


class WsListener:
    """Collects the `incident` messages the API pushes to dashboards."""

    def __init__(self, base: str, ca: str, token_fn) -> None:
        self.base, self.ca, self.token_fn = base, ca, token_fn
        self.incidents: list[dict] = []
        self.ready = threading.Event()
        self.error: str | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()
        self.ready.wait(15)

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        try:
            from websockets.sync.client import connect
        except ImportError:
            self.error = "pip install websockets"
            self.ready.set()
            return
        ctx = ssl.create_default_context(cafile=self.ca)
        url = self.base.replace("https://", "wss://") + "/ws/events"
        try:
            with connect(url, ssl=ctx, subprotocols=["bearer." + self.token_fn()]) as ws:
                self.ready.set()
                while not self._stop.is_set():
                    try:
                        msg = json.loads(ws.recv(timeout=1))
                    except TimeoutError:
                        continue
                    if isinstance(msg, dict) and msg.get("kind") == "incident":
                        self.incidents.append(msg["data"])
        except Exception as exc:                       # reported by the check below
            self.error = str(exc)
            self.ready.set()


def play(t, ws, attack, *, attacks=("all",), wait_s: float = 150, out=print, sleep=time.sleep) -> list[str]:
    """Run the scenario. `t.api(method, path, params=...)` -> (status, json); `ws.incidents` -> pushed incidents;
    `attack(name)` runs one attack. Returns the failed checks (empty = all good)."""
    failures: list[str] = []

    def check(name: str, ok: bool) -> bool:
        out(("  PASS  " if ok else "  FAIL  ") + name)
        if not ok:
            failures.append(name)
        return ok

    def body(path, **params):
        status, data = t.api("GET", path, params=params or None)
        return data if status == 200 else None

    out("== IPS lab end-to-end: attacker %s -> camera %s ==" % (ATTACKER, CAMERA))
    check("the WebSocket is connected", ws.ready.is_set() and ws.error is None)
    known = {e["id"] for e in body("/events", limit=500, source="cyber") or []}
    for name in attacks:
        out("  attack: %s" % name)
        attack(name)

    def new_alerts():
        rows = body("/events", limit=500, source="cyber") or []
        return [e for e in rows if e["id"] not in known and e["type"] in ALERT_TYPES
                and (e.get("data") or {}).get("src_ip") == ATTACKER]

    started = time.time()
    deadline, found, first_seen = started + wait_s, {}, {}
    while time.time() < deadline:
        found = {e["type"]: e for e in new_alerts()}
        for kind in found:
            first_seen.setdefault(kind, round(time.time() - started, 1))
        if set(ALERT_TYPES) <= set(found):
            break
        sleep(3)
    for kind in ALERT_TYPES:
        check("sensor alert %s for the attacker arrived%s" % (kind, " after %.1f s" % first_seen[kind] if kind in first_seen else ""),
              kind in found)
    for kind, e in found.items():
        det = (e.get("data") or {}).get("details") or {}
        rep = det.get("reports") or {}
        check("%s carries MITRE %s, IPS score and both reports" % (kind, det.get("mitre_technique")),
              bool(det.get("mitre_technique")) and det.get("ips_score") is not None
              and bool(rep.get("technical")) and bool(rep.get("executive")))
        check("%s has zone network and the attacker as source" % kind, e["zone"] == "network")
    by_detector = {}
    for e in found.values():
        d = (e.get("data") or {}).get("detector", "unknown")
        by_detector[d] = by_detector.get(d, 0) + 1
    out("  info  alerts by detector: %s" % (by_detector or "none"))
    false_alarms = [e for e in body("/events", limit=500, source="cyber") or []
                    if e["id"] not in known and (e.get("data") or {}).get("src_ip") == CLIENT
                    and e["type"] in (*ALERT_TYPES, "cyber.unexpected_traffic")
                    and (e.get("data") or {}).get("detector") != "ml"]
    check("the normal client raised no alert (%d)" % len(false_alarms), not false_alarms)

    wanted = {e["id"] for e in found.values()}

    def incident():
        for row in body("/incidents", limit=50) or []:
            if row["zone"] == "network" and len(wanted & set(row["events"])) >= max(1, len(wanted)):
                return row
        return None

    inc = None
    for _ in range(40):
        inc = incident()
        if inc or not wanted:
            break
        sleep(1)
    if check("one incident in zone network holds the alerts", inc is not None) and inc:
        check("incident level is high or critical (%s, score %s)" % (inc["level"], inc["score"]),
              inc["level"] in ("high", "critical"))
        timeline = body("/incidents/%s/events" % inc["id"]) or []
        check("the incident timeline lists the alerts", wanted <= {e["id"] for e in timeline})
        pushed = False
        for _ in range(20):
            pushed = any(m.get("id") == inc["id"] for m in ws.incidents)
            if pushed:
                break
            sleep(1)
        check("the WebSocket pushed the incident", pushed)
    out("\n" + ("LAB E2E OK: everything arrived." if not failures else "LAB E2E FAILED: %d problem(s)." % len(failures)))
    return failures


def main(argv=None) -> int:
    from ips_transport import add_transport_args, make_transport
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_transport_args(p)
    p.add_argument("--attack", default="all", choices=["scan", "brute", "dos", "all"])
    p.add_argument("--wait", type=float, default=150, help="seconds to wait for the alerts")
    a = p.parse_args(argv)
    a.mode = "docker"
    # Start from a clean engine/cyber so repeated runs do not inherit stale risk/incident/firewall state.
    subprocess.run([*COMPOSE, "exec", "-T", "cyber", "rm", "-f", "/data/blocklist.json"], cwd=ROOT, capture_output=True)
    subprocess.run([*COMPOSE, "restart", "engine", "cyber"], cwd=ROOT, capture_output=True)
    time.sleep(4)
    t = make_transport(a)
    t.api("GET", "/devices")                                   # logs in once
    ws = WsListener(a.base.rstrip("/"), a.ca, lambda: t.token)
    ws.start()
    try:
        failures = play(t, ws, run_attack, attacks=(a.attack,), wait_s=a.wait)
    finally:
        ws.stop()
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
