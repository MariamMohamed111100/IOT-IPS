"""Closed loop with the REAL engine: cyber event -> score -> system/block -> cyber blocks."""
import json
import sys
from dataclasses import replace

from conftest import REPO, alert, feed_scan

# append, not insert(0): services/engine has its own main.py that must not shadow ours
sys.path.append(str(REPO / "services/engine"))

from cyb.config import SID_PORT_SCAN  # noqa: E402
from cyb.service import CyberService  # noqa: E402
from eng.core import Engine  # noqa: E402
from eng.notify import Notifier  # noqa: E402
from eng.policy import load_policy  # noqa: E402
from smartsecure_common import make_event  # noqa: E402


class Loop:
    """Wires cyber's sink into the engine and the engine's system/block back into cyber."""

    def __init__(self, settings, clock) -> None:
        self.out = []
        self.engine = Engine(load_policy(REPO / "config/risk_scores.yaml"),
                             lambda tp, p, r: self.out.append((tp, p, r)),
                             notifier=Notifier(background=False), clock=clock)
        loop = self

        class Sink:
            def publish(self, event):
                loop.engine.on_message("security/alerts/cyber", event.model_dump_json())

        self.cyber = CyberService(settings, Sink(), clock=clock)
        self.cyber.restore()

    def block_commands(self):
        return [p for tp, p, _ in self.out if tp == "system/block"]

    def deliver_blocks(self):
        for cmd in self.block_commands():
            self.cyber.handle_block(json.dumps(cmd))

    def physical(self, type_, zone="garage"):
        ev = make_event("sim", type_, zone, "medium", sensor_id="x")
        self.engine.on_message(f"home/{zone}/pir/pir_{zone}/event", ev.model_dump_json())


def test_scan_alone_is_blocked_by_cyber_before_the_engine_has_anything_to_say(
        settings, clock):
    loop = Loop(settings, clock)
    feed_scan(loop.cyber, clock)
    assert "192.168.1.15" in loop.cyber.blocks.blocks
    assert loop.block_commands() == []          # a lone scan never reaches High: no engine action


def test_engine_block_command_is_executed_and_the_confirmation_is_not_scored_or_reblocked(
        settings, clock):
    loop = Loop(replace(settings, autoblock=()), clock)      # only the engine may block
    loop.physical("motion.night")
    loop.physical("face.unknown")
    feed_scan(loop.cyber, clock)                             # 20 + 40 + 25 = 85 = High
    (cmd,) = loop.block_commands()
    assert cmd["ip"] == "192.168.1.15" and cmd["reason"] == "cyber.port_scan"
    assert loop.cyber.blocks.blocks == {}
    loop.deliver_blocks()
    assert "192.168.1.15" in loop.cyber.blocks.blocks
    assert len(loop.block_commands()) == 1                   # cyber.ip_blocked caused no new block
    assert loop.cyber.blocks.blocks["192.168.1.15"].by == "engine"


def test_a_spoofed_loopback_scan_never_becomes_a_block(settings, clock):
    loop = Loop(settings, clock)
    for p in range(1, 40):
        loop.cyber.process_record(alert(SID_PORT_SCAN, src="127.0.0.1", port=p), clock())
    clock.advance(3)
    loop.cyber.tick(clock())
    assert loop.cyber.blocks.blocks == {} and loop.block_commands() == []
