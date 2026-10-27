import json
import os
import shutil

import pytest
from conftest import FakeClock

from cyb.blocks import BlockManager
from cyb.firewall import (
    CHAIN,
    BlocklistFirewall,
    FirewallError,
    IptablesFirewall,
    make_firewall,
    run_command,
)
from cyb.util import parse_networks


class FakeRunner:
    """Records argv lists; `rules` plays the kernel's rule table."""

    def __init__(self, fail_on: str = "") -> None:
        self.calls, self.rules, self.fail_on, self.chain_exists = [], set(), fail_on, False

    def __call__(self, cmd):
        self.calls.append(cmd)
        binary, flag = cmd[0], cmd[1]
        if self.fail_on and self.fail_on in " ".join(cmd):
            return 1, "boom"
        if flag == "-N":
            if self.chain_exists:
                return 1, "iptables: Chain already exists."
            self.chain_exists = True
            return 0, ""
        if flag == "-F":
            self.rules = {r for r in self.rules if not (r[0] == binary and r[1][0] == CHAIN)}
            return 0, ""
        key = (binary, tuple(cmd[2:]))
        if flag == "-C":
            return (0, "") if key in self.rules else (1, "no such rule")
        if flag == "-A":
            self.rules.add(key)
            return 0, ""
        if flag == "-I":                                  # -I HOOK 1 -j CHAIN
            self.rules.add((binary, (cmd[2], *cmd[4:])))
            return 0, ""
        if flag == "-D":
            self.rules.discard(key)
            return 0, ""
        return 1, "unexpected"


def test_iptables_setup_creates_chain_and_hooks_once():
    run = FakeRunner()
    fw = IptablesFirewall(run)
    fw.setup()
    fw.setup()                                                # idempotent
    assert ["iptables", "-N", CHAIN] in run.calls
    for hook in ("INPUT", "FORWARD"):
        inserted = [c for c in run.calls if c[:5] == ["iptables", "-I", hook, "1", "-j"]]
        assert len(inserted) == 1


def test_iptables_block_and_unblock_are_idempotent_and_use_the_right_binary():
    run = FakeRunner()
    fw = IptablesFirewall(run)
    fw.block("203.0.113.9")
    fw.block("203.0.113.9")
    fw.block("2001:db8::1")
    adds = [c for c in run.calls if c[1] == "-A"]
    assert adds == [["iptables", "-A", CHAIN, "-s", "203.0.113.9", "-j", "DROP"],
                    ["ip6tables", "-A", CHAIN, "-s", "2001:db8::1", "-j", "DROP"]]
    fw.unblock("203.0.113.9")
    fw.unblock("203.0.113.9")
    assert not any("203.0.113.9" in r[1] for r in run.rules)


@pytest.mark.parametrize("bad", ["-j ACCEPT", "1.2.3.4; reboot", "--help", "", "1.2.3.0/24",
                                 "example.com"])
def test_iptables_never_lets_a_value_become_an_option(bad):
    run = FakeRunner()
    fw = IptablesFirewall(run)
    with pytest.raises(FirewallError):
        fw.block(bad)
    with pytest.raises(FirewallError):
        fw.unblock(bad)
    assert run.calls == []


def test_iptables_errors_are_reported():
    with pytest.raises(FirewallError):
        IptablesFirewall(FakeRunner(fail_on="-A")).block("203.0.113.9")
    with pytest.raises(FirewallError):
        IptablesFirewall(FakeRunner(fail_on="-F")).setup()


def test_missing_binary_is_a_firewall_error():
    with pytest.raises(FirewallError):
        run_command(["definitely-not-a-real-binary-xyz", "-L"])


def test_backend_factory():
    assert isinstance(make_firewall("blocklist"), BlocklistFirewall)
    assert isinstance(make_firewall("iptables"), IptablesFirewall)
    with pytest.raises(ValueError):
        make_firewall("yolo")


class Recorder:
    def __init__(self):
        self.items = []

    def __call__(self, type_, severity, data):
        self.items.append((type_, severity, data))


def manager(tmp_path, clock=None, **kw):
    rec, fw = Recorder(), kw.pop("fw", BlocklistFirewall())
    args = {"default_s": 3600, "min_s": 30, "max_s": 86400, "max_blocks": 256,
            "never_block": parse_networks("127.0.0.0/8,192.168.1.1")}
    args.update(kw)
    mgr = BlockManager(fw, tmp_path / "blocklist.json", rec, clock=clock or FakeClock(), **args)
    mgr.restore()
    return mgr, fw, rec


def cmd(**kw):
    body = {"id": "abc123456", "ts": "2026-10-11T10:00:00Z", "ip": "203.0.113.9",
            "reason": "cyber.port_scan", "window_seconds": 3600}
    body.update(kw)
    return json.dumps(body)


def test_valid_engine_command_blocks_persists_and_confirms(tmp_path):
    mgr, fw, rec = manager(tmp_path)
    assert mgr.handle_command(cmd()) is True
    assert fw.blocked == {"203.0.113.9"}
    ((type_, sev, data),) = rec.items
    assert type_ == "cyber.ip_blocked" and sev == "high"
    assert data["ip"] == "203.0.113.9" and data["reason"] == "cyber.port_scan"
    assert data["blocked_by"] == "engine" and data["window_s"] == 3600 and "expires_at" in data
    saved = json.loads((tmp_path / "blocklist.json").read_text())
    assert saved["blocks"][0]["ip"] == "203.0.113.9"
    assert (tmp_path / "blocklist.json").stat().st_mode & 0o004          # world-readable


def test_duplicate_delivery_and_repeat_blocks_do_not_reconfirm(tmp_path):
    clock = FakeClock()
    mgr, fw, rec = manager(tmp_path, clock)
    assert mgr.handle_command(cmd())
    assert mgr.handle_command(cmd())                                   # same id (QoS 1 redelivery)
    clock.advance(100)
    assert mgr.handle_command(cmd(id="other-id-1"))                    # new id, already blocked
    assert len(rec.items) == 1
    assert mgr.blocks["203.0.113.9"].expires_at == 1100 + 3600         # extended, not shortened


@pytest.mark.parametrize("payload", [
    "not json", "[]", '"x"', "null", "{}", '{"ip": "1.2.3.4", "id": 5}',
    json.dumps({"id": "i" * 100, "ip": "1.2.3.4"}),
    json.dumps({"id": "abc12345", "ip": "-j ACCEPT"}),
    json.dumps({"id": "abc12345", "ip": "10.0.0.0/8"}),
    json.dumps({"id": "abc12345", "ip": ["1.2.3.4"]}),
    json.dumps({"id": "abc12345", "ip": "127.0.0.1"}),                 # loopback
    json.dumps({"id": "abc12345", "ip": "192.168.1.1"}),               # never_block (gateway)
    json.dumps({"id": "abc12345", "ip": "169.254.1.1"}),
    json.dumps({"id": "abc12345", "ip": "224.0.0.1"}),
    json.dumps({"id": "abc12345", "ip": "1.2.3.4", "action": "reboot"}),
    "x" * 5000])
def test_hostile_or_invalid_commands_change_nothing(tmp_path, payload):
    mgr, fw, rec = manager(tmp_path)
    assert mgr.handle_command(payload) is False
    assert fw.blocked == set() and rec.items == [] and mgr.blocks == {}


def test_bytes_payloads_work_like_mqtt_delivers_them(tmp_path):
    mgr, fw, _ = manager(tmp_path)
    assert mgr.handle_command(cmd(ip="203.0.113.50").encode())
    assert "203.0.113.50" in fw.blocked


@pytest.mark.parametrize("window,expected", [(1, 30), (10**9, 86400), (-5, 30), (0, 30),
                                             (120, 120)])
def test_block_window_is_clamped(tmp_path, window, expected):
    mgr, _, rec = manager(tmp_path)
    assert mgr.handle_command(cmd(window_seconds=window))
    assert rec.items[0][2]["window_s"] == expected


@pytest.mark.parametrize("window", [None, "soon", True])
def test_missing_or_bad_window_uses_the_default(tmp_path, window):
    mgr, _, rec = manager(tmp_path)
    body = json.loads(cmd())
    body["window_seconds"] = window
    assert mgr.handle_command(json.dumps(body))
    assert rec.items[0][2]["window_s"] == 3600


def test_blocks_expire_and_are_confirmed(tmp_path):
    clock = FakeClock()
    mgr, fw, rec = manager(tmp_path, clock)
    mgr.handle_command(cmd(window_seconds=60))
    clock.advance(59)
    mgr.tick()
    assert fw.blocked == {"203.0.113.9"}
    clock.advance(2)
    mgr.tick()
    assert fw.blocked == set() and mgr.blocks == {}
    assert [r[0] for r in rec.items] == ["cyber.ip_blocked", "cyber.ip_unblocked"]
    assert json.loads((tmp_path / "blocklist.json").read_text())["blocks"] == []


def test_admin_unblock_command(tmp_path):
    mgr, fw, rec = manager(tmp_path)
    mgr.handle_command(cmd())
    assert mgr.handle_command(cmd(id="unblock-1", action="unblock"))
    assert fw.blocked == set() and rec.items[-1][0] == "cyber.ip_unblocked"
    assert mgr.handle_command(cmd(id="unblock-2", action="unblock")) is False   # nothing to do


def test_blocks_survive_a_restart_and_expired_ones_do_not(tmp_path):
    clock = FakeClock()
    mgr, _, _ = manager(tmp_path, clock)
    mgr.handle_command(cmd(ip="203.0.113.1", window_seconds=600, id="one-12345"))
    mgr.handle_command(cmd(ip="203.0.113.2", window_seconds=60, id="two-12345"))
    clock.advance(120)
    mgr2, fw2, rec2 = manager(tmp_path, clock)                           # "restart"
    assert set(mgr2.blocks) == {"203.0.113.1"} and fw2.blocked == {"203.0.113.1"}
    assert rec2.items == []                                              # restoring is silent


def test_a_damaged_state_file_is_survivable(tmp_path):
    for text in ("{{{", "[]", '{"blocks": "x"}', '{"blocks": [1, null, {"ip": 5}]}'):
        (tmp_path / "blocklist.json").write_text(text, encoding="utf-8")
        mgr, _, _ = manager(tmp_path)
        assert mgr.blocks == {}


def test_state_for_a_now_protected_address_is_not_restored(tmp_path):
    clock = FakeClock()
    (tmp_path / "blocklist.json").write_text(json.dumps({"blocks": [
        {"ip": "192.168.1.1", "reason": "x", "blocked_at": 0, "expires_at": 5000, "by": "x"},
        {"ip": "127.0.0.1", "reason": "x", "blocked_at": 0, "expires_at": 5000, "by": "x"},
        {"ip": "203.0.113.7", "reason": "x", "blocked_at": 0, "expires_at": 5000, "by": "x"}]}))
    mgr, _, _ = manager(tmp_path, clock)
    assert set(mgr.blocks) == {"203.0.113.7"}


def test_the_number_of_blocks_is_capped(tmp_path):
    mgr, fw, _ = manager(tmp_path, max_blocks=3)
    for i in range(1, 6):
        mgr.handle_command(cmd(ip=f"203.0.113.{i}", id=f"id-{i}-12345"))
    assert len(mgr.blocks) == 3 and len(fw.blocked) == 3


def test_a_failing_firewall_never_records_a_block_that_does_not_exist(tmp_path):
    class Broken(BlocklistFirewall):
        def block(self, ip):
            raise FirewallError("netfilter said no")

    mgr, _, rec = manager(tmp_path, fw=Broken())
    assert mgr.handle_command(cmd()) is False
    assert mgr.blocks == {} and rec.items == []
    assert mgr.handle_command(cmd()) is False            # not marked "seen": it can be retried


def test_a_failed_unblock_is_retried_on_the_next_tick(tmp_path):
    clock = FakeClock()

    class Flaky(BlocklistFirewall):
        fail = True

        def unblock(self, ip):
            if self.fail:
                raise FirewallError("busy")
            super().unblock(ip)

    mgr, fw, rec = manager(tmp_path, clock, fw=Flaky())
    mgr.handle_command(cmd(window_seconds=30))
    clock.advance(31)
    mgr.tick()
    assert "203.0.113.9" in mgr.blocks                   # still tracked, will retry
    fw.fail = False
    mgr.tick()
    assert mgr.blocks == {} and rec.items[-1][0] == "cyber.ip_unblocked"


def test_unwritable_state_file_does_not_crash(tmp_path):
    mgr, fw, _ = manager(tmp_path)
    mgr.state_file = tmp_path / "missing-dir" / "x" / "blocklist.json"
    mgr.state_file.parent.parent.write_text("a file, not a directory", encoding="utf-8")
    assert mgr.handle_command(cmd())                      # still enforced in memory
    assert "203.0.113.9" in fw.blocked


def test_iptables_roundtrip():
    """setup -> block -> unblock against the real kernel when run as root with iptables
    (Linux/CI: set CYBER_TEST_REAL_IPTABLES=1); otherwise the exact same roundtrip runs against
    an in-process rule-table emulator, so the default suite is green on every OS."""
    probe = ["iptables", "-C", CHAIN, "-s", "203.0.113.77", "-j", "DROP"]
    if os.environ.get("CYBER_TEST_REAL_IPTABLES") and shutil.which("iptables"):
        fw, run = IptablesFirewall(), run_command
    else:
        run = FakeRunner()
        fw = IptablesFirewall(run)
    fw.setup()
    fw.block("203.0.113.77")
    assert run(probe)[0] == 0
    fw.unblock("203.0.113.77")
    assert run(probe)[0] != 0
