"""
test_actions.py - tests for actions.py.

Run:   python -m unittest -v test_actions
"""

import ipaddress
import json
import os
import re
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from iot_ips import actions
from iot_ips.actions import ActionExecutor, build_commands, format_command, undo_argv
from iot_ips.paths import PACKAGE_DIR

ALLOW = tuple(ipaddress.ip_network(n) for n in ("192.168.1.1/32", "192.168.1.2/32", "10.0.0.0/8"))
LOG_KEYS = {"ts", "seq", "action", "status", "note", "dry_run", "device_id", "rule_id", "level",
            "target", "commands", "undo", "expires_in_s"}
CMD_RE = re.compile(r"^ip6?tables -[ID] FORWARD -[sd] [0-9a-f:.]+ -m comment --comment iot-ips(-temp)? -j DROP$")


class FakeClock:
    def __init__(self, start=1_800_000_000.0):
        self.now = start

    def __call__(self):
        return self.now


def decision(acts, src="203.0.113.5", dev_ip="192.168.1.50", dev_id="CAM-001", level="Critical", rule="critical_certain", skipped=None):
    return {"action": acts, "targets": {"src_ip": src, "device_ip": dev_ip, "device_id": dev_id},
            "level": level, "rule_id": rule, "skipped": skipped or []}


def make(**kw):
    kw.setdefault("allow_list", ALLOW)
    return ActionExecutor(**kw)


def acl(path):
    """The file's ACL text on Windows (POSIX mode bits are checked directly instead)."""
    return subprocess.run(["icacls", path], capture_output=True, text=True, check=False).stdout


class TestCommands(unittest.TestCase):
    def test_block_command_is_exact(self):
        ip = ipaddress.ip_address("203.0.113.5")
        argv = build_commands("block_source", src_ip=ip)[0]
        self.assertEqual(format_command(argv), "iptables -I FORWARD -s 203.0.113.5 -m comment --comment iot-ips -j DROP")
        self.assertEqual(format_command(undo_argv(argv)), "iptables -D FORWARD -s 203.0.113.5 -m comment --comment iot-ips -j DROP")

    def test_temporary_block_uses_its_own_comment(self):
        argv = build_commands("temporary_block", src_ip=ipaddress.ip_address("203.0.113.5"))[0]
        self.assertIn("iot-ips-temp", argv)

    def test_isolation_blocks_both_directions(self):
        cmds = build_commands("isolate_device", device_ip=ipaddress.ip_address("192.168.1.50"))
        self.assertEqual([c[3] for c in cmds], ["-s", "-d"])
        self.assertTrue(all("192.168.1.50" in c for c in cmds))

    def test_ipv6_uses_ip6tables(self):
        self.assertEqual(build_commands("block_source", src_ip=ipaddress.ip_address("2001:db8::1"))[0][0], "ip6tables")

    def test_bookkeeping_and_missing_addresses_give_no_command(self):
        for name in actions.BOOKKEEPING_ACTIONS:
            self.assertEqual(build_commands(name, src_ip=ipaddress.ip_address("203.0.113.5")), [])
        self.assertEqual(build_commands("block_source"), [])
        self.assertEqual(build_commands("isolate_device"), [])

    def test_printable_form_quotes_dangerous_parts(self):
        # even if a part ever contained shell characters, the logged form is quoted
        self.assertEqual(format_command(["echo", "a; rm -rf /"]), "echo 'a; rm -rf /'")

    def test_parse_ip(self):
        self.assertEqual(str(actions.parse_ip(" 192.168.1.5 ")), "192.168.1.5")
        self.assertEqual(str(actions.parse_ip("::ffff:192.168.1.5")), "192.168.1.5")
        for bad in (None, 5, "", "x", "1.2.3", "1.2.3.4/24", "1.2.3.4\n5", "1" * 100, ["1.2.3.4"], b"1.2.3.4"):
            self.assertIsNone(actions.parse_ip(bad), bad)


class TestExecutorBasics(unittest.TestCase):
    def test_real_execution_is_refused(self):
        for bad in (False, None, 0, "yes"):
            with self.assertRaises(ValueError):
                ActionExecutor(dry_run=bad)

    def test_bad_limits_are_refused(self):
        for kw in ({"temporary_block_seconds": 0}, {"temporary_block_seconds": 10 ** 6}, {"temporary_block_seconds": True},
                   {"max_active_blocks": 0}, {"max_active_blocks": "5"}, {"max_log_bytes": 10}):
            with self.subTest(kw=kw):
                with self.assertRaises(ValueError):
                    ActionExecutor(**kw)

    def test_bookkeeping_actions_are_simulated(self):
        ex = make()
        recs = ex.run(decision(["monitor", "log", "create_incident", "notify_admin"], level="Low", rule="low"))
        self.assertEqual([r["action"] for r in recs], ["monitor", "log", "create_incident", "notify_admin"])
        for r in recs:
            self.assertEqual((r["status"], r["note"], r["dry_run"], r["commands"], r["undo"]), ("simulated", "ok", True, [], []))
            self.assertEqual(set(r), LOG_KEYS)
            self.assertEqual((r["device_id"], r["rule_id"], r["level"]), ("CAM-001", "low", "Low"))
        self.assertEqual([r["seq"] for r in recs], [1, 2, 3, 4])

    def test_block_source_records_command_and_undo(self):
        ex = make()
        (rec,) = ex.run(decision(["block_source"]))
        self.assertEqual(rec["status"], "simulated")
        self.assertEqual(rec["target"], "203.0.113.5")
        self.assertEqual(rec["commands"], ["iptables -I FORWARD -s 203.0.113.5 -m comment --comment iot-ips -j DROP"])
        self.assertEqual(rec["undo"], ["iptables -D FORWARD -s 203.0.113.5 -m comment --comment iot-ips -j DROP"])
        self.assertIsNone(rec["expires_in_s"])
        self.assertIn("203.0.113.5", ex.active_blocks())

    def test_isolate_records_two_commands(self):
        ex = make()
        (rec,) = ex.run(decision(["isolate_device"]))
        self.assertEqual((rec["status"], len(rec["commands"]), len(rec["undo"])), ("simulated", 2, 2))
        self.assertEqual(ex.isolated_devices(), ["192.168.1.50"])

    def test_no_real_command_is_ever_executed(self):
        boom = mock.Mock(side_effect=AssertionError("a real command was started"))
        with mock.patch.object(subprocess, "run", boom), mock.patch.object(subprocess, "Popen", boom), \
                mock.patch.object(subprocess, "call", boom), mock.patch.object(subprocess, "check_output", boom), \
                mock.patch.object(os, "system", boom), mock.patch.object(os, "popen", boom):
            ex = make()
            ex.run(decision(["temporary_block", "block_source", "isolate_device", "notify_admin"]))
        boom.assert_not_called()

    def test_source_code_has_no_way_to_run_programs_or_open_connections(self):
        for name in ("actions.py", "policy.py"):
            with open(os.path.join(PACKAGE_DIR, name), "r", encoding="utf-8") as fh:
                source = fh.read()
            for forbidden in ("import subprocess", "from subprocess", "os.system", "os.popen", "os.exec", "os.spawn",
                              "import socket", "from socket", "eval(", "exec(", "pickle", "shell=True", "__import__"):
                self.assertNotIn(forbidden, source, "%s contains %r" % (name, forbidden))


class TestSafetyRules(unittest.TestCase):
    def test_allow_listed_sources_are_never_blocked(self):
        for src in ("192.168.1.1", "192.168.1.2", "10.4.5.6", "::ffff:192.168.1.1", " 192.168.1.1 "):
            for act in ("block_source", "temporary_block"):
                with self.subTest(src=src, action=act):
                    ex = make()
                    (rec,) = ex.run(decision([act], src=src))
                    self.assertEqual((rec["status"], rec["note"], rec["commands"]), ("skipped", "source_allow_listed", []))
                    self.assertEqual(ex.active_blocks(), {})

    def test_never_block_addresses(self):
        for src in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "255.255.255.255", "::1", "ff02::1", "fe80::1"):
            with self.subTest(src=src):
                ex = make()
                (rec,) = ex.run(decision(["block_source"], src=src))
                self.assertEqual((rec["status"], rec["note"]), ("skipped", "source_never_block"))
                self.assertEqual(rec["commands"], [])

    def test_missing_or_invalid_source_is_not_blocked(self):
        for src in (None, "", "not an ip", 12345, "1.2.3.4/24", "999.1.1.1"):
            with self.subTest(src=src):
                (rec,) = make().run(decision(["block_source"], src=src))
                self.assertEqual((rec["status"], rec["note"]), ("skipped", "no_valid_source"))

    def test_a_device_is_not_blocked_as_a_source_of_itself(self):
        (rec,) = make().run(decision(["block_source"], src="192.168.1.50", dev_ip="192.168.1.50"))
        self.assertEqual(rec["note"], "source_is_device")

    def test_isolation_rules(self):
        cases = {
            "8.8.8.8": "device_ip_not_private",       # a public address is never isolated
            "127.0.0.1": "device_ip_not_private",
            "192.168.1.1": "device_allow_listed",      # the router must stay reachable
            None: "no_valid_device_ip", "junk": "no_valid_device_ip",
        }
        for dev, note in cases.items():
            with self.subTest(dev=dev):
                (rec,) = make().run(decision(["isolate_device"], dev_ip=dev))
                self.assertEqual((rec["status"], rec["note"], rec["commands"]), ("skipped", note, []))

    def test_executor_rechecks_a_tampered_decision(self):
        """Even if policy.py were bypassed, the executor still refuses to block the router."""
        ex = make()
        recs = ex.run(decision(["block_source", "temporary_block", "isolate_device"], src="192.168.1.1", dev_ip="192.168.1.1"))
        self.assertTrue(all(r["status"] == "skipped" for r in recs))
        self.assertEqual((ex.active_blocks(), ex.isolated_devices()), ({}, []))

    def test_unknown_actions_are_refused_not_run(self):
        for bad in ("rm_rf", "BLOCK_SOURCE", "block_source; reboot", 5, None, ["x"], {"a": 1}):
            with self.subTest(bad=bad):
                recs = make().run(decision([bad]))
                self.assertEqual([(r["status"], r["note"], r["action"]) for r in recs], [("refused", "unknown_action", "none")])

    def test_invalid_decisions_are_refused(self):
        for bad in (None, [], "block_source", 5, 3.5):
            with self.subTest(bad=bad):
                (rec,) = make().run(bad)
                self.assertEqual((rec["status"], rec["note"]), ("refused", "invalid_decision"))

    def test_action_given_as_a_single_string_works(self):
        (rec,) = make().run(decision("monitor"))
        self.assertEqual(rec["action"], "monitor")

    def test_duplicate_and_excess_actions(self):
        recs = make().run(decision(["monitor"] * 50))
        self.assertEqual(len(recs), 1)
        recs = make().run(decision(["bogus"] * 100))
        self.assertEqual(len(recs), 16)   # at most 16 entries are looked at

    def test_ttl_and_limits_come_from_the_executor_not_the_decision(self):
        d = decision(["temporary_block"])
        d["expires_in_s"] = 10 ** 9
        d["ttl"] = 10 ** 9
        (rec,) = make(temporary_block_seconds=120).run(d)
        self.assertEqual(rec["expires_in_s"], 120)

    def test_skipped_entries_are_logged_with_known_codes_only(self):
        d = decision(["notify_admin"], skipped=[
            {"action": "block_source", "why": "source_allow_listed"},
            {"action": "block_source", "why": "free text <script>"},
            {"action": "evil", "why": "source_allow_listed"},
            "junk"])
        recs = make().run(d)
        self.assertEqual([(r["action"], r["status"], r["note"]) for r in recs],
                         [("notify_admin", "simulated", "ok"), ("block_source", "skipped", "source_allow_listed")])


class TestBlockLifecycle(unittest.TestCase):
    def test_temporary_block_expires(self):
        clock = FakeClock()
        ex = make(clock=clock, temporary_block_seconds=60)
        (rec,) = ex.run(decision(["temporary_block"]))
        self.assertEqual(rec["expires_in_s"], 60)
        self.assertIn("203.0.113.5", ex.active_blocks())
        clock.now += 59
        ex.run(decision(["monitor"]))
        self.assertIn("203.0.113.5", ex.active_blocks())
        clock.now += 2
        recs = ex.run(decision(["monitor"]))
        self.assertEqual(ex.active_blocks(), {})
        expired = [r for r in recs if r["note"] == "expired"]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["commands"], [])
        self.assertEqual(expired[0]["undo"], ["iptables -D FORWARD -s 203.0.113.5 -m comment --comment iot-ips-temp -j DROP"])

    def test_blocking_twice_does_not_duplicate(self):
        ex = make()
        ex.run(decision(["block_source"]))
        (rec,) = ex.run(decision(["block_source"]))
        self.assertEqual((rec["status"], rec["note"], rec["commands"]), ("skipped", "already_blocked", []))
        (rec,) = ex.run(decision(["temporary_block"]))
        self.assertEqual(rec["note"], "already_blocked")

    def test_permanent_block_replaces_a_temporary_one(self):
        ex = make()
        ex.run(decision(["temporary_block"]))
        (rec,) = ex.run(decision(["block_source"]))
        self.assertEqual((rec["status"], rec["note"]), ("simulated", "upgraded_to_permanent"))
        self.assertIsNone(ex.active_blocks()["203.0.113.5"])

    def test_block_budget_stops_a_flood_of_spoofed_sources(self):
        ex = make(max_active_blocks=3)
        results = [ex.run(decision(["temporary_block"], src="203.0.113.%d" % i))[0] for i in range(1, 7)]
        self.assertEqual([r["status"] for r in results], ["simulated"] * 3 + ["refused"] * 3)
        self.assertEqual({r["note"] for r in results[3:]}, {"block_budget_exhausted"})
        self.assertEqual(len(ex.active_blocks()), 3)
        (rec,) = ex.run(decision(["isolate_device"]))   # isolation shares the same budget
        self.assertEqual(rec["note"], "block_budget_exhausted")

    def test_budget_is_freed_when_blocks_expire(self):
        clock = FakeClock()
        ex = make(max_active_blocks=1, clock=clock, temporary_block_seconds=30)
        ex.run(decision(["temporary_block"], src="203.0.113.1"))
        self.assertEqual(ex.run(decision(["temporary_block"], src="203.0.113.2"))[0]["status"], "refused")
        clock.now += 31
        recs = ex.run(decision(["temporary_block"], src="203.0.113.2"))
        self.assertEqual(recs[-1]["status"], "simulated")


class TestActionLog(unittest.TestCase):
    def test_log_file_is_one_valid_json_object_per_line(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "actions.jsonl")
            ex = make(log_path=path)
            ex.run(decision(["block_source", "isolate_device", "notify_admin"]))
            ex.run(decision(["monitor"], dev_id="BULB-001", level="Low", rule="low"))
            with open(path, "rb") as fh:
                raw = fh.read()
            raw.decode("ascii")
            lines = raw.split(b"\n")
            self.assertEqual(lines[-1], b"")
            records = [json.loads(line) for line in lines[:-1]]
            self.assertEqual(len(records), 4)
            self.assertEqual([r["seq"] for r in records], [1, 2, 3, 4])
            for r in records:
                self.assertEqual(set(r), LOG_KEYS)
                for cmd in r["commands"] + r["undo"]:
                    self.assertRegex(cmd, CMD_RE)

    def test_hostile_text_cannot_forge_or_break_log_lines(self):
        payloads = ["CAM-001\n{\"action\":\"block_source\"}", "x" * 500, "<script>alert(1)</script>", "a\x1b[31m", "CAM-001\n", "../../etc/passwd"]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "a.jsonl")
            ex = make(log_path=path)
            for p in payloads:
                d_ = decision(["monitor"], dev_id=p, rule=p, level=p)
                d_["targets"]["src_ip"] = p
                ex.run(d_)
            with open(path, "rb") as fh:
                lines = fh.read().split(b"\n")[:-1]
            self.assertEqual(len(lines), len(payloads))
            for line in lines:
                rec = json.loads(line)
                self.assertEqual((rec["device_id"], rec["rule_id"], rec["level"]), ("unknown-device", "unknown_rule", None))

    def test_log_file_is_owner_only(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "a.jsonl")
            make(log_path=path).run(decision(["monitor"]))
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            else:
                self.assertNotIn("Everyone", acl(path), "the log must not be world-writable")

    def test_log_is_rotated_when_it_gets_too_big(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "a.jsonl")
            ex = make(log_path=path, max_log_bytes=2048)
            for _ in range(40):
                ex.run(decision(["monitor", "log"]))
            self.assertTrue(os.path.exists(path + ".1"))
            self.assertLess(os.path.getsize(path), 2048 + 400)
            for name in (path, path + ".1"):
                with open(name, "rb") as fh:
                    for line in fh.read().split(b"\n")[:-1]:
                        json.loads(line)

    def test_unwritable_log_does_not_crash(self):
        with tempfile.TemporaryDirectory() as d:
            ex = make(log_path=d)   # a directory, not a file
            recs = ex.run(decision(["monitor"]))
            self.assertEqual(len(recs), 1)
            self.assertGreaterEqual(ex.log_errors, 1)

    def test_log_does_not_follow_a_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "victim.txt")
            with open(target, "w") as fh:
                fh.write("keep me")
            link = os.path.join(d, "a.jsonl")
            simulated = False
            try:
                os.symlink(target, link)
            except OSError as exc:
                # Windows only lets a normal user create symlinks with Developer Mode on
                # (WinError 1314). Make a plain file and force the same guard instead.
                if getattr(exc, "winerror", None) != 1314:
                    raise
                with open(link, "w"):
                    pass
                simulated = True
            ex = make(log_path=link)
            if simulated:
                is_link = lambda p: os.path.abspath(p) == os.path.abspath(link)  # noqa: E731
                with mock.patch.object(actions.os.path, "islink", is_link):
                    ex.run(decision(["monitor"]))
                self.assertEqual(os.path.getsize(link), 0)
            else:
                ex.run(decision(["monitor"]))
            with open(target) as fh:
                self.assertEqual(fh.read(), "keep me")
            self.assertGreaterEqual(ex.log_errors, 1)

    def test_in_memory_records_are_bounded(self):
        ex = make()
        for _ in range(11000):
            ex.run(decision(["monitor"]))
        self.assertEqual(len(ex.records), 10000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
