"""
test_policy.py - tests for policy.py and config/policy.yaml.

Run:   python -m pytest tests/test_policy.py
The integration tests at the end use the real risk engine and its reference scenarios.
"""

import copy
import json
import os
import random
import re
import tempfile
import unittest

import yaml

from iot_ips import actions, policy
from iot_ips import risk as risk_engine
from iot_ips.paths import CONFIG_DIR
from iot_ips.policy import PolicyConfigError, decide, load_policy
from iot_ips.scenarios import DEVICES, SCENARIOS

DEFAULT_YAML = str(CONFIG_DIR / "policy.yaml")
CMD_RE = re.compile(r"^ip6?tables -I FORWARD -[sd] [0-9a-f:.]+ -m comment --comment iot-ips(-temp)? -j DROP$")
VALID_LEVELS = {"Low", "Medium", "High", "Critical"}
DECISION_KEYS = {"action", "reason", "command", "dry_run", "rule_id", "level", "targets", "skipped", "warnings"}

CAM = {"device_id": "CAM-001", "ip": "192.168.1.50", "criticality": "high"}


def risk(level, score):
    return {"level": level, "score": score, "factors": {}}


def det(conf=0.94, attack="brute_force", label="ATTACK"):
    return {"label": label, "attack_type": attack, "confidence": conf, "mitre_technique": "T1110"}


def ev(src="203.0.113.5"):
    return {"src_ip": src, "dst_ip": "192.168.1.50", "device_id": "CAM-001"}


def d(level, score, conf=0.94, attack="brute_force", src="203.0.113.5", profile=CAM):
    return decide(risk(level, score), det(conf, attack), ev(src), profile)


def assert_valid(tc, dec):
    tc.assertEqual(set(dec), DECISION_KEYS)
    tc.assertTrue(dec["dry_run"])
    tc.assertIsInstance(dec["action"], list)
    tc.assertTrue(set(dec["action"]) <= set(actions.ACTION_NAMES))
    tc.assertEqual(len(dec["action"]), len(set(dec["action"])))
    for cmd in dec["command"]:
        tc.assertRegex(cmd, CMD_RE)
    json.dumps(dec, allow_nan=False)


def network(dec):
    return [a for a in dec["action"] if a in actions.NETWORK_ACTIONS]


# ---------------------------------------------------------------------------
class TestLevelTable(unittest.TestCase):
    """One test per row of the response policy table."""

    def test_low_logs_and_monitors(self):
        dec = d("Low", 25, conf=0.55, attack="port_scan")
        self.assertEqual(dec["action"], ["log", "create_incident", "monitor"])
        self.assertEqual((dec["command"], dec["rule_id"]), ([], "low"))

    def test_medium_logs_and_notifies(self):
        dec = d("Medium", 55, conf=0.75, attack="port_scan")
        self.assertEqual(dec["action"], ["log", "create_incident", "notify_admin"])
        self.assertEqual(network(dec), [])

    def test_high_notifies_and_blocks_temporarily(self):
        dec = d("High", 77, conf=0.85)
        self.assertEqual(dec["action"], ["temporary_block", "create_incident", "notify_admin"])
        self.assertEqual(dec["command"], ["iptables -I FORWARD -s 203.0.113.5 -m comment --comment iot-ips-temp -j DROP"])
        self.assertEqual(dec["rule_id"], "high_probable")

    def test_critical_blocks_isolates_and_notifies(self):
        dec = d("Critical", 81, conf=0.94)
        self.assertEqual(dec["action"], ["block_source", "isolate_device", "create_incident", "notify_admin"])
        self.assertEqual(len(dec["command"]), 3)   # one block rule + two isolation rules
        self.assertEqual(dec["rule_id"], "critical_certain")
        self.assertIn("rule critical_certain matched", dec["reason"])

    def test_the_pdf_example_rule(self):
        """IF risk >= 80 AND confidence >= 0.90 AND attack_type != unknown THEN block_source + create_incident + notify_admin"""
        dec = d("Critical", 87, conf=0.94, attack="Brute Force")
        for needed in ("block_source", "create_incident", "notify_admin"):
            self.assertIn(needed, dec["action"])

    def test_level_name_is_case_and_space_insensitive(self):
        self.assertEqual(d(" critical ", 90)["rule_id"], "critical_certain")
        self.assertEqual(d("LOW", 10)["rule_id"], "low")

    def test_benign_verdict_does_nothing(self):
        dec = decide(risk("Low", 0), det(0.99, "benign", "BENIGN"), ev(), CAM)
        self.assertEqual((dec["action"], dec["command"], dec["rule_id"]), ([], [], "benign"))
        dec = decide(risk("Critical", 99), det(0.99, "benign", " benign "), ev(), CAM)   # even with a wild risk
        self.assertEqual(dec["action"], [])


class TestConfidenceGates(unittest.TestCase):
    def test_critical_but_not_certain_only_blocks_temporarily(self):
        dec = d("Critical", 85, conf=0.75)
        self.assertEqual(dec["rule_id"], "critical_probable")
        self.assertEqual(network(dec), ["temporary_block"])

    def test_critical_with_low_confidence_blocks_nothing(self):
        dec = d("Critical", 85, conf=0.40)
        self.assertEqual((dec["rule_id"], network(dec), dec["command"]), ("critical_other", [], []))
        self.assertEqual(dec["action"], ["create_incident", "notify_admin"])

    def test_unknown_attack_type_prevents_harsh_actions(self):
        for attack in ("unknown", "Unknown", "", None, "none", "unrecognized", 5, ["x"]):
            with self.subTest(attack=attack):
                dec = d("Critical", 95, conf=0.99, attack=attack)
                self.assertNotIn("block_source", dec["action"])
                self.assertNotIn("isolate_device", dec["action"])

    def test_score_must_back_up_the_level(self):
        dec = d("Critical", 70, conf=0.99)   # a Critical level with a score below 80 is suspicious
        self.assertEqual(dec["rule_id"], "critical_probable")

    def test_high_with_low_confidence_only_notifies(self):
        dec = d("High", 70, conf=0.59)
        self.assertEqual((dec["rule_id"], network(dec)), ("high_other", []))

    def test_confidence_boundaries(self):
        self.assertEqual(d("Critical", 80, conf=0.90)["rule_id"], "critical_certain")
        self.assertEqual(d("Critical", 80, conf=0.8999)["rule_id"], "critical_probable")
        self.assertEqual(d("Critical", 80, conf=0.60)["rule_id"], "critical_probable")
        self.assertEqual(d("Critical", 80, conf=0.5999)["rule_id"], "critical_other")
        self.assertEqual(d("Critical", 80, conf=0.95)["rule_id"], "critical_certain")
        self.assertEqual(d("Critical", 79.9, conf=0.95)["rule_id"], "critical_probable")

    def test_low_and_medium_never_block_whatever_the_confidence(self):
        for level, score in (("Low", 10), ("Medium", 55)):
            for conf in (0.0, 0.5, 0.99, 1.0):
                self.assertEqual(network(d(level, score, conf=conf)), [], (level, conf))


class TestAllowListAndTargets(unittest.TestCase):
    def test_trusted_sources_are_never_blocked_at_any_level(self):
        for src in ("192.168.1.1", "192.168.1.2", "192.168.1.10", "192.168.1.20", "192.168.1.30",
                    "::ffff:192.168.1.10", " 192.168.1.30 "):
            for level, score in (("High", 77), ("Critical", 90)):
                with self.subTest(src=src, level=level):
                    dec = d(level, score, conf=0.99, src=src)
                    self.assertFalse({"block_source", "temporary_block"} & set(dec["action"]))
                    self.assertTrue(any(s["why"] == "source_allow_listed" for s in dec["skipped"]))
                    self.assertEqual([c for c in dec["command"] if "-s %s " % src.strip() in c], [])

    def test_attacker_spoofing_the_router_cannot_get_it_blocked(self):
        dec = d("Critical", 99, conf=0.99, src="192.168.1.1")
        self.assertFalse({"block_source", "temporary_block"} & set(dec["action"]))
        self.assertIn("notify_admin", dec["action"])   # a person is still told

    def test_isolation_is_skipped_when_the_source_is_trusted(self):
        for src in ("192.168.1.1", "192.168.1.10", "::ffff:192.168.1.10", "127.0.0.1"):
            with self.subTest(src=src):
                dec = d("Critical", 90, conf=0.99, src=src)
                self.assertNotIn("isolate_device", dec["action"])
                self.assertNotIn("block_source", dec["action"])
                self.assertIn("notify_admin", dec["action"])   # a person is still told
                self.assertIn("create_incident", dec["action"])
                self.assertIn({"action": "isolate_device", "why": "source_allow_listed"}, dec["skipped"])
                self.assertEqual([c for c in dec["command"] if "DROP" in c], [])

    def test_isolation_still_happens_for_an_untrusted_source(self):
        dec = d("Critical", 90, conf=0.99, src="203.0.113.5")
        self.assertIn("isolate_device", dec["action"])
        self.assertIn("block_source", dec["action"])

    def test_never_block_addresses(self):
        for src in ("127.0.0.1", "0.0.0.0", "224.0.0.251", "169.254.10.10", "255.255.255.255", "::1", "ff02::1", "fe80::5"):
            with self.subTest(src=src):
                dec = d("Critical", 99, conf=0.99, src=src)
                self.assertFalse({"block_source", "temporary_block"} & set(dec["action"]))
                self.assertEqual([s["why"] for s in dec["skipped"] if s["action"] == "block_source"], ["source_never_block"])

    def test_missing_or_invalid_source(self):
        for src in (None, "", "garbage", 12345, "1.2.3.4/32", "1.2.3.4\n5", ["203.0.113.5"]):
            with self.subTest(src=src):
                dec = d("Critical", 99, conf=0.99, src=src)
                self.assertNotIn("block_source", dec["action"])
                self.assertIn("no_valid_source", [s["why"] for s in dec["skipped"]])
                self.assertIn("isolate_device", dec["action"])   # the device can still be protected

    def test_missing_event_entirely(self):
        dec = decide(risk("Critical", 99), det(0.99), None, None)
        self.assertEqual(network(dec), [])
        self.assertIsNone(dec["targets"]["src_ip"])

    def test_the_device_is_not_blocked_as_a_source(self):
        dec = d("Critical", 99, conf=0.99, src="192.168.1.50")
        self.assertIn("source_is_device", [s["why"] for s in dec["skipped"]])

    def test_isolation_needs_a_private_non_allow_listed_device_address(self):
        for ip, why in (("8.8.8.8", "device_ip_not_private"), ("192.168.1.1", "device_allow_listed"),
                        ("junk", "no_valid_device_ip"), (None, "no_valid_device_ip")):
            with self.subTest(ip=ip):
                profile = {"device_id": "X-1", "ip": ip}
                dec = decide(risk("Critical", 99), det(0.99), {"src_ip": "203.0.113.5"}, profile)
                self.assertNotIn("isolate_device", dec["action"])
                self.assertIn(why, [s["why"] for s in dec["skipped"]])

    def test_device_ip_falls_back_to_dst_ip(self):
        dec = decide(risk("Critical", 99), det(0.99), {"src_ip": "203.0.113.5", "dst_ip": "192.168.1.60"}, {})
        self.assertEqual(dec["targets"]["device_ip"], "192.168.1.60")
        self.assertIn("isolate_device", dec["action"])

    def test_ipv4_mapped_addresses_are_normalised(self):
        dec = d("High", 77, conf=0.9, src="::ffff:203.0.113.5")
        self.assertEqual(dec["targets"]["src_ip"], "203.0.113.5")
        self.assertEqual(len(dec["command"]), 1)

    def test_ipv6_source_uses_ip6tables(self):
        dec = d("High", 77, conf=0.9, src="2001:db8::1")
        self.assertTrue(dec["command"][0].startswith("ip6tables "))

    def test_custom_allow_list_network(self):
        raw = base_raw()
        raw["allow_list"].append("203.0.113.0/24")
        pol = load_raw(raw)
        dec = decide(risk("Critical", 99), det(0.99), ev("203.0.113.77"), CAM, policy=pol)
        self.assertFalse({"block_source", "temporary_block"} & set(dec["action"]))


# ---------------------------------------------------------------------------
class TestInvariants(unittest.TestCase):
    """Properties that must hold for ANY input."""

    def _pool(self):
        return [None, True, False, 0, 1, -1, 0.5, 0.59, 0.6, 0.89, 0.9, 1.0, 1.5, 55, 79.9, 80, 100, 101, 431, float("nan"),
                float("inf"), 10 ** 400, "", " ", "Low", "Medium", "High", "Critical", "critical", "ATTACK", "BENIGN", "benign",
                "brute_force", "unknown", "x" * 4000, "203.0.113.5", "192.168.1.1", "192.168.1.50", "8.8.8.8", "::1", "0.0.0.0",
                "0.9", "90", "\n", "<script>", "'; DROP TABLE x;--", [], [1], {}, {"a": 1}, object(), (1,)]

    def test_fuzz_decisions_are_always_valid_and_safe(self):
        rng = random.Random(20261020)
        pool = self._pool()
        pol = load_policy()
        allowed = set()
        for rule in pol["rules"]:
            allowed |= set(rule["then"])
        allowed |= set(pol["fallback"]["then"])
        limits = pol["limits"]

        def rmap(keys):
            return {k: rng.choice(pool) for k in keys if rng.random() < 0.85}

        for _ in range(8000):
            risk_in = rmap(["level", "score", "factors"])
            det_in = rmap(["label", "attack_type", "confidence"])
            ev_in = rmap(["src_ip", "dst_ip", "device_id"])
            prof_in = rmap(["device_id", "ip", "criticality"])
            dec = decide(risk_in, det_in, ev_in, prof_in)
            assert_valid(self, dec)
            self.assertTrue(set(dec["action"]) <= allowed, dec["action"])          # only actions written in policy.yaml
            if str(det_in.get("label", "")).strip().upper() == "BENIGN" and isinstance(det_in.get("label"), str):
                self.assertEqual(dec["action"], [])
            net = set(network(dec))
            if net:
                lvl = risk_in.get("level")
                lvl = lvl.strip().capitalize() if isinstance(lvl, str) else None
                conf = det_in.get("confidence")
                conf = float(conf) if isinstance(conf, (int, float)) and not isinstance(conf, bool) else None
                self.assertIn(lvl, ("High", "Critical"))
                self.assertIsNotNone(conf)
                self.assertTrue(conf >= limits["block_min_confidence"])
                if net & {"block_source", "isolate_device"}:
                    self.assertEqual(lvl, "Critical")
                    self.assertTrue(conf >= limits["harsh_min_confidence"])
                    self.assertTrue(policy._attack_known(det_in.get("attack_type")))
            # every command targets the validated source or device address, and never a protected one
            src_ip = actions.parse_ip(dec["targets"]["src_ip"])
            dev_ip = actions.parse_ip(dec["targets"]["device_ip"])
            for cmd in dec["command"]:
                ip = actions.parse_ip(cmd.split()[5])
                self.assertIn(ip, (src_ip, dev_ip), cmd)
                self.assertFalse(actions.is_allow_listed(ip, pol["allow_networks"]), cmd)
                self.assertFalse(actions.is_never_block(ip), cmd)

    def test_non_mapping_inputs_do_not_raise_and_block_nothing(self):
        for bad in (None, [], "text", 5, 3.5, object(), (1, 2)):
            with self.subTest(bad=bad):
                dec = decide(bad, bad, bad, bad)
                assert_valid(self, dec)
                self.assertEqual(network(dec), [])
                self.assertEqual(dec["rule_id"], "unusable_risk")
                self.assertIn("invalid_risk", dec["warnings"])

    def test_invalid_level_uses_the_cautious_fallback(self):
        for level in (None, "", "Severe", 5, "Crit", ["Critical"]):
            with self.subTest(level=level):
                dec = decide({"level": level, "score": 99}, det(0.99), ev(), CAM)
                self.assertEqual((dec["rule_id"], network(dec)), ("unusable_risk", []))
                self.assertEqual(dec["action"], ["log", "create_incident", "notify_admin"])
                self.assertIn("invalid_level", dec["warnings"])

    def test_bad_confidence_never_triggers_blocking(self):
        for conf in (None, "x", float("nan"), float("inf"), -1, 2, True, [], "0.99 "[:0]):
            with self.subTest(conf=conf):
                dec = decide(risk("Critical", 99), det(conf), ev(), CAM)
                self.assertEqual(network(dec), [])
                self.assertIn("invalid_confidence", dec["warnings"])

    def test_numeric_strings_work_like_numbers(self):
        a = decide(risk("Critical", 90), det(0.94), ev(), CAM)
        b = decide({"level": "Critical", "score": "90"}, det("0.94"), ev(), CAM)
        self.assertEqual(a["action"], b["action"])

    def test_missing_label_is_treated_as_an_attack_with_a_warning(self):
        dec = decide(risk("High", 70), {"attack_type": "dos", "confidence": 0.9}, ev(), CAM)
        self.assertIn("label_missing_or_invalid", dec["warnings"])
        self.assertIn("temporary_block", dec["action"])

    def test_inputs_are_not_modified_and_result_is_deterministic(self):
        args = (risk("Critical", 90), det(0.95), ev(), CAM)
        before = copy.deepcopy(args)
        first = decide(*args)
        second = decide(*args)
        self.assertEqual(args, before)
        self.assertEqual(first, second)

    def test_hostile_strings_never_reach_the_decision(self):
        payload = "<script>alert(1)</script>'; DROP TABLE incidents;--\n\x1b[31m$(reboot)"
        dec = decide(risk("Critical", 90),
                     {"label": "ATTACK", "attack_type": payload, "confidence": 0.95, "mitre_technique": payload},
                     {"src_ip": payload, "dst_ip": payload, "device_id": payload},
                     {"device_id": payload, "ip": payload, "criticality": payload})
        assert_valid(self, dec)
        text = json.dumps(dec)
        for needle in ("script", "DROP", "incidents", "reboot", "\\x1b", "alert"):
            self.assertNotIn(needle, text)
        self.assertIsNone(dec["targets"]["device_id"])

    def test_device_id_must_be_a_clean_identifier(self):
        for bad in ("CAM-001\n", "CAM 001", "../x", "", "a" * 41, "-x", None, 5):
            with self.subTest(bad=bad):
                dec = decide(risk("Low", 5), det(0.5), {}, {"device_id": bad})
                self.assertIsNone(dec["targets"]["device_id"])
        self.assertEqual(decide(risk("Low", 5), det(0.5), {}, {"device_id": "CAM-001"})["targets"]["device_id"], "CAM-001")

    def test_commands_only_contain_validated_addresses(self):
        for src in ("203.0.113.5", "10.9.9.9", "2001:db8::7", "::ffff:203.0.113.9"):
            dec = d("Critical", 99, conf=0.99, src=src)
            self.assertTrue(dec["command"])
            for cmd in dec["command"]:
                self.assertRegex(cmd, CMD_RE)


# ---------------------------------------------------------------------------
def base_raw():
    with open(DEFAULT_YAML, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_raw(raw):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "p.yaml")
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(raw, fh)
        return load_policy(path)


def load_text(text=None, data=None):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "p.yaml")
        with open(path, "wb") as fh:
            fh.write(data if data is not None else text.encode("utf-8"))
        return load_policy(path)


def rule(raw, rid):
    return next(r for r in raw["rules"] if r["id"] == rid)


class TestPolicyFile(unittest.TestCase):
    def test_default_policy_is_valid_and_covers_every_level(self):
        pol = load_policy()
        self.assertTrue(pol["dry_run"])
        covered = set()
        for r in pol["rules"]:
            if r["catch_all"]:
                covered |= r["levels"]
        self.assertEqual(covered, VALID_LEVELS)

    def test_every_rule_only_uses_catalog_actions(self):
        for r in load_policy()["rules"]:
            self.assertTrue(set(r["then"]) <= set(actions.ACTION_NAMES))

    def test_bad_policies_are_rejected_for_the_right_reason(self):
        def m_real_run(r): r["dry_run"] = False
        def m_real_run_str(r): r["dry_run"] = "true"
        def m_unknown_top(r): r["extra"] = 1
        def m_missing_top(r): del r["fallback"]
        def m_version(r): r["version"] = 2
        def m_medium_blocks(r): rule(r, "medium")["then"].append("temporary_block")
        def m_low_isolates(r): rule(r, "low")["then"].append("isolate_device")
        def m_temp_no_conf(r): del rule(r, "high_probable")["when"]["min_confidence"]
        def m_temp_low_conf(r): rule(r, "high_probable")["when"]["min_confidence"] = 0.5
        def m_harsh_low_conf(r): rule(r, "critical_certain")["when"]["min_confidence"] = 0.8
        def m_harsh_no_conf(r): del rule(r, "critical_certain")["when"]["min_confidence"]
        def m_harsh_no_known(r): del rule(r, "critical_certain")["when"]["attack_known"]
        def m_harsh_known_false(r): rule(r, "critical_certain")["when"]["attack_known"] = False
        def m_catch_all_blocks(r): rule(r, "high_other")["then"].append("temporary_block")
        def m_unknown_action(r): rule(r, "low")["then"].append("format_disk")
        def m_action_type(r): rule(r, "low")["then"].append(5)
        def m_dup_action(r): rule(r, "low")["then"].append("log")
        def m_empty_then(r): rule(r, "low")["then"] = []
        def m_dup_rule_id(r): rule(r, "low")["id"] = "medium"
        def m_bad_rule_id(r): rule(r, "low")["id"] = "Low Rule!"
        def m_no_high_catch_all(r): r["rules"] = [x for x in r["rules"] if x["id"] != "high_other"]
        def m_no_critical_catch_all(r): r["rules"] = [x for x in r["rules"] if x["id"] != "critical_other"]
        def m_fallback_blocks(r): r["fallback"]["then"].append("block_source")
        def m_fallback_id_clash(r): r["fallback"]["id"] = "low"
        def m_fallback_extra_key(r): r["fallback"]["when"] = {}
        def m_allow_all(r): r["allow_list"].append("0.0.0.0/0")
        def m_allow_broad(r): r["allow_list"].append("10.0.0.0/7")
        def m_allow_v6_broad(r): r["allow_list"].append("2000::/16")
        def m_allow_bad(r): r["allow_list"].append("300.1.1.1")
        def m_allow_hostbits(r): r["allow_list"].append("192.168.1.5/24")
        def m_allow_type(r): r["allow_list"].append(12345)
        def m_allow_not_list(r): r["allow_list"] = "192.168.1.1"
        def m_bad_level(r): rule(r, "low")["when"]["level"] = ["Severe"]
        def m_empty_levels(r): rule(r, "low")["when"]["level"] = []
        def m_level_type(r): rule(r, "low")["when"]["level"] = "Low"
        def m_when_extra(r): rule(r, "low")["when"]["src_ip"] = "1.2.3.4"
        def m_when_no_level(r): del rule(r, "low")["when"]["level"]
        def m_conf_range(r): rule(r, "high_probable")["when"]["min_confidence"] = 2
        def m_score_range(r): rule(r, "critical_certain")["when"]["min_score"] = 300
        def m_known_type(r): rule(r, "critical_certain")["when"]["attack_known"] = "yes"
        def m_nan(r): rule(r, "critical_certain")["when"]["min_score"] = float("nan")
        def m_no_rules(r): r["rules"] = []
        def m_too_many_rules(r): r["rules"] = [dict(id="r%d" % i, when={"level": ["Low"]}, then=["log"]) for i in range(51)]
        def m_rule_extra_key(r): rule(r, "low")["priority"] = 1
        def m_limit_order(r): r["limits"]["harsh_min_confidence"] = 0.5
        def m_limit_block_low(r): r["limits"]["block_min_confidence"] = 0.2
        def m_limit_ttl(r): r["limits"]["temporary_block_seconds"] = 5
        def m_limit_budget(r): r["limits"]["max_active_blocks"] = 0
        def m_limit_float(r): r["limits"]["max_active_blocks"] = 10.5
        def m_limit_bool(r): r["limits"]["max_active_blocks"] = True
        def m_limit_missing(r): del r["limits"]["max_log_bytes"]

        expected = {
            "m_real_run": "dry_run", "m_real_run_str": "dry_run", "m_unknown_top": "keys wrong", "m_missing_top": "keys wrong",
            "m_version": "version", "m_medium_blocks": "only High or Critical", "m_low_isolates": "only High or Critical",
            "m_temp_no_conf": "temporary_block needs", "m_temp_low_conf": "temporary_block needs",
            "m_harsh_low_conf": "harsh_min_confidence", "m_harsh_no_conf": "harsh_min_confidence",
            "m_harsh_no_known": "attack_known: true", "m_harsh_known_false": "attack_known: true",
            "m_catch_all_blocks": "temporary_block needs", "m_unknown_action": "catalog", "m_action_type": "catalog",
            "m_dup_action": "twice", "m_empty_then": "1 to 8", "m_dup_rule_id": "duplicate rule id", "m_bad_rule_id": "bad id",
            "m_no_high_catch_all": "covers level High", "m_no_critical_catch_all": "covers level Critical",
            "m_fallback_blocks": "fallback must not", "m_fallback_id_clash": "fallback id", "m_fallback_extra_key": "fallback must have",
            "m_allow_all": "too broad", "m_allow_broad": "too broad", "m_allow_v6_broad": "too broad", "m_allow_bad": "bad address",
            "m_allow_hostbits": "bad address", "m_allow_type": "strings", "m_allow_not_list": "allow_list",
            "m_bad_level": "valid levels", "m_empty_levels": "valid levels", "m_level_type": "valid levels",
            "m_when_extra": "may only add", "m_when_no_level": "needs 'level'", "m_conf_range": "between",
            "m_score_range": "between", "m_known_type": "true or false", "m_nan": "between", "m_no_rules": "1 to 50",
            "m_too_many_rules": "1 to 50", "m_rule_extra_key": "exactly the keys", "m_limit_order": "harsh_min_confidence",
            "m_limit_block_low": "block_min_confidence", "m_limit_ttl": "temporary_block_seconds",
            "m_limit_budget": "max_active_blocks", "m_limit_float": "max_active_blocks", "m_limit_bool": "max_active_blocks",
            "m_limit_missing": "exactly the keys",
        }
        mutators = {k: v for k, v in locals().items() if k.startswith("m_")}
        self.assertEqual(set(mutators), set(expected))
        self.assertGreaterEqual(len(mutators), 50)
        for name, mutate in sorted(mutators.items()):
            with self.subTest(mutation=name):
                raw = copy.deepcopy(base_raw())
                mutate(raw)
                with self.assertRaises(PolicyConfigError) as ctx:
                    load_raw(raw)
                self.assertIn(expected[name], str(ctx.exception))

    def test_duplicate_keys_are_rejected(self):
        with open(DEFAULT_YAML, "r", encoding="utf-8") as fh:
            text = fh.read()
        with self.assertRaises(PolicyConfigError):
            load_text(text + "\nversion: 1\n")
        with self.assertRaises(PolicyConfigError):
            load_text(text.replace("dry_run: true", "dry_run: true\ndry_run: false", 1))

    def test_malformed_unsafe_and_oversized_files_are_rejected(self):
        for text in ("version: [unclosed", "- a\n- b\n", "plain string", "",
                     "!!python/object/apply:os.system ['echo pwned']", "version: !!python/object/apply:os.getcwd []\n"):
            with self.subTest(text=text[:30]):
                with self.assertRaises(PolicyConfigError):
                    load_text(text)
        with self.assertRaises(PolicyConfigError):
            load_text(data=b"\xff\xfe\x00bad")
        with self.assertRaises(PolicyConfigError):
            load_text(data=b"#" * (policy.MAX_POLICY_BYTES + 5))
        with self.assertRaises(PolicyConfigError):
            load_policy(os.path.join(tempfile.gettempdir(), "no_such_policy_file.yaml"))

    def test_hash_pinning(self):
        good = policy.policy_sha256(DEFAULT_YAML)
        load_policy(DEFAULT_YAML, expected_sha256=good)
        for bad in ("0" * 64, "", None.__class__, 5):
            with self.subTest(bad=bad):
                with self.assertRaises(PolicyConfigError):
                    load_policy(DEFAULT_YAML, expected_sha256=bad)

    def test_decide_rejects_an_unvalidated_policy(self):
        for bad in ({}, {"_validated": True}, base_raw(), "policy.yaml", 5):
            with self.subTest(bad=repr(bad)[:30]):
                with self.assertRaises(PolicyConfigError):
                    decide(risk("Low", 1), det(), ev(), CAM, policy=bad)

    def test_reload_policy(self):
        self.assertTrue(policy.reload_policy()["dry_run"])

    def test_a_loosened_but_valid_policy_is_honoured(self):
        raw = base_raw()
        rule(raw, "high_probable")["then"] = ["create_incident", "notify_admin"]
        pol = load_raw(raw)
        dec = decide(risk("High", 70), det(0.9), ev(), CAM, policy=pol)
        self.assertEqual(dec["action"], ["create_incident", "notify_admin"])


# ---------------------------------------------------------------------------
class TestWithRiskEngine(unittest.TestCase):
    """Real risk-engine output goes into the policy and then into the executor."""

    EXPECTED = {   # scenario -> (actions, network actions)
        "L1": (["log", "create_incident", "monitor"], []),
        "L2": (["log", "create_incident", "monitor"], []),
        "M1": (["log", "create_incident", "notify_admin"], []),
        "M2": (["log", "create_incident", "notify_admin"], []),
        "H1": (["temporary_block", "create_incident", "notify_admin"], ["temporary_block"]),
        "H2": (["temporary_block", "create_incident", "notify_admin"], ["temporary_block"]),
        "C1": (["block_source", "isolate_device", "create_incident", "notify_admin"], ["block_source", "isolate_device"]),
        "C2": (["block_source", "isolate_device", "create_incident", "notify_admin"], ["block_source", "isolate_device"]),
        "C3": (["block_source", "isolate_device", "create_incident", "notify_admin"], ["block_source", "isolate_device"]),
        "B1": ([], []),
    }

    def run_scenario(self, sc, **overrides):
        profile = DEVICES[sc["device"]]
        event = dict(sc["event"], **overrides)
        r = risk_engine.assess(sc["detection"], event, profile)
        return r, decide(r, sc["detection"], event, profile)

    def test_every_scenario_gets_the_expected_response(self):
        for sc in SCENARIOS:
            with self.subTest(sc["id"]):
                r, dec = self.run_scenario(sc)
                assert_valid(self, dec)
                actions_expected, net_expected = self.EXPECTED[sc["id"]]
                self.assertEqual(dec["action"], actions_expected, (r["level"], r["score"], dec["reason"]))
                self.assertEqual(network(dec), net_expected)

    def test_the_attack_name_comes_from_the_risk_engine(self):
        """The policy must not keep a second list of attack names: it asks
        the risk engine, so the policy and the score always agree."""
        for attack in ("brute_force", "port_scan", "mirai", "dos", "device_takeover", "web_based"):
            with self.subTest(attack=attack):
                self.assertTrue(policy._attack_known(attack), attack)
        for attack in ("unknown", "benign", "none", "", None, 5, "x" * 4000, "203.0.113.5", "8.8.8.8"):
            with self.subTest(attack=attack):
                self.assertFalse(policy._attack_known(attack), attack)

    def test_an_attack_the_risk_engine_does_not_know_is_never_blocked_hard(self):
        for attack in ("x" * 4000, "203.0.113.5", "not_an_attack", "8.8.8.8"):
            with self.subTest(attack=attack):
                dec = d("Critical", 95, conf=0.99, attack=attack)
                self.assertNotIn("block_source", dec["action"], attack)
                self.assertNotIn("isolate_device", dec["action"], attack)

    def test_an_alias_of_a_known_attack_is_still_known(self):
        """'bruteforce' is an alias of 'brute_force' in risk_weights.yaml, so the
        policy must treat it exactly like the canonical name."""
        self.assertTrue(policy._attack_known("bruteforce"))
        self.assertTrue(policy._attack_known("DDoS-ICMP Flood"))
        dec = d("Critical", 95, conf=0.99, attack="bruteforce")
        self.assertIn("block_source", dec["action"])

    def test_response_gets_stronger_as_the_risk_level_rises(self):
        rank = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
        rows = []
        for sc in SCENARIOS:
            r, dec = self.run_scenario(sc)
            if sc["detection"]["label"] == "ATTACK":
                rows.append((rank[r["level"]], len(network(dec)), "notify_admin" in dec["action"]))
        rows.sort()
        self.assertEqual([x[1] for x in rows], sorted(x[1] for x in rows))   # network actions never drop as the level rises

    def test_spoofing_a_trusted_source_on_a_severe_attack_cannot_get_the_device_isolated(self):
        c2 = next(s for s in SCENARIOS if s["id"] == "C2")
        r, dec = self.run_scenario(c2, src_ip="192.168.1.20")   # attacker pretends to be a trusted PC
        self.assertEqual(r["level"], "Critical")
        self.assertNotIn("isolate_device", dec["action"])        # a spoofed trusted IP must not cut the device off
        self.assertNotIn("block_source", dec["action"])          # and the trusted address is not blocked
        self.assertIn("notify_admin", dec["action"])             # and a person is told

    def test_known_limitation_spoofed_trusted_source_can_lower_the_response(self):
        """Faking a trusted address lowers the risk score by up to ~7 points. A borderline
        Critical event (C1, score 81) then becomes High, and with the trusted address
        protected nothing is blocked automatically. A person is still notified and an
        incident is still recorded. This is a documented limitation (see the threat model)."""
        c1 = next(s for s in SCENARIOS if s["id"] == "C1")
        _, normal = self.run_scenario(c1)
        r, spoofed = self.run_scenario(c1, src_ip="192.168.1.20")
        self.assertIn("block_source", normal["action"])
        self.assertFalse({"block_source", "temporary_block", "isolate_device"} & set(spoofed["action"]))
        self.assertEqual(spoofed["action"], ["create_incident", "notify_admin"])
        self.assertGreaterEqual(r["score"], 60)   # still High, not dismissed

    def test_spoofing_the_router_as_the_source_cannot_cause_a_self_block(self):
        for sc in SCENARIOS:
            if sc["expected_level"] in ("High", "Critical"):
                _, dec = self.run_scenario(sc, src_ip="192.168.1.1")
                self.assertFalse({"block_source", "temporary_block"} & set(dec["action"]), sc["id"])

    def test_full_chain_into_the_executor_writes_a_valid_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "actions.jsonl")
            executor = actions.ActionExecutor.from_policy(load_policy(), log_path=path)
            for sc in SCENARIOS:
                _, dec = self.run_scenario(sc)
                executor.run(dec)
            with open(path, "rb") as fh:
                records = [json.loads(line) for line in fh.read().split(b"\n")[:-1]]
            self.assertEqual(len(records), len(executor.records))
            self.assertTrue(all(r["dry_run"] is True for r in records))
            self.assertTrue(any(r["action"] == "block_source" and r["status"] == "simulated" for r in records))
            for r in records:
                for cmd in r["commands"] + r["undo"]:
                    self.assertRegex(cmd, re.compile(r"^ip6?tables -[ID] FORWARD -[sd] [0-9a-f:.]+ -m comment --comment iot-ips(-temp)? -j DROP$"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
