"""
test_risk.py - tests for risk.py.

Run:   python -m unittest -v test_risk
(or    python -m unittest discover -v    to run every module's tests together)
"""

import copy
import json
import os
import random
import tempfile
import unittest

import yaml

from iot_ips import risk
from iot_ips.paths import CONFIG_DIR
from iot_ips.risk import RiskConfigError, assess, level_for, load_config
from iot_ips.scenarios import DEVICES, SCENARIOS

DEFAULT_YAML = str(CONFIG_DIR / "risk_weights.yaml")
SCEN = {s["id"]: s for s in SCENARIOS}
VALID_LEVELS = {"Low", "Medium", "High", "Critical"}


def run(sc, **kw):
    return assess(sc["detection"], sc["event"], DEVICES[sc["device"]], **kw)


def make(attack="brute_force", conf=0.9, device="CAM-001", src="203.0.113.5", port=22, failed=40, conns=0):
    """Build (detection, event, profile) for a one-off case."""
    return (
        {"label": "ATTACK", "attack_type": attack, "confidence": conf, "mitre_technique": "T0000"},
        {"src_ip": src, "dst_port": port, "failed_attempts": failed, "connection_attempts": conns},
        DEVICES[device],
    )


def score_of(**kw):
    return assess(*make(**kw))["score"]


def assert_valid_result(tc, res):
    tc.assertIsInstance(res, dict)
    tc.assertIsInstance(res["score"], int)
    tc.assertGreaterEqual(res["score"], 0)
    tc.assertLessEqual(res["score"], 100)
    tc.assertIn(res["level"], VALID_LEVELS)
    tc.assertIsInstance(res["factors"], dict)
    tc.assertIsInstance(res["warnings"], list)
    json.dumps(res, allow_nan=False)  # must be plain, NaN-free JSON data


# ---------------------------------------------------------------------------
class TestLevels(unittest.TestCase):
    def test_boundaries(self):
        cases = [(0, "Low"), (29, "Low"), (30, "Medium"), (59, "Medium"),
                 (60, "High"), (79, "High"), (80, "Critical"), (100, "Critical")]
        for score, level in cases:
            with self.subTest(score=score):
                self.assertEqual(level_for(score), level)

    def test_out_of_range_is_clamped_and_garbage_rejected(self):
        self.assertEqual(level_for(-50), "Low")
        self.assertEqual(level_for(1000), "Critical")
        for bad in ("abc", None, float("nan"), float("inf"), True, [], {}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    level_for(bad)


# ---------------------------------------------------------------------------
class TestScenarioLevels(unittest.TestCase):
    """Two cases per level (8), plus extra Critical and a benign case."""

    def _check(self, sid):
        sc = SCEN[sid]
        res = run(sc)
        assert_valid_result(self, res)
        self.assertEqual(res["level"], sc["expected_level"], "%s: %s -> %s" % (sid, sc["story"], res))

    def test_low_1(self): self._check("L1")
    def test_low_2(self): self._check("L2")
    def test_medium_1(self): self._check("M1")
    def test_medium_2(self): self._check("M2")
    def test_high_1(self): self._check("H1")
    def test_high_2(self): self._check("H2")
    def test_critical_1_pdf_example(self): self._check("C1")
    def test_critical_2(self): self._check("C2")
    def test_critical_3(self): self._check("C3")

    def test_benign_is_zero(self):
        res = run(SCEN["B1"])
        self.assertEqual((res["score"], res["level"], res["factors"]), (0, "Low", {}))

    def test_every_weight_set_gives_valid_results(self):
        cfg = load_config()
        for name in cfg["weight_sets"]:
            for sc in SCENARIOS:
                with self.subTest(weight_set=name, scenario=sc["id"]):
                    res = run(sc, weight_set=name)
                    assert_valid_result(self, res)
                    self.assertEqual(res["weight_set"], name)


# ---------------------------------------------------------------------------
class TestFactorBreakdown(unittest.TestCase):
    def test_breakdown_adds_up_to_the_score(self):
        for sc in SCENARIOS:
            if sc["detection"]["label"] == "BENIGN":
                continue
            with self.subTest(sc["id"]):
                res = run(sc)
                factors = res["factors"]
                self.assertEqual(set(factors), set(risk.ALL_FACTORS))
                self.assertAlmostEqual(sum(f["weight"] for f in factors.values()), 1.0, delta=0.001)
                total = sum(f["contribution"] for f in factors.values())
                self.assertLessEqual(abs(total - res["score"]), 0.5 + 0.05)
                for f in factors.values():
                    if f["value"] is not None:
                        self.assertTrue(0 <= f["value"] <= 100)

    def test_pdf_example_numbers(self):
        f = run(SCEN["C1"])["factors"]
        self.assertEqual(f["confidence"]["value"], 94.0)
        self.assertEqual(f["attack_severity"]["value"], 70.0)
        self.assertEqual(f["device_criticality"]["value"], 75.0)
        self.assertEqual(f["persistence"]["value"], 100.0)   # 431 attempts >= cap
        self.assertEqual(f["source_trust"]["value"], 60.0)   # internal, unknown device
        self.assertEqual(f["behavioral_deviation"]["value"], 100.0)  # port 22 not expected on a camera

    def test_optional_factor_is_skipped_and_weights_rescaled(self):
        det, ev, prof = make()
        prof = {k: v for k, v in prof.items() if k != "expected_ports"}
        res = assess(det, ev, prof)
        dev = res["factors"]["behavioral_deviation"]
        self.assertIsNone(dev["value"])
        self.assertEqual(dev["weight"], 0.0)
        self.assertAlmostEqual(sum(f["weight"] for f in res["factors"].values()), 1.0, delta=0.001)
        total = sum(f["contribution"] for f in res["factors"].values())
        self.assertLessEqual(abs(total - res["score"]), 0.55)  # score really is the re-scaled average
        assert_valid_result(self, res)

    def test_worst_case_scores_near_100_even_without_optional_factors(self):
        # Worst case: external source counts as 90 (not 100) by design, so the
        # re-scaled average is 94 / 0.95 = 98.9 -> 99. Without re-scaling it
        # would be only 94.
        det = {"label": "ATTACK", "attack_type": "device_takeover", "confidence": 1.0}
        ev = {"src_ip": "203.0.113.5", "failed_attempts": 10 ** 6}
        prof = {"criticality": "critical"}  # no expected_ports, no dst_port -> deviation skipped
        res = assess(det, ev, prof)
        self.assertEqual((res["score"], res["level"]), (99, "Critical"))
        self.assertIsNone(res["factors"]["behavioral_deviation"]["value"])

    def test_attempts_use_the_larger_of_the_two_counters(self):
        self.assertEqual(score_of(failed=5, conns=200), score_of(failed=200, conns=5))


# ---------------------------------------------------------------------------
class TestMonotonic(unittest.TestCase):
    """Risk scores must rise with severity (project evaluation criterion)."""

    def _non_decreasing(self, scores):
        self.assertEqual(scores, sorted(scores), scores)

    def test_attack_severity(self):
        order = ["port_scan", "unexpected_protocol", "spoofing", "brute_force", "dos", "ddos", "mirai", "device_takeover"]
        scores = [score_of(attack=a) for a in order]
        self._non_decreasing(scores)
        self.assertLess(scores[0], scores[-1])

    def test_device_criticality(self):
        det, ev, _ = make()
        scores = []
        for crit in ("low", "medium", "high", "critical"):
            prof = dict(DEVICES["CAM-001"], criticality=crit)
            scores.append(assess(det, ev, prof)["score"])
        self._non_decreasing(scores)
        self.assertLess(scores[0], scores[-1])

    def test_attempts(self):
        scores = [score_of(failed=n) for n in (0, 1, 5, 20, 100, 300, 5000)]
        self._non_decreasing(scores)
        self.assertLess(scores[0], scores[-1])

    def test_confidence(self):
        scores = [score_of(conf=c) for c in (0.0, 0.3, 0.6, 0.9, 1.0)]
        self._non_decreasing(scores)
        self.assertLess(scores[0], scores[-1])

    def test_source_trust(self):
        trusted = score_of(src="192.168.1.20")
        internal = score_of(src="192.168.1.77")
        external = score_of(src="203.0.113.5")
        self.assertLessEqual(trusted, internal)
        self.assertLessEqual(internal, external)
        self.assertLess(trusted, external)

    def test_unexpected_port_raises_score(self):
        self.assertLess(score_of(port=443), score_of(port=22))

    def test_same_attack_is_riskier_on_a_more_critical_device(self):
        bulb = score_of(device="BULB-001", port=80)
        camera = score_of(device="CAM-001", port=443)
        industrial = score_of(device="IND-001", port=502)
        self.assertLess(bulb, camera)
        self.assertLess(camera, industrial)


# ---------------------------------------------------------------------------
class TestRobustness(unittest.TestCase):
    def test_non_mapping_inputs_do_not_raise(self):
        for bad in (None, [], "text", 5, 3.5, object(), (1, 2)):
            with self.subTest(bad=bad):
                res = assess(bad, bad, bad)
                assert_valid_result(self, res)
                self.assertIn("invalid_detection", res["warnings"])

    def test_empty_inputs_give_a_cautious_nonzero_result(self):
        res = assess({}, {}, {})
        assert_valid_result(self, res)
        self.assertGreater(res["score"], 0)
        for code in ("label_missing_or_invalid", "invalid_confidence", "unknown_attack_type",
                     "missing_device_criticality", "no_attempt_data", "missing_source_ip"):
            self.assertIn(code, res["warnings"])

    def test_bad_numbers_fall_back_and_never_propagate(self):
        bad_values = [float("nan"), float("inf"), float("-inf"), -1, -1e9, True, False, "abc", "", "nan",
                      "inf", "1e999", 10 ** 400, [], {}, None, object()]
        for value in bad_values:
            with self.subTest(value=repr(value)):
                det = {"label": "ATTACK", "attack_type": "dos", "confidence": value}
                ev = {"src_ip": "203.0.113.5", "dst_port": value, "failed_attempts": value, "connection_attempts": value}
                assert_valid_result(self, assess(det, ev, DEVICES["CAM-001"]))

    def test_confidence_out_of_range_is_not_trusted(self):
        for bad in (1.5, -0.1, 94, "94"):
            with self.subTest(bad=bad):
                res = assess(*make(conf=bad))
                self.assertIn("invalid_confidence", res["warnings"])
                self.assertEqual(res["factors"]["confidence"]["value"], 50.0)  # the configured default

    def test_numeric_strings_from_csv_work_like_numbers(self):
        det, ev, prof = make(conf=0.94, failed=431, port=22)
        ev_str = dict(ev, failed_attempts="431", dst_port="22", connection_attempts="0")
        det_str = dict(det, confidence="0.94")
        self.assertEqual(assess(det, ev, prof)["score"], assess(det_str, ev_str, prof)["score"])

    def test_huge_attempt_count_is_capped(self):
        res = assess(*make(failed=10 ** 18))
        self.assertEqual(res["factors"]["persistence"]["value"], 100.0)

    def test_attack_name_variants(self):
        cases = {
            "DDoS-ICMP_Flood": "ddos", "DoS-TCP_Flood": "dos", "Recon-PortScan": "reconnaissance",
            "DictionaryBruteForce": "brute_force", "Brute Force": "brute_force", "BRUTE-FORCE": "brute_force",
            "Mirai-greeth_flood": "mirai", "Port Scan": "port_scan", "  Spoofing ": "spoofing",
            "MITM-ArpSpoofing": "spoofing", "Web-Based": "web_based",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                res = assess(*make(attack=name))
                self.assertEqual(res["factors"]["attack_severity"]["detail"], expected)
                self.assertNotIn("unknown_attack_type", res["warnings"])

    def test_unknown_attack_uses_cautious_default_and_warns(self):
        res = assess(*make(attack="zero_day_thing"))
        self.assertIn("unknown_attack_type", res["warnings"])
        self.assertEqual(res["factors"]["attack_severity"]["value"], 60.0)

    def test_similar_looking_names_do_not_match_by_accident(self):
        for name in ("dosage", "ddosx", "reconnaissanceX", "brute", "mirai2"):
            with self.subTest(name=name):
                self.assertIn("unknown_attack_type", assess(*make(attack=name))["warnings"])

    def test_missing_or_bad_device_profile_is_treated_as_important(self):
        det, ev, _ = make()
        for prof in (None, {}, {"criticality": "banana"}, {"criticality": 5}, {"criticality": None}):
            with self.subTest(prof=prof):
                res = assess(det, ev, prof)
                self.assertEqual(res["factors"]["device_criticality"]["value"], 75.0)
                self.assertTrue({"missing_device_profile", "missing_device_criticality", "unknown_device_criticality"} & set(res["warnings"]))

    def test_criticality_is_case_and_space_insensitive(self):
        det, ev, _ = make()
        a = assess(det, ev, dict(DEVICES["CAM-001"], criticality="High"))["score"]
        b = assess(det, ev, dict(DEVICES["CAM-001"], criticality=" HIGH "))["score"]
        self.assertEqual(a, b)

    def test_ip_handling(self):
        trusted = assess(*make(src="192.168.1.20"))["factors"]["source_trust"]["detail"]
        mapped = assess(*make(src="::ffff:192.168.1.20"))["factors"]["source_trust"]["detail"]
        self.assertEqual((trusted, mapped), ("trusted_internal", "trusted_internal"))
        cases = {
            "192.168.1.77": "internal_unknown", "10.1.2.3": "internal_unknown", "172.16.5.5": "internal_unknown",
            "172.32.0.1": "external", "203.0.113.5": "external", "8.8.8.8": "external",
            "fe80::1": "external", "not an ip": "external", "": "external", "999.1.1.1": "external",
            "192.168.1.20/32": "external", "192.168.1.20 ": "trusted_internal",
        }
        for ip, expected in cases.items():
            with self.subTest(ip=ip):
                self.assertEqual(assess(*make(src=ip))["factors"]["source_trust"]["detail"], expected)
        for ip in (None, 12345, ["192.168.1.20"], b"192.168.1.20", "1" * 500):
            with self.subTest(ip=repr(ip)[:30]):
                res = assess(*make(src=ip))
                self.assertEqual(res["factors"]["source_trust"]["detail"], "external")

    def test_fuzz_never_raises_and_always_returns_valid_result(self):
        rng = random.Random(20261020)
        pool = [None, True, False, 0, 1, -1, 7, 431, 3.14, 1e308, -1e308, float("nan"), float("inf"), 10 ** 400,
                "", " ", "ATTACK", "BENIGN", "benign", "dos", "x" * 5000, "192.168.1.20", "203.0.113.5", "22", "high",
                "\x00\n\r\t", "<script>", "'; DROP TABLE incidents;--", [], [1, 2], ["22", 554], {}, {"a": 1}, object(), (1,)]
        det_keys = ["label", "attack_type", "confidence", "mitre_technique", "x"]
        ev_keys = ["src_ip", "dst_port", "failed_attempts", "connection_attempts", "protocol", "x"]
        prof_keys = ["criticality", "expected_ports", "expected_services", "expected_protocols", "ip", "x"]

        def rand_map(keys):
            return {k: rng.choice(pool) for k in keys if rng.random() < 0.8}

        for _ in range(4000):
            res = assess(rand_map(det_keys), rand_map(ev_keys), rand_map(prof_keys))
            assert_valid_result(self, res)


# ---------------------------------------------------------------------------
class TestSecurity(unittest.TestCase):
    def test_inputs_are_not_modified(self):
        det, ev, prof = make()
        before = copy.deepcopy((det, ev, prof))
        assess(det, ev, prof)
        self.assertEqual((det, ev, prof), before)

    def test_hostile_strings_never_reach_the_result(self):
        payload = "<script>alert(1)</script>'; DROP TABLE incidents;--\n\x1b[31m"
        det = {"label": "ATTACK", "attack_type": payload, "confidence": 0.9, "mitre_technique": payload}
        ev = {"src_ip": payload, "dst_port": payload, "failed_attempts": payload, "device_id": payload, "protocol": payload}
        prof = {"criticality": payload, "expected_ports": [payload], "device_id": payload}
        text = json.dumps(assess(det, ev, prof))
        for needle in ("script", "DROP", "incidents", "\\x1b", "alert"):
            self.assertNotIn(needle, text)

    def test_every_string_in_the_result_comes_from_a_small_safe_vocabulary(self):
        det, ev, prof = make(attack="DDoS-ICMP_Flood", src="192.168.1.20")
        res = assess(det, ev, prof)
        allowed = set(risk.ALL_FACTORS)

        def strings(obj):
            if isinstance(obj, str):
                yield obj
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    yield from strings(k)
                    yield from strings(v)
            elif isinstance(obj, list):
                for v in obj:
                    yield from strings(v)

        for s in strings(res):
            self.assertRegex(s, r"^[A-Za-z0-9_=]{1,64}$", s)
        self.assertTrue(allowed <= set(res["factors"]))

    def test_spoofed_trusted_ip_cannot_hide_an_attack(self):
        """An attacker who fakes a trusted source IP lowers the score by at most
        the capped weight of source_trust, so a Critical attack stays at least High."""
        cfg = load_config()
        max_drop = cfg["limits"]["max_source_trust_weight"] * 100.0
        for sid in ("H1", "H2", "C1", "C2", "C3"):
            sc = SCEN[sid]
            real = run(sc)["score"]
            ev = dict(sc["event"], src_ip="192.168.1.20")  # spoofed trusted address
            spoofed = assess(sc["detection"], ev, DEVICES[sc["device"]])["score"]
            self.assertLessEqual(real - spoofed, max_drop, sid)
        c2 = SCEN["C2"]
        spoofed_c2 = assess(c2["detection"], dict(c2["event"], src_ip="192.168.1.20"), DEVICES["IND-001"])
        self.assertIn(spoofed_c2["level"], ("High", "Critical"))

    def test_result_is_deterministic(self):
        sc = SCEN["C1"]
        self.assertEqual(run(sc), run(sc))

    def test_result_has_the_contract_fields(self):
        res = run(SCEN["H1"])
        self.assertTrue({"score", "level", "factors"} <= set(res))


# ---------------------------------------------------------------------------
class TestConfig(unittest.TestCase):
    @staticmethod
    def base():
        with open(DEFAULT_YAML, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)

    def load_raw(self, raw):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "w.yaml")
            with open(path, "w", encoding="utf-8") as fh:
                yaml.safe_dump(raw, fh)
            return load_config(path)

    def load_text(self, text, as_bytes=None):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "w.yaml")
            with open(path, "wb") as fh:
                fh.write(as_bytes if as_bytes is not None else text.encode("utf-8"))
            return load_config(path)

    def test_default_config_is_valid(self):
        cfg = load_config()
        self.assertGreaterEqual(len(cfg["weight_sets"]), 2)
        for name, w in cfg["weight_sets"].items():
            self.assertAlmostEqual(sum(w.values()), 1.0, places=9, msg=name)
        self.assertEqual(cfg["active_weight_set"], "balanced")
        self.assertEqual(cfg["levels"], {"medium": 30, "high": 60, "critical": 80})

    def test_valid_modified_config_is_accepted(self):
        raw = self.base()
        raw["weight_sets"]["balanced"].update(confidence=0.25, attack_severity=0.20)
        self.assertAlmostEqual(sum(self.load_raw(raw)["weight_sets"]["balanced"].values()), 1.0)

    def test_bad_configs_are_rejected(self):
        def m_sum(r): r["weight_sets"]["balanced"]["confidence"] = 0.5
        def m_negative(r): r["weight_sets"]["balanced"].update(confidence=-0.1, attack_severity=0.55)
        def m_core_zero(r): r["weight_sets"]["balanced"].update(source_trust=0.0, attack_severity=0.35)
        def m_dominant(r): r["weight_sets"]["balanced"].update(confidence=0.45, attack_severity=0.20, device_criticality=0.15, persistence=0.05, source_trust=0.05, behavioral_deviation=0.05, potential_impact=0.05)
        def m_trust_big(r): r["weight_sets"]["balanced"].update(source_trust=0.30, attack_severity=0.05)
        def m_unknown_top(r): r["extra"] = 1
        def m_missing_top(r): del r["levels"]
        def m_unknown_factor(r): r["weight_sets"]["balanced"]["bonus"] = 0.0
        def m_missing_factor(r): del r["weight_sets"]["balanced"]["persistence"]
        def m_active(r): r["active_weight_set"] = "nope"
        def m_set_name(r): r["weight_sets"]["Bad Name!"] = dict(r["weight_sets"]["balanced"])
        def m_levels_order(r): r["levels"] = {"medium": 60, "high": 30, "critical": 80}
        def m_levels_float(r): r["levels"]["medium"] = 30.5
        def m_levels_big(r): r["levels"]["critical"] = 101
        def m_scale_missing(r): del r["backend_scale"]
        def m_scale_order(r): r["backend_scale"] = {"medium": 61, "high": 31, "critical": 91}
        def m_scale_float(r): r["backend_scale"]["high"] = 61.5
        def m_scale_big(r): r["backend_scale"]["critical"] = 101
        def m_scale_key(r): r["backend_scale"]["extreme"] = 99
        def m_crit_dec(r): r["device_criticality"]["high"] = 10
        def m_trust_dec(r): r["source_trust"]["trusted"] = 95
        def m_table_range(r): r["attack_severity"]["dos"] = 150
        def m_table_nan(r): r["attack_severity"]["dos"] = float("nan")
        def m_table_bool(r): r["attack_severity"]["dos"] = True
        def m_table_str(r): r["attack_severity"]["dos"] = "75"
        def m_table_mismatch(r): del r["attack_impact"]["dos"]
        def m_alias_unknown(r): r["attack_aliases"]["foo"] = "nonexistent"
        def m_alias_shadow(r): r["attack_aliases"]["dos"] = "ddos"
        def m_alias_name(r): r["attack_aliases"]["Bad Alias"] = "dos"
        def m_attack_name(r): r["attack_severity"]["Bad Name"] = 1; r["attack_impact"]["Bad Name"] = 1
        def m_name_trailing_newline(r): r["attack_severity"]["bad\n"] = 1; r["attack_impact"]["bad\n"] = 1
        def m_public_net(r): r["source_trust"]["internal_networks"].append("8.8.8.0/24")
        def m_all_net(r): r["source_trust"]["internal_networks"] = ["0.0.0.0/0"]
        def m_bad_net(r): r["source_trust"]["internal_networks"] = ["not-a-network"]
        def m_host_bits(r): r["source_trust"]["internal_networks"] = ["192.168.1.5/24"]
        def m_trusted_out(r): r["source_trust"]["trusted_ips"].append("8.8.8.8")
        def m_trusted_bad(r): r["source_trust"]["trusted_ips"] = ["300.1.1.1"]
        def m_trusted_type(r): r["source_trust"]["trusted_ips"] = [12345]
        def m_default_conf(r): r["defaults"]["confidence"] = 2
        def m_cap_zero(r): r["persistence"]["cap"] = 0
        def m_version(r): r["version"] = 2
        def m_limit_zero(r): r["limits"]["max_single_weight"] = 0.0
        def m_not_dict(r): r["weight_sets"] = ["x"]

        mutators = [v for k, v in sorted(locals().items()) if k.startswith("m_")]
        self.assertGreaterEqual(len(mutators), 35)
        for mutate in mutators:
            with self.subTest(mutation=mutate.__name__):
                raw = copy.deepcopy(self.base())
                mutate(raw)
                with self.assertRaises(RiskConfigError):
                    self.load_raw(raw)

    def test_duplicate_keys_are_rejected(self):
        with open(DEFAULT_YAML, "r", encoding="utf-8") as fh:
            text = fh.read()
        with self.assertRaises(RiskConfigError):
            self.load_text(text + "\nversion: 1\n")
        with self.assertRaises(RiskConfigError):
            self.load_text(text.replace("  trusted: 20", "  trusted: 20\n  trusted: 25"))

    def test_malformed_unsafe_and_oversized_files_are_rejected(self):
        bad_texts = [
            "version: [unclosed",
            "- just\n- a\n- list\n",
            "just a string",
            "",
            "!!python/object/apply:os.system ['echo pwned']",
            "version: !!python/object/apply:os.getcwd []\n",
            "a: &a [*a]\n",
        ]
        for text in bad_texts:
            with self.subTest(text=text[:30]):
                with self.assertRaises(RiskConfigError):
                    self.load_text(text)
        with self.assertRaises(RiskConfigError):
            self.load_text("", as_bytes=b"\xff\xfe\x00bad utf8")
        with self.assertRaises(RiskConfigError):
            self.load_text("", as_bytes=b"#" * (risk.MAX_CONFIG_BYTES + 10))

    def test_missing_file_is_rejected(self):
        with self.assertRaises(RiskConfigError):
            load_config(os.path.join(tempfile.gettempdir(), "definitely_not_here_weights.yaml"))

    def test_hash_pinning_detects_tampering(self):
        good = risk.config_sha256(DEFAULT_YAML)
        self.assertEqual(len(good), 64)
        load_config(DEFAULT_YAML, expected_sha256=good)
        load_config(DEFAULT_YAML, expected_sha256=good.upper())
        for bad in ("0" * 64, "", "abc", None.__class__, 123):
            with self.subTest(bad=bad):
                with self.assertRaises(RiskConfigError):
                    load_config(DEFAULT_YAML, expected_sha256=bad)

    def test_assess_rejects_unvalidated_config_and_unknown_weight_set(self):
        det, ev, prof = make()
        for bad_cfg in ({}, {"_validated": True}, self.base(), "risk_weights.yaml", 5):
            with self.subTest(cfg=repr(bad_cfg)[:30]):
                with self.assertRaises(RiskConfigError):
                    assess(det, ev, prof, config=bad_cfg)
        for bad_set in ("nope", "", None.__class__, 5, ["balanced"]):
            with self.subTest(weight_set=repr(bad_set)):
                with self.assertRaises(RiskConfigError):
                    assess(det, ev, prof, weight_set=bad_set)

    def test_changing_weights_changes_scores_but_not_validity(self):
        raw = self.base()
        raw["active_weight_set"] = "device_centric"
        cfg = self.load_raw(raw)
        det, ev, _ = make()
        bulb = dict(DEVICES["BULB-001"])
        cam = dict(DEVICES["CAM-001"])
        gap_dc = assess(det, ev, cam, config=cfg)["score"] - assess(det, ev, bulb, config=cfg)["score"]
        gap_bal = assess(det, ev, cam)["score"] - assess(det, ev, bulb)["score"]
        self.assertGreater(gap_dc, gap_bal)  # device_centric separates devices more

    def test_reload_config_returns_a_valid_config(self):
        cfg = risk.reload_config()
        self.assertEqual(cfg["active_weight_set"], "balanced")


class TestBackendScore(unittest.TestCase):
    """to_backend_score(): our 0/30/60/80 levels must read the same on the backend's 0/31/61/91 scale."""

    BACKEND = {"medium": 31, "high": 61, "critical": 91}

    @staticmethod
    def backend_level(value):
        if value >= 91:
            return "Critical"
        if value >= 61:
            return "High"
        if value >= 31:
            return "Medium"
        return "Low"

    def test_every_score_keeps_its_level(self):
        for score in range(0, 101):
            with self.subTest(score=score):
                self.assertEqual(self.backend_level(risk.to_backend_score(score)), level_for(score))

    def test_boundaries(self):
        self.assertEqual(risk.to_backend_score(0), 0)
        self.assertEqual(risk.to_backend_score(30), 31)
        self.assertEqual(risk.to_backend_score(60), 61)
        self.assertEqual(risk.to_backend_score(80), 91)
        self.assertEqual(risk.to_backend_score(100), 100)
        self.assertEqual(risk.to_backend_score(79), 89)   # the last High stays High
        self.assertEqual(risk.to_backend_score(81), 91 + 1 * 9 // 20)

    def test_never_decreases_and_stays_in_range(self):
        values = [risk.to_backend_score(s) for s in range(0, 101)]
        self.assertEqual(values, sorted(values))
        self.assertTrue(all(0 <= v <= 100 for v in values))

    def test_fractions_and_out_of_range(self):
        self.assertEqual(risk.to_backend_score(29.99), risk.to_backend_score(29))
        self.assertEqual(risk.to_backend_score(-5), 0)
        self.assertEqual(risk.to_backend_score(500), 100)

    def test_bad_values_are_refused(self):
        for bad in (None, "abc", float("nan"), float("inf"), True, [80], {}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    risk.to_backend_score(bad)

    def test_other_scales_still_keep_levels(self):
        for scale in ({"medium": 25, "high": 50, "critical": 75}, {"medium": 40, "high": 70, "critical": 100},
                      {"medium": 5, "high": 10, "critical": 15}):   # heavy compression: rounding would cross a level
            raw = TestConfig.base()
            raw["backend_scale"] = scale
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "w.yaml")
                with open(path, "w", encoding="utf-8") as fh:
                    yaml.safe_dump(raw, fh)
                cfg = load_config(path)
            for score in range(0, 101):
                out = risk.to_backend_score(score, cfg)
                level = level_for(score, cfg)
                lo = {"Low": 0, "Medium": scale["medium"], "High": scale["high"], "Critical": scale["critical"]}[level]
                self.assertGreaterEqual(out, lo, (score, scale))
                hi = {"Low": scale["medium"], "Medium": scale["high"], "High": scale["critical"], "Critical": 101}[level]
                self.assertLess(out, hi, (score, scale))

    def test_the_score_of_assess_is_not_changed(self):
        # the mapping is for publishing only: assess() still returns the internal score
        result = assess({"label": "ATTACK", "attack_type": "DoS", "confidence": 0.95}, {"src_ip": "8.8.8.8"}, {"criticality": "critical"})
        self.assertLessEqual(result["score"], 100)
        self.assertEqual(level_for(result["score"]), result["level"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
