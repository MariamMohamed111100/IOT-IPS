"""Tests for detector.py. Run:  python -m pytest -v"""
import copy
import os

import pytest
import yaml

from iot_ips.detector import DetectorConfigError, detect, resolve_direction, validate_config
from iot_ips.paths import CONFIG_DIR

CAMERA = {
    "device_id": "cam-01",
    "device_type": "ip_camera",
    "expected_protocols": ["TCP", "UDP"],
    "expected_ports": [80, 554],
}


def benign_event(**over):
    e = {
        "device_id": "cam-01", "timestamp": "2026-10-21T10:00:00",
        "src_ip": "192.168.1.20", "dst_ip": "192.168.1.50",
        "dst_port": 554, "protocol": "TCP",
        "failed_attempts": 0, "connection_attempts": 3,
        "Rate": 15.0, "syn_count": 1, "unique_dst_ports": 1, "unique_dst_ips": 1,
    }
    e.update(over)
    return e


# ---------- benign ----------
def test_benign_normal_traffic():
    d = detect(benign_event(), CAMERA)
    assert d["label"] == "BENIGN"
    assert d["attack_type"] == "None"
    assert d["mitre_technique"] is None


# ---------- one test per rule ----------
def test_port_scan():
    d = detect(benign_event(unique_dst_ports=150), CAMERA)
    assert d["label"] == "ATTACK"
    assert d["attack_type"] == "Port Scan"
    assert d["mitre_technique"] == "T1046"


def test_brute_force_ssh():
    d = detect(benign_event(dst_port=22, failed_attempts=300, connection_attempts=320), None)
    assert d["attack_type"] == "Brute Force"
    assert d["mitre_technique"] == "T1110"
    assert d["confidence"] >= 0.9


def test_brute_force_telnet_and_rtsp():
    for port in (23, 554):
        d = detect(benign_event(dst_port=port, failed_attempts=120), None)
        assert d["attack_type"] == "Brute Force"


def test_dos_high_rate():
    d = detect(benign_event(Rate=9000.0, connection_attempts=500), CAMERA)
    assert d["attack_type"] == "DoS"
    assert d["mitre_technique"] == "T1498"


def test_dos_syn_flood():
    d = detect(benign_event(syn_count=500, connection_attempts=500), CAMERA)
    assert d["attack_type"] == "DoS"


def test_unexpected_port():
    d = detect(benign_event(dst_port=4444), CAMERA)
    assert d["attack_type"] == "Unexpected Protocol/Port"
    assert d["mitre_technique"] == "T1571"


def test_unexpected_protocol():
    d = detect(benign_event(protocol="ICMP"), CAMERA)
    assert d["attack_type"] == "Unexpected Protocol/Port"


def test_unexpected_needs_profile():
    # without a profile there is nothing to compare against
    assert detect(benign_event(dst_port=4444), None)["label"] == "BENIGN"


# ---------- confidence behaviour ----------
def test_confidence_rises_with_strength():
    weak = detect(benign_event(Rate=2100.0, connection_attempts=5000))["confidence"]
    strong = detect(benign_event(Rate=9000.0, connection_attempts=5000))["confidence"]
    assert 0 <= weak < strong <= 1


def test_dos_confidence_follows_the_weaker_condition():
    """A high rate with barely enough connections is a weak DoS; many connections with barely enough rate too."""
    few_connections = detect(benign_event(Rate=20000.0, connection_attempts=500))
    many_connections = detect(benign_event(Rate=20000.0, connection_attempts=5000))
    barely_fast = detect(benign_event(Rate=2100.0, connection_attempts=50000))
    assert few_connections["attack_type"] == many_connections["attack_type"] == "DoS"
    assert few_connections["confidence"] < many_connections["confidence"]
    assert barely_fast["confidence"] < many_connections["confidence"]


def test_a_port_scan_is_not_reported_as_dos():
    """1,000 probes = 1,000 connections with one SYN each (what a flow engine measures)."""
    event = benign_event(Rate=70.0, syn_count=1000, connection_attempts=1000, unique_dst_ports=1000, dst_port=8000)
    result = detect(event)
    assert result["attack_type"] == "Port Scan"


def test_most_confident_rule_wins():
    d = detect(benign_event(Rate=9000.0, connection_attempts=500, unique_dst_ports=21), CAMERA)
    assert d["attack_type"] == "DoS"


# ---------- evasion tests (KNOWN LIMITATIONS: the rules miss these) ----------
def test_evasion_slow_scan_is_missed():
    # 5 ports spread over hours: stays under min_unique_ports (20)
    d = detect(benign_event(unique_dst_ports=5), CAMERA)
    assert d["label"] == "BENIGN"  # limitation: ML / time-window rules needed


def test_evasion_low_rate_brute_force_is_missed():
    # 10 failed SSH logins: stays under min_failed_attempts (50)
    d = detect(benign_event(dst_port=22, failed_attempts=10, connection_attempts=12), None)
    assert d["label"] == "BENIGN"


def test_evasion_low_rate_dos_is_missed():
    d = detect(benign_event(Rate=300.0, syn_count=20, connection_attempts=500), CAMERA)
    assert d["label"] == "BENIGN"


def test_evasion_attack_on_expected_port_and_protocol_is_missed():
    # attacker uses only allowed port/protocol with low volume
    d = detect(benign_event(dst_port=80, protocol="TCP", Rate=50.0), CAMERA)
    assert d["label"] == "BENIGN"


# ---------- robustness ----------
def test_missing_fields_do_not_crash():
    assert detect({})["label"] == "BENIGN"
    assert detect(None)["label"] == "BENIGN"


def test_csv_strings_nan_and_inf():
    d = detect({"Rate": "9000", "dst_port": "80", "connection_attempts": "500"})  # CSV gives strings
    assert d["attack_type"] == "DoS"
    assert detect({"Rate": "nan", "syn_count": "inf"})["label"] == "BENIGN"
    assert detect({"failed_attempts": "abc", "dst_port": "22"})["label"] == "BENIGN"


def test_output_contract_keys():
    d = detect(benign_event(Rate=9000.0, connection_attempts=500))
    assert set(d) == {"label", "attack_type", "confidence", "mitre_technique"}


# ---------- integration findings (the sample events and device profiles with application protocols) ----------
APP_PROFILE = {"device_id": "CAM-001", "expected_protocols": ["RTSP", "HTTPS", "DNS"], "expected_ports": [554, 443]}


def test_transport_name_is_not_compared_with_application_protocols():
    # TCP on an expected port must not be "unexpected" when the profile lists RTSP/HTTPS/DNS
    assert detect(benign_event(dst_port=554, protocol="TCP"), APP_PROFILE)["label"] == "BENIGN"
    assert detect(benign_event(dst_port=443, protocol="UDP"), APP_PROFILE)["label"] == "BENIGN"


def test_unexpected_port_is_still_flagged_with_application_profile():
    assert detect(benign_event(dst_port=8080, protocol="TCP"), APP_PROFILE)["label"] == "ATTACK"


def test_application_protocol_mismatch_is_still_flagged():
    d = detect(benign_event(dst_port=554, protocol="TELNET"), APP_PROFILE)
    assert d["attack_type"] == "Unexpected Protocol/Port"


def test_normal_camera_clip_upload_rate_is_not_dos():
    # a benign sample event: 1040 packets/s upload to the cloud
    assert detect(benign_event(dst_port=443, Rate=1040.0), APP_PROFILE)["label"] == "BENIGN"


def test_real_flood_is_still_dos():
    assert detect(benign_event(Rate=12633.0, connection_attempts=18000))["attack_type"] == "DoS"


# ---------- review fixes: brute force, DoS, direction, config validation ----------
CAM_REAL = {"device_id": "CAM-001", "ip": "192.168.1.50", "expected_protocols": ["RTSP", "HTTPS", "DNS", "NTP"],
            "expected_ports": [554, 443]}


def test_many_plain_connections_to_rtsp_are_not_brute_force():
    # live viewing: 150 connections to port 554 and no failed login at all
    assert detect(benign_event(dst_port=554, failed_attempts=0, connection_attempts=150), CAM_REAL)["label"] == "BENIGN"


def test_brute_force_counts_failed_attempts_only():
    assert detect(benign_event(dst_port=554, failed_attempts=10, connection_attempts=5000), CAM_REAL)["label"] == "BENIGN"
    assert detect(benign_event(dst_port=22, failed_attempts=60, connection_attempts=60), CAM_REAL)["attack_type"] == "Brute Force"


def test_fast_upload_with_few_connections_is_not_dos():
    # a clip upload: 4000 packets/s but 3 connections
    assert detect(benign_event(dst_port=443, Rate=4000.0, connection_attempts=3, src_ip="192.168.1.50",
                               dst_ip="52.29.14.7"), CAM_REAL)["label"] == "BENIGN"
    assert detect(benign_event(dst_port=443, syn_count=900, connection_attempts=3), CAM_REAL)["label"] == "BENIGN"


def test_dos_needs_both_rate_and_connections():
    assert detect(benign_event(Rate=9000.0, connection_attempts=500), CAM_REAL)["attack_type"] == "DoS"
    assert detect(benign_event(Rate=100.0, connection_attempts=5000), CAM_REAL)["label"] == "BENIGN"


def test_outbound_traffic_is_not_unexpected():
    for port in (8883, 123, 53):
        e = benign_event(dst_port=port, src_ip="192.168.1.50", dst_ip="52.1.1.1", protocol="TCP")
        assert detect(e, CAM_REAL)["label"] == "BENIGN", port
    assert detect(benign_event(dst_port=8883, direction="outbound"), CAM_REAL)["label"] == "BENIGN"


def test_inbound_unexpected_port_is_still_flagged():
    assert detect(benign_event(dst_port=8883, direction="inbound"), CAM_REAL)["attack_type"] == "Unexpected Protocol/Port"
    # no direction given, destination is the device: derived as inbound
    assert detect(benign_event(dst_port=4444), CAM_REAL)["attack_type"] == "Unexpected Protocol/Port"


def test_unknown_direction_is_treated_as_inbound():
    assert resolve_direction({"dst_port": 4444}, None) == "inbound"
    assert resolve_direction({"direction": "sideways", "src_ip": "1.2.3.4"}, CAM_REAL) == "inbound"
    assert resolve_direction({"direction": " OUTBOUND "}, CAM_REAL) == "outbound"
    assert resolve_direction({"src_ip": "192.168.1.50"}, CAM_REAL) == "outbound"
    # an explicit direction beats the IP addresses
    assert resolve_direction({"direction": "inbound", "src_ip": "192.168.1.50"}, CAM_REAL) == "inbound"


def _write_rules(tmp_path, mutate):
    cfg = copy.deepcopy(yaml.safe_load((CONFIG_DIR / "detector_rules.yaml").read_text(encoding="utf-8")))
    mutate(cfg)
    path = os.path.join(str(tmp_path), "rules.yaml")
    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(cfg, handle)
    return path


def test_shipped_rules_file_is_valid():
    validate_config(yaml.safe_load((CONFIG_DIR / "detector_rules.yaml").read_text(encoding="utf-8")))


def test_misspelled_threshold_key_raises_instead_of_silently_disabling(tmp_path):
    def typo(cfg):
        rule = cfg["rules"]["brute_force"]
        rule["min_failed_atempts"] = rule.pop("min_failed_attempts")
    path = _write_rules(tmp_path, typo)
    with pytest.raises(DetectorConfigError):
        detect(benign_event(dst_port=22, failed_attempts=300), CAM_REAL, config_path=path)


@pytest.mark.parametrize("mutate", [
    lambda c: c["rules"]["dos"].pop("min_rate"),
    lambda c: c["rules"]["dos"].update(min_rat=1),
    lambda c: c["rules"].pop("port_scan"),
    lambda c: c["rules"].update(portscan=c["rules"]["port_scan"]),
    lambda c: c["rules"]["dos"].update(min_rate=-5),
    lambda c: c["rules"]["dos"].update(min_rate="fast"),
    lambda c: c["rules"]["dos"].update(base_confidence=1.5),
    lambda c: c["rules"]["dos"].update(base_confidence=0.99, max_confidence=0.5),
    lambda c: c["rules"]["dos"].update(enabled="yes"),
    lambda c: c["rules"]["brute_force"].update(target_ports=[]),
    lambda c: c["rules"]["brute_force"].update(target_ports=[22, "ssh"]),
    lambda c: c["settings"].update(benign_confidence=2),
    lambda c: c.update(extra=1),
    lambda c: c.pop("settings"),
], ids=lambda f: "case")
def test_bad_rules_files_are_refused(tmp_path, mutate):
    with pytest.raises(DetectorConfigError):
        detect(benign_event(), CAM_REAL, config_path=_write_rules(tmp_path, mutate))


def test_unreadable_or_empty_rules_file_is_refused(tmp_path):
    empty = os.path.join(str(tmp_path), "empty.yaml")
    open(empty, "w").close()
    with pytest.raises(DetectorConfigError):
        detect(benign_event(), CAM_REAL, config_path=empty)
    with pytest.raises(DetectorConfigError):
        detect(benign_event(), CAM_REAL, config_path=os.path.join(str(tmp_path), "missing.yaml"))


def test_disabled_rule_is_still_allowed(tmp_path):
    path = _write_rules(tmp_path, lambda c: c["rules"]["dos"].update(enabled=False))
    assert detect(benign_event(Rate=9000.0, connection_attempts=500), CAM_REAL, config_path=path)["label"] == "BENIGN"
