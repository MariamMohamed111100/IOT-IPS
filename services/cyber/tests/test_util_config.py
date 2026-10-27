import pytest

from cyb.config import Settings
from cyb.util import (
    clean_text,
    finite_number,
    is_blockable,
    parse_networks,
    valid_ip,
    valid_mac,
    valid_port,
)


@pytest.mark.parametrize("value", ["203.0.113.9", "192.168.1.15", "2001:db8::1", " 10.0.0.1 "])
def test_valid_ip_accepts_single_addresses(value):
    assert valid_ip(value) == value.strip()


@pytest.mark.parametrize("value", [
    "", "10.0.0.0/8", "fe80::1%eth0", "example.com", "1.2.3", "1.2.3.4; rm -rf /", "-j ACCEPT",
    None, 5, ["1.1.1.1"], "1" * 60])
def test_valid_ip_rejects_everything_else(value):
    assert valid_ip(value) is None


@pytest.mark.parametrize("ip", ["127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1",
                                "255.255.255.255", "::1", "ff02::1", "fe80::1"])
def test_special_purpose_addresses_are_not_blockable(ip):
    assert not is_blockable(ip)


def test_lan_and_public_addresses_are_blockable():
    assert is_blockable("192.168.1.77") and is_blockable("203.0.113.9")


def test_valid_mac_normalises_and_rejects():
    assert valid_mac("DE-AD-BE-EF-00-01") == "de:ad:be:ef:00:01"
    for bad in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "de:ad:be:ef:00", "zz:zz:zz:zz:zz:zz",
                None, 7):
        assert valid_mac(bad) is None


def test_ports_and_numbers_are_strict():
    assert valid_port(22) == 22 and valid_port(65535) == 65535
    for bad in (0, 65536, True, "22", 1.5, None):
        assert valid_port(bad) is None
    assert finite_number(3) == 3.0 and finite_number(2.5) == 2.5
    for bad in (True, "3", float("nan"), float("inf"), None):
        assert finite_number(bad) is None


def test_clean_text_removes_control_characters_and_truncates():
    assert clean_text("a\nb\x00c<script>", 50) == "a_b_c_script_"
    assert len(clean_text("x" * 500, 64)) == 64


def test_parse_networks_rejects_garbage():
    assert len(parse_networks("10.0.0.0/8, 192.168.1.5,")) == 2
    with pytest.raises(ValueError):
        parse_networks("not-a-network")


def test_default_settings_from_empty_env():
    s = Settings.from_env({})
    assert s.firewall == "blocklist" and s.autoblock == ("cyber.port_scan", "cyber.brute_force")
    assert s.portscan_min_targets == 15 and s.brute_min_attempts == 5
    assert any(net.network_address.is_loopback for net in s.never_block)


def test_env_overrides_are_applied():
    s = Settings.from_env({"PORTSCAN_MIN_TARGETS": "30", "CYBER_FIREWALL": "IPTABLES",
                           "ROGUE_ARP": "true", "CYBER_NEVER_BLOCK": "192.168.1.1",
                           "CYBER_AUTOBLOCK": ""})
    assert s.portscan_min_targets == 30 and s.firewall == "iptables" and s.rogue_arp
    assert s.autoblock == () and len(s.never_block) == 3


@pytest.mark.parametrize("env", [
    {"CYBER_FIREWALL": "yolo"}, {"PORTSCAN_MIN_TARGETS": "abc"}, {"PORTSCAN_MIN_TARGETS": "1"},
    {"BRUTE_WINDOW_S": "nan"}, {"BRUTE_WINDOW_S": "-5"}, {"CYBER_AUTOBLOCK": "cyber.bogus"},
    {"BLOCK_MIN_S": "100", "BLOCK_MAX_S": "10"}, {"ROGUE_ARP": "maybe"},
    {"CYBER_NEVER_BLOCK": "999.1.1.1"}])
def test_invalid_configuration_fails_fast(env):
    with pytest.raises(ValueError):
        Settings.from_env(env)
