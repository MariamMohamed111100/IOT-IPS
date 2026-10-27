import pytest
import yaml
from conftest import REPO

from eng.policy import attacker_ip, load_policy, parse_policy


def raw():
    return yaml.safe_load((REPO / "config" / "risk_scores.yaml").read_text())


def test_real_file_loads_and_levels():
    p = load_policy(REPO / "config" / "risk_scores.yaml")
    assert [p.level_for(s) for s in (0, 30, 31, 60, 61, 90, 91, 100)] == [
        "low", "low", "medium", "medium", "high", "high", "critical", "critical"]


def test_bad_action_rejected():
    r = raw()
    r["responses"]["high"].append("explode")
    with pytest.raises(ValueError):
        parse_policy(r)


def test_bad_correlation_rejected():
    r = raw()
    r["correlations"] = [{"name": "x", "requires": ["face.unknown"], "bonus": 5}]
    with pytest.raises(ValueError):
        parse_policy(r)


@pytest.mark.parametrize("bad", ["127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "fe80::1%eth0",
                                 "nope", 5, None, "1.2.3.4/24", "x" * 60])
def test_attacker_ip_rejects(bad):
    assert attacker_ip(bad, ()) is None


def test_attacker_ip_accepts_lan_and_honours_never_block():
    assert attacker_ip("192.168.1.15", ()) == "192.168.1.15"
    p = parse_policy(raw(), extra_never_block="192.168.1.0/24")
    assert attacker_ip("192.168.1.15", p.never_block) is None
