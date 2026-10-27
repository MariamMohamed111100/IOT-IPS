"""
detector.py - Rule-based IPS detector (Task 3, Phase 1: IPS without AI).

    detect(event, device_profile=None) -> Detection dict

Detection message (same contract the ML model will use next week):
    {
      "label": "BENIGN" | "ATTACK",
      "attack_type": str,
      "confidence": float 0..1,
      "mitre_technique": str | None
    }

The ML model only has to expose the same detect(event) function to replace
this file. Thresholds live in detector_rules.yaml.

Rules (all thresholds in config/detector_rules.yaml, validated when loaded):
  * dos         high Rate or SYN count AND many connections (a fast clip upload is not a DoS)
  * brute_force many FAILED logins on SSH/Telnet/RTSP (plain connections, e.g. live video, do not count)
  * port_scan   many unique destination ports or hosts
  * unexpected_traffic  INBOUND traffic on a port/protocol the device profile does not list.
                Outbound traffic (the camera talking to its cloud, DNS, NTP) is not judged by this rule.

Direction: event["direction"] is "inbound" (towards the device) or "outbound" (from the device).
If it is missing or invalid it is derived from the device's IP in the profile; if that is impossible
the event is treated as inbound (the cautious choice: the rule still applies).

A configuration file with a missing, misspelled or out-of-range key raises DetectorConfigError.
It never silently disables a rule.
"""
import math
import os

import yaml

from . import paths as _paths

DEFAULT_CONFIG = str(_paths.CONFIG_DIR / "detector_rules.yaml")

_config_cache = {}
TRANSPORT_PROTOCOLS = {"TCP", "UDP", "ICMP", "IGMP", "GRE", "ARP", "ICMPV6", "SCTP"}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
class DetectorConfigError(ValueError):
    """detector_rules.yaml is missing a key, has an unknown key or a bad value."""


_NUMBER_KEYS = {"min_rate", "min_syn_count", "min_connection_attempts", "min_failed_attempts",
                "min_unique_ports", "min_unique_destinations"}
_CONFIDENCE_KEYS = {"base_confidence", "max_confidence", "confidence_one_violation", "confidence_both_violations"}
# rule name -> (required keys, optional keys)
_RULE_KEYS = {
    "dos": ({"attack_type", "mitre_technique", "min_rate", "min_syn_count", "min_connection_attempts",
             "base_confidence", "max_confidence"}, {"enabled"}),
    "brute_force": ({"attack_type", "mitre_technique", "target_ports", "min_failed_attempts",
                     "base_confidence", "max_confidence"}, {"enabled"}),
    "port_scan": ({"attack_type", "mitre_technique", "min_unique_ports", "min_unique_destinations",
                   "base_confidence", "max_confidence"}, {"enabled"}),
    "unexpected_traffic": ({"attack_type", "mitre_technique", "confidence_one_violation",
                            "confidence_both_violations"}, {"enabled"}),
}


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def validate_config(config):
    """Raise DetectorConfigError unless the configuration is complete and sane. Returns the config."""
    if not isinstance(config, dict):
        raise DetectorConfigError("the rules file must be a mapping with 'settings' and 'rules'")
    extra = set(config) - {"settings", "rules"}
    if extra or "settings" not in config or "rules" not in config:
        raise DetectorConfigError("top-level keys must be exactly 'settings' and 'rules' (unexpected: %s)"
                                  % ", ".join(sorted(map(str, extra))) if extra else "missing 'settings' or 'rules'")
    settings = config["settings"]
    if not isinstance(settings, dict) or set(settings) != {"benign_confidence"}:
        raise DetectorConfigError("settings must contain exactly: benign_confidence")
    if not _is_number(settings["benign_confidence"]) or not 0 <= settings["benign_confidence"] <= 1:
        raise DetectorConfigError("settings.benign_confidence must be a number from 0 to 1")
    rules = config["rules"]
    if not isinstance(rules, dict):
        raise DetectorConfigError("'rules' must be a mapping")
    if set(rules) != set(_RULE_KEYS):
        missing = sorted(set(_RULE_KEYS) - set(rules))
        unknown = sorted(map(str, set(rules) - set(_RULE_KEYS)))
        raise DetectorConfigError("rules must be exactly %s (missing: %s; unknown: %s)"
                                  % (", ".join(_RULE_KEYS), missing or "none", unknown or "none"))
    for name, (required, optional) in _RULE_KEYS.items():
        rule = rules[name]
        if not isinstance(rule, dict):
            raise DetectorConfigError("rule %s must be a mapping" % name)
        missing = sorted(required - set(rule))
        unknown = sorted(map(str, set(rule) - required - optional))
        if missing or unknown:
            raise DetectorConfigError("rule %s: missing keys %s, unknown keys %s" % (name, missing or "none", unknown or "none"))
        if "enabled" in rule and not isinstance(rule["enabled"], bool):
            raise DetectorConfigError("rule %s: enabled must be true or false" % name)
        for key in ("attack_type", "mitre_technique"):
            if not isinstance(rule[key], str) or not rule[key].strip():
                raise DetectorConfigError("rule %s: %s must be a non-empty text" % (name, key))
        for key in required & _NUMBER_KEYS:
            if not _is_number(rule[key]) or rule[key] <= 0:
                raise DetectorConfigError("rule %s: %s must be a number greater than 0" % (name, key))
        for key in required & _CONFIDENCE_KEYS:
            if not _is_number(rule[key]) or not 0 <= rule[key] <= 1:
                raise DetectorConfigError("rule %s: %s must be a number from 0 to 1" % (name, key))
        if "base_confidence" in rule and rule["base_confidence"] > rule["max_confidence"]:
            raise DetectorConfigError("rule %s: base_confidence is above max_confidence" % name)
        if name == "unexpected_traffic" and rule["confidence_one_violation"] > rule["confidence_both_violations"]:
            raise DetectorConfigError("rule %s: confidence_one_violation is above confidence_both_violations" % name)
        if name == "brute_force":
            ports = rule["target_ports"]
            if not isinstance(ports, list) or not ports or not all(
                    isinstance(p, int) and not isinstance(p, bool) and 0 <= p <= 65535 for p in ports):
                raise DetectorConfigError("rule brute_force: target_ports must be a non-empty list of ports 0-65535")
    return config


def load_config(path=DEFAULT_CONFIG):
    """Load and validate detector_rules.yaml (cached). Raises DetectorConfigError on a bad file."""
    if path not in _config_cache:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except (OSError, yaml.YAMLError) as exc:
            raise DetectorConfigError("cannot read %s (%s)" % (os.path.basename(str(path)), type(exc).__name__))
        _config_cache[path] = validate_config(data)
    return _config_cache[path]


def resolve_direction(event, profile=None):
    """"inbound" or "outbound". Explicit value first, then the device IP, else "inbound" (cautious)."""
    value = str(event.get("direction") or "").strip().lower()
    if value in ("inbound", "outbound"):
        return value
    device_ip = (profile or {}).get("ip")
    if device_ip:
        if str(event.get("src_ip") or "").strip() == device_ip:
            return "outbound"
        if str(event.get("dst_ip") or "").strip() == device_ip:
            return "inbound"
    return "inbound"


def _num(value, default=0.0):
    """Safe number: CSV values may be strings, empty, NaN or inf."""
    try:
        x = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(x) or math.isinf(x):
        return default
    return x


def _scale(ratio, base, maximum):
    """ratio == 1 -> base, ratio >= 3 -> maximum, linear in between."""
    frac = min(max((ratio - 1.0) / 2.0, 0.0), 1.0)
    return round(base + frac * (maximum - base), 2)


def _ratio(value, threshold):
    """How many times the value exceeds the threshold (0 if disabled)."""
    if threshold is None or threshold <= 0:
        return 0.0
    return value / threshold


def _result(label, attack_type, confidence, mitre):
    return {
        "label": label,
        "attack_type": attack_type,
        "confidence": confidence,
        "mitre_technique": mitre,
    }


# --------------------------------------------------------------------------
# rules - each returns a confidence (float) if it fires, otherwise None
# --------------------------------------------------------------------------
def rule_dos(event, cfg, profile):
    """A high packet rate (or SYN count) AND many connections. A rate alone is also what a
    fast video upload looks like, so the connection count must be high as well."""
    connections = _ratio(_num(event.get("connection_attempts")), cfg["min_connection_attempts"])
    if connections < 1.0:
        return None
    flood = max(
        _ratio(_num(event.get("Rate")), cfg["min_rate"]),
        _ratio(_num(event.get("syn_count")), cfg["min_syn_count"]),
    )
    # Both conditions are needed, so the confidence follows the weaker one. A scan of 1,000 ports is
    # 1,000 connections with one SYN each: it passes both limits barely and must not outrank Port Scan.
    ratio = min(flood, connections)
    if ratio >= 1.0:
        return _scale(ratio, cfg["base_confidence"], cfg["max_confidence"])
    return None


def rule_brute_force(event, cfg, profile):
    port = int(_num(event.get("dst_port"), -1))
    # Target service: known port, or the dataset's SSH/Telnet flag is set.
    on_target_service = (
        port in cfg["target_ports"]
        or _num(event.get("SSH")) == 1
        or _num(event.get("Telnet")) == 1
    )
    if not on_target_service:
        return None
    # Only FAILED logins count. Many plain connections to port 554 are normal live viewing.
    ratio = _ratio(_num(event.get("failed_attempts")), cfg["min_failed_attempts"])
    if ratio >= 1.0:
        return _scale(ratio, cfg["base_confidence"], cfg["max_confidence"])
    return None


def rule_port_scan(event, cfg, profile):
    ratio = max(
        _ratio(_num(event.get("unique_dst_ports")), cfg["min_unique_ports"]),
        _ratio(_num(event.get("unique_dst_ips")), cfg["min_unique_destinations"]),
    )
    if ratio >= 1.0:
        return _scale(ratio, cfg["base_confidence"], cfg["max_confidence"])
    return None


def rule_unexpected_traffic(event, cfg, profile):
    """Compare the event with the device profile (expected protocols/ports)."""
    if not profile:
        return None  # nothing to compare against
    if resolve_direction(event, profile) != "inbound":
        return None  # the device calling out (cloud, DNS, NTP) is not judged by its listening ports
    violations = 0

    expected_ports = profile.get("expected_ports") or []
    port = event.get("dst_port")
    if expected_ports and port not in (None, "") and int(_num(port, -1)) not in [
        int(p) for p in expected_ports
    ]:
        violations += 1

    expected_protocols = [str(p).upper() for p in (profile.get("expected_protocols") or [])]
    protocol = str(event.get("protocol") or "").upper()
    # The event's "protocol" is the transport (TCP/UDP/...) while a profile lists application
    # protocols (RTSP, HTTPS, DNS). Comparing the two flags every normal event, so a transport
    # name is only compared when the profile itself lists transport names.
    if protocol in TRANSPORT_PROTOCOLS and not (set(expected_protocols) & TRANSPORT_PROTOCOLS):
        protocol = ""
    if expected_protocols and protocol and protocol not in expected_protocols:
        violations += 1

    if violations == 0:
        return None
    return cfg["confidence_both_violations"] if violations == 2 else cfg["confidence_one_violation"]


RULES = {
    "dos": rule_dos,
    "brute_force": rule_brute_force,
    "port_scan": rule_port_scan,
    "unexpected_traffic": rule_unexpected_traffic,
}


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------
def detect(event, device_profile=None, config_path=DEFAULT_CONFIG):
    """Run all enabled rules on one event and return the Detection message.

    event          dict of features + context (bad/missing fields are tolerated)
    device_profile optional dict (expected_protocols, expected_ports, ...)
    """
    config = load_config(config_path)   # raises DetectorConfigError: a bad file must be loud, not silent
    benign = _result("BENIGN", "None", config["settings"]["benign_confidence"], None)

    if not isinstance(event, dict):
        return benign  # bad input must never crash the pipeline

    best = None  # (confidence, rule_cfg)
    for name, func in RULES.items():  # dict order = severity order
        cfg = config["rules"].get(name)
        if not cfg or not cfg.get("enabled", True):
            continue
        try:
            confidence = func(event, cfg, device_profile)
        except (KeyError, TypeError, ValueError):
            confidence = None  # a broken rule must not stop the others
        if confidence is not None and (best is None or confidence > best[0]):
            best = (confidence, cfg)

    if best is None:
        return benign
    confidence, cfg = best
    return _result("ATTACK", cfg["attack_type"], confidence, cfg["mitre_technique"])


if __name__ == "__main__":
    demo = {"device_id": "cam-01", "dst_port": 22, "failed_attempts": 300,
            "connection_attempts": 320, "Rate": 12.0}
    print(detect(demo))
