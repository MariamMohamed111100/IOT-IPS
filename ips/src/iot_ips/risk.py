"""
risk.py - IoT-IPS Risk Engine

    assess(detection, event, device_profile) -> risk

Takes the detector's verdict, the network event and the profile of
the protected device and answers: "how dangerous is this event for
THIS device?" as a score from 0 to 100 plus a level and a factor breakdown.

Risk message (the shared contract):
    {
      "score":   int 0..100,
      "level":   "Low" | "Medium" | "High" | "Critical",
      "factors": {name: {"value", "weight", "contribution", "detail"}},
      "weight_set": str,       # which weight set produced the score
      "warnings": [str, ...]   # fixed codes; defaults/invalid inputs that were used
    }

Design rules (security first):
  * Pure function: no I/O, no network, no randomness, inputs are never modified.
  * Every input is untrusted. Numbers are validated (no NaN/inf/bool/negative),
    names are normalised, IPs are parsed with `ipaddress`. Bad or missing data
    never raises: it falls back to a cautious default and adds a warning code.
  * Nothing the caller supplies is copied into the result as free text, so a
    malicious attack_type or IP string cannot reach the reports.
  * All numbers come from risk_weights.yaml, which is validated strictly when loaded
    (safe YAML only, duplicate keys rejected, weights sum to 1, no single
    factor can dominate, only private ranges can be "internal").
  * The score is a transparent weighted average, so it can be explained.

Python 3.8+, needs PyYAML.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import math
import numbers
import os
import re
import threading
import warnings as _pywarnings
from collections.abc import Mapping
from typing import Any, Dict, List, Optional

import yaml

from . import paths as _paths

__all__ = [
    "assess",
    "level_for",
    "to_backend_score",
    "canonical_attack_name",
    "load_config",
    "reload_config",
    "config_sha256",
    "RiskConfigError",
    "LEVELS",
    "CORE_FACTORS",
    "OPTIONAL_FACTORS",
]

DEFAULT_CONFIG_PATH = str(_paths.CONFIG_DIR / "risk_weights.yaml")
MAX_CONFIG_BYTES = 64 * 1024

LEVELS = ("Low", "Medium", "High", "Critical")
CORE_FACTORS = ("confidence", "attack_severity", "device_criticality", "persistence", "source_trust")
OPTIONAL_FACTORS = ("behavioral_deviation", "potential_impact")
ALL_FACTORS = CORE_FACTORS + OPTIONAL_FACTORS

_CRITICALITY_KEYS = ("low", "medium", "high", "critical")
_TRUST_KEYS = ("trusted", "internal_unknown", "external")

# Only these ranges may be configured as "internal" (stops a typo such as
# 0.0.0.0/0 from making every address look internal).
_ALLOWED_INTERNAL_SUPERNETS = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)

_NAME_RE = re.compile(r"^[a-z0-9_]{1,40}$")
_SET_RE = re.compile(r"^[a-z0-9_]{1,32}$")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")

_MAX_NAME_CHARS = 100
_MAX_NUMBER_STR = 32
_MAX_IP_STR = 64
_MAX_PORT_LIST = 1024
_WEIGHT_SUM_TOLERANCE = 1e-6

# Unforgeable marker proving a config dict came out of load_config().
_VALIDATED = object()


class RiskConfigError(ValueError):
    """risk_weights.yaml is missing, malformed, unsafe, or a bad config was passed in."""


# ---------------------------------------------------------------------------
# Config loading and validation
# ---------------------------------------------------------------------------

class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys (a silent-override typo)."""


def _construct_unique_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in seen
        except TypeError:
            raise RiskConfigError("unhashable key in config")
        if duplicate:
            raise RiskConfigError("duplicate key in config: %r" % (key,))
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


def _is_real(value: Any) -> bool:
    return isinstance(value, numbers.Real) and not isinstance(value, bool)


def _cfg_number(value: Any, name: str, lo: float, hi: float) -> float:
    if not _is_real(value):
        raise RiskConfigError("%s must be a number" % name)
    try:
        number = float(value)
    except (OverflowError, ValueError):
        raise RiskConfigError("%s is not a usable number" % name)
    if not math.isfinite(number) or number < lo or number > hi:
        raise RiskConfigError("%s must be between %s and %s" % (name, lo, hi))
    return number


def _cfg_dict(value: Any, name: str) -> dict:
    if not isinstance(value, dict):
        raise RiskConfigError("%s must be a mapping" % name)
    return value


def _cfg_exact_keys(mapping: dict, expected, name: str) -> None:
    keys = set(mapping)
    if keys != set(expected):
        raise RiskConfigError(
            "%s must have exactly the keys %s" % (name, ", ".join(sorted(expected)))
        )


def _cfg_ip_list(value: Any, name: str, limit: int) -> list:
    if not isinstance(value, list) or len(value) > limit:
        raise RiskConfigError("%s must be a list of at most %d entries" % (name, limit))
    for item in value:
        if not isinstance(item, str):
            raise RiskConfigError("%s entries must be strings" % name)
    return value


def _validate_config(raw: Any) -> dict:
    allowed_top = {
        "version", "active_weight_set", "weight_sets", "limits", "levels",
        "attack_severity", "attack_impact", "attack_aliases", "device_criticality",
        "defaults", "persistence", "source_trust", "backend_scale",
    }
    raw = _cfg_dict(raw, "config")
    if set(raw) != allowed_top:
        extra = sorted(str(k) for k in set(raw) - allowed_top)
        missing = sorted(allowed_top - set(raw))
        raise RiskConfigError("config keys wrong (unknown: %s; missing: %s)" % (extra, missing))

    if raw["version"] != 1 or isinstance(raw["version"], bool):
        raise RiskConfigError("unsupported config version")

    cfg: Dict[str, Any] = {"_validated": _VALIDATED}

    # -- limits --------------------------------------------------------------
    limits = _cfg_dict(raw["limits"], "limits")
    _cfg_exact_keys(limits, ("max_single_weight", "max_source_trust_weight"), "limits")
    max_single = _cfg_number(limits["max_single_weight"], "limits.max_single_weight", 0.05, 1.0)
    max_trust = _cfg_number(limits["max_source_trust_weight"], "limits.max_source_trust_weight", 0.0, 1.0)
    cfg["limits"] = {"max_single_weight": max_single, "max_source_trust_weight": max_trust}

    # -- weight sets ---------------------------------------------------------
    sets_raw = _cfg_dict(raw["weight_sets"], "weight_sets")
    if not sets_raw or len(sets_raw) > 20:
        raise RiskConfigError("weight_sets must contain between 1 and 20 sets")
    weight_sets: Dict[str, Dict[str, float]] = {}
    for set_name, set_raw in sets_raw.items():
        if not isinstance(set_name, str) or not _SET_RE.fullmatch(set_name):
            raise RiskConfigError("bad weight set name")
        where = "weight_sets.%s" % set_name
        set_raw = _cfg_dict(set_raw, where)
        _cfg_exact_keys(set_raw, ALL_FACTORS, where)
        weights = {f: _cfg_number(set_raw[f], "%s.%s" % (where, f), 0.0, 1.0) for f in ALL_FACTORS}
        for factor in CORE_FACTORS:
            if weights[factor] <= 0.0:
                raise RiskConfigError("%s.%s must be greater than 0" % (where, factor))
        if abs(sum(weights.values()) - 1.0) > _WEIGHT_SUM_TOLERANCE:
            raise RiskConfigError("%s weights must sum to 1" % where)
        if max(weights.values()) > max_single + 1e-12:
            raise RiskConfigError("%s has a weight above limits.max_single_weight" % where)
        if weights["source_trust"] > max_trust + 1e-12:
            raise RiskConfigError("%s.source_trust is above limits.max_source_trust_weight" % where)
        weight_sets[set_name] = weights
    cfg["weight_sets"] = weight_sets

    active = raw["active_weight_set"]
    if not isinstance(active, str) or active not in weight_sets:
        raise RiskConfigError("active_weight_set must name one of weight_sets")
    cfg["active_weight_set"] = active

    # -- levels --------------------------------------------------------------
    levels = _cfg_dict(raw["levels"], "levels")
    _cfg_exact_keys(levels, ("medium", "high", "critical"), "levels")
    for key in ("medium", "high", "critical"):
        if not isinstance(levels[key], int) or isinstance(levels[key], bool):
            raise RiskConfigError("levels.%s must be an integer" % key)
    if not 0 < levels["medium"] < levels["high"] < levels["critical"] <= 100:
        raise RiskConfigError("levels must satisfy 0 < medium < high < critical <= 100")
    cfg["levels"] = {k: int(levels[k]) for k in ("medium", "high", "critical")}

    # -- backend scale -------------------------------------------------------
    # Lower bound of each level on the backend's scale (published scores only).
    scale = _cfg_dict(raw["backend_scale"], "backend_scale")
    _cfg_exact_keys(scale, ("medium", "high", "critical"), "backend_scale")
    for key in ("medium", "high", "critical"):
        if not isinstance(scale[key], int) or isinstance(scale[key], bool):
            raise RiskConfigError("backend_scale.%s must be an integer" % key)
    if not 0 < scale["medium"] < scale["high"] < scale["critical"] <= 100:
        raise RiskConfigError("backend_scale must satisfy 0 < medium < high < critical <= 100")
    cfg["backend_scale"] = {k: int(scale[k]) for k in ("medium", "high", "critical")}

    # -- attack tables -------------------------------------------------------
    severity_raw = _cfg_dict(raw["attack_severity"], "attack_severity")
    impact_raw = _cfg_dict(raw["attack_impact"], "attack_impact")
    if not severity_raw or len(severity_raw) > 100:
        raise RiskConfigError("attack_severity must list between 1 and 100 attacks")
    if set(severity_raw) != set(impact_raw):
        raise RiskConfigError("attack_severity and attack_impact must list the same attacks")
    severity: Dict[str, float] = {}
    impact: Dict[str, float] = {}
    for name in severity_raw:
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            raise RiskConfigError("bad attack name in attack_severity")
        severity[name] = _cfg_number(severity_raw[name], "attack_severity.%s" % name, 0, 100)
        impact[name] = _cfg_number(impact_raw[name], "attack_impact.%s" % name, 0, 100)
    cfg["attack_severity"] = severity
    cfg["attack_impact"] = impact

    aliases_raw = _cfg_dict(raw["attack_aliases"], "attack_aliases")
    if len(aliases_raw) > 500:
        raise RiskConfigError("too many attack_aliases")
    aliases: Dict[str, str] = {}
    for alias, target in aliases_raw.items():
        if not isinstance(alias, str) or not _NAME_RE.fullmatch(alias):
            raise RiskConfigError("bad alias name")
        if alias in severity:
            raise RiskConfigError("alias %r shadows a real attack name" % alias)
        if not isinstance(target, str) or target not in severity:
            raise RiskConfigError("alias %r points to an unknown attack" % alias)
        aliases[alias] = target
    cfg["attack_aliases"] = aliases

    # -- device criticality --------------------------------------------------
    crit_raw = _cfg_dict(raw["device_criticality"], "device_criticality")
    _cfg_exact_keys(crit_raw, _CRITICALITY_KEYS, "device_criticality")
    crit = {k: _cfg_number(crit_raw[k], "device_criticality.%s" % k, 0, 100) for k in _CRITICALITY_KEYS}
    if not crit["low"] <= crit["medium"] <= crit["high"] <= crit["critical"]:
        raise RiskConfigError("device_criticality must not decrease from low to critical")
    cfg["device_criticality"] = crit

    # -- defaults ------------------------------------------------------------
    defaults_raw = _cfg_dict(raw["defaults"], "defaults")
    _cfg_exact_keys(defaults_raw, ("confidence", "attack_severity", "attack_impact", "device_criticality"), "defaults")
    cfg["defaults"] = {
        "confidence": _cfg_number(defaults_raw["confidence"], "defaults.confidence", 0.0, 1.0),
        "attack_severity": _cfg_number(defaults_raw["attack_severity"], "defaults.attack_severity", 0, 100),
        "attack_impact": _cfg_number(defaults_raw["attack_impact"], "defaults.attack_impact", 0, 100),
        "device_criticality": _cfg_number(defaults_raw["device_criticality"], "defaults.device_criticality", 0, 100),
    }

    # -- persistence ---------------------------------------------------------
    pers_raw = _cfg_dict(raw["persistence"], "persistence")
    _cfg_exact_keys(pers_raw, ("cap",), "persistence")
    cfg["persistence"] = {"cap": _cfg_number(pers_raw["cap"], "persistence.cap", 1, 1e9)}

    # -- source trust --------------------------------------------------------
    trust_raw = _cfg_dict(raw["source_trust"], "source_trust")
    _cfg_exact_keys(trust_raw, _TRUST_KEYS + ("internal_networks", "trusted_ips"), "source_trust")
    trust = {k: _cfg_number(trust_raw[k], "source_trust.%s" % k, 0, 100) for k in _TRUST_KEYS}
    if not trust["trusted"] <= trust["internal_unknown"] <= trust["external"]:
        raise RiskConfigError("source_trust must not decrease from trusted to external")

    networks: List[Any] = []
    for text in _cfg_ip_list(trust_raw["internal_networks"], "source_trust.internal_networks", 64):
        try:
            net = ipaddress.ip_network(text, strict=True)
        except ValueError:
            raise RiskConfigError("bad network in source_trust.internal_networks")
        if not any(net.version == s.version and net.subnet_of(s) for s in _ALLOWED_INTERNAL_SUPERNETS):
            raise RiskConfigError("only private ranges may be listed in source_trust.internal_networks")
        networks.append(net)

    trusted: List[Any] = []
    for text in _cfg_ip_list(trust_raw["trusted_ips"], "source_trust.trusted_ips", 1024):
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            raise RiskConfigError("bad address in source_trust.trusted_ips")
        if not any(ip in net for net in networks):
            raise RiskConfigError("every trusted IP must lie inside source_trust.internal_networks")
        trusted.append(ip)

    trust["internal_networks"] = tuple(networks)
    trust["trusted_ips"] = frozenset(trusted)
    cfg["source_trust"] = trust
    return cfg


def config_sha256(path: Optional[str] = None) -> str:
    """SHA-256 of the config file. Store it somewhere safe and pass it to
    load_config(expected_sha256=...) to detect tampering with risk_weights.yaml."""
    path = DEFAULT_CONFIG_PATH if path is None else str(path)
    with open(path, "rb") as handle:
        data = handle.read(MAX_CONFIG_BYTES + 1)
    return hashlib.sha256(data).hexdigest()


def load_config(path: Optional[str] = None, expected_sha256: Optional[str] = None) -> dict:
    """Read, verify and validate the configuration file.

    Raises RiskConfigError for anything wrong: the engine must not run on a
    config it cannot trust. If `expected_sha256` is given the file must match it.
    """
    path = DEFAULT_CONFIG_PATH if path is None else str(path)
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise RiskConfigError("cannot read config file (%s)" % (exc.strerror or "error"))
    if len(data) > MAX_CONFIG_BYTES:
        raise RiskConfigError("config file is too large")

    if expected_sha256 is not None:
        digest = hashlib.sha256(data).hexdigest()
        if not isinstance(expected_sha256, str) or not hmac.compare_digest(digest, expected_sha256.strip().lower()):
            raise RiskConfigError("config file hash does not match the expected value (tampered?)")

    if os.name == "posix":
        try:
            if os.stat(path).st_mode & 0o002:
                _pywarnings.warn("risk config %s is writable by everyone" % path, RuntimeWarning, stacklevel=2)
        except OSError:
            pass

    try:
        # _UniqueKeyLoader is a SafeLoader subclass: plain data only, no Python objects.
        raw = yaml.load(data.decode("utf-8"), Loader=_UniqueKeyLoader)  # noqa: S506
    except (yaml.YAMLError, UnicodeDecodeError, RecursionError):
        raise RiskConfigError("config file is not valid safe YAML")
    return _validate_config(raw)


_config_lock = threading.Lock()
_default_config: Optional[dict] = None


def _get_default_config() -> dict:
    global _default_config
    with _config_lock:
        if _default_config is None:
            _default_config = load_config()
        return _default_config


def reload_config() -> dict:
    """Drop the cached default config and load risk_weights.yaml again."""
    global _default_config
    with _config_lock:
        _default_config = None
    return _get_default_config()


def _resolve_config(config: Any) -> dict:
    if config is None:
        return _get_default_config()
    if isinstance(config, dict) and config.get("_validated") is _VALIDATED:
        return config
    raise RiskConfigError("config must be the result of load_config()")


# ---------------------------------------------------------------------------
# Input helpers (everything here treats its input as hostile)
# ---------------------------------------------------------------------------

def _to_number(value: Any) -> Optional[float]:
    """Finite number from an int/float or a short numeric string, else None.
    Booleans, NaN, infinity, huge values and everything else give None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, numbers.Real):
        try:
            number = float(value)
        except (OverflowError, ValueError, TypeError):
            return None
        return number if math.isfinite(number) else None
    if isinstance(value, str):
        text = value.strip()
        if not text or len(text) > _MAX_NUMBER_STR:
            return None
        try:
            number = float(text)
        except ValueError:
            return None
        return number if math.isfinite(number) else None
    return None


def _normalize_name(value: Any) -> Optional[str]:
    """'DDoS-ICMP Flood' -> 'ddos_icmp_flood'. Only [a-z0-9_] can come out."""
    if not isinstance(value, str):
        return None
    text = _NON_ALNUM_RE.sub("_", value.strip()[:_MAX_NAME_CHARS].lower()).strip("_")
    return text or None


def _canonical_attack(value: Any, cfg: dict) -> Optional[str]:
    name = _normalize_name(value)
    if name is None:
        return None
    severity = cfg["attack_severity"]
    aliases = cfg["attack_aliases"]
    if name in severity:
        return name
    if name in aliases:
        return aliases[name]
    candidates = sorted(list(severity) + list(aliases), key=len, reverse=True)
    for key in candidates:
        if name.startswith(key + "_"):
            return key if key in severity else aliases[key]
    return None


def canonical_attack_name(value: Any, config: Optional[dict] = None) -> Optional[str]:
    """Canonical attack name for a detector's attack_type string, or None if
    unknown. 'DDoS-ICMP_Flood' -> 'ddos'. Used by the reports so they speak the
    same attack names as the risk engine."""
    return _canonical_attack(value, _resolve_config(config))


def _clean_label(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text = value.strip().upper()
    return text if text in ("BENIGN", "ATTACK") else None


def _classify_source(value: Any, cfg: dict):
    """Return (category, trust_value, warning_code_or_None)."""
    trust = cfg["source_trust"]
    if value is None:
        return "external", trust["external"], "missing_source_ip"
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > _MAX_IP_STR:
        return "external", trust["external"], "invalid_source_ip"
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return "external", trust["external"], "invalid_source_ip"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip in trust["trusted_ips"]:
        return "trusted_internal", trust["trusted"], None
    if any(ip in net for net in trust["internal_networks"]):
        return "internal_unknown", trust["internal_unknown"], None
    return "external", trust["external"], None


def _port_set(value: Any) -> Optional[frozenset]:
    if not isinstance(value, (list, tuple, set, frozenset)) or len(value) > _MAX_PORT_LIST:
        return None
    ports = set()
    for item in value:
        number = _to_number(item)
        if number is not None and number.is_integer() and 0 <= number <= 65535:
            ports.add(int(number))
    return frozenset(ports) if ports else None


def _deviation(event: Mapping, profile: Mapping):
    """0 if dst_port is one the device is expected to serve, 100 if not,
    None if it cannot be decided (no expected ports or no usable dst_port)."""
    expected = _port_set(profile.get("expected_ports"))
    if expected is None:
        expected = _port_set(profile.get("expected_services"))
    if expected is None:
        return None, "no_expected_ports"
    port = _to_number(event.get("dst_port"))
    if port is None or not port.is_integer() or not 0 <= port <= 65535:
        return None, "no_valid_dst_port"
    if int(port) in expected:
        return 0.0, "port_expected"
    return 100.0, "port_unexpected"


def level_for(score: Any, config: Optional[dict] = None) -> str:
    """Map a 0-100 score to Low / Medium / High / Critical."""
    cfg = _resolve_config(config)
    number = _to_number(score)
    if number is None:
        raise ValueError("score must be a finite number")
    number = min(100.0, max(0.0, number))
    levels = cfg["levels"]
    if number >= levels["critical"]:
        return "Critical"
    if number >= levels["high"]:
        return "High"
    if number >= levels["medium"]:
        return "Medium"
    return "Low"


def _round_half_up(value: float) -> int:
    return int(math.floor(value + 0.5))


# ---------------------------------------------------------------------------
# The risk engine
# ---------------------------------------------------------------------------

def to_backend_score(score: Any, config: Optional[dict] = None) -> int:
    """Convert an internal 0-100 score to the backend's scale (config: backend_scale).

    The backend reads its level from the score with its own limits (0/31/61/91), ours are
    0/30/60/80, so publishing our score as it is would show an 81 (Critical) as High.
    This is a piecewise-linear map that sends every internal level onto the same level of the
    backend: 0..29 -> 0..30, 30..59 -> 31..60, 60..79 -> 61..90, 80..100 -> 91..100. It never
    decreases, 0 stays 0 and 100 stays 100. The internal score (and every decision made
    from it) is not changed; only the number sent to the backend is.
    """
    cfg = _resolve_config(config)
    number = _to_number(score)
    if number is None:
        raise ValueError("score must be a finite number")
    value = int(math.floor(min(100.0, max(0.0, number))))
    ours = [0] + [cfg["levels"][k] for k in ("medium", "high", "critical")] + [100]
    theirs = [0] + [cfg["backend_scale"][k] for k in ("medium", "high", "critical")] + [100]
    for i in range(3):                      # the three half-open segments Low, Medium, High
        if value < ours[i + 1]:
            span_in, span_out = ours[i + 1] - ours[i], theirs[i + 1] - theirs[i]
            return theirs[i] + (value - ours[i]) * span_out // span_in
    span_in, span_out = 100 - ours[3], 100 - theirs[3]      # Critical: closed at 100
    return theirs[3] + ((value - ours[3]) * span_out // span_in if span_in else 0)


def assess(detection: Any, event: Any, device_profile: Any,
           config: Optional[dict] = None, weight_set: Optional[str] = None) -> dict:
    """Score how dangerous `event` is for the device described by `device_profile`.

    detection, event, device_profile: dicts as in the shared contract. Anything
    that is not a mapping, and any missing/invalid field, is handled with a
    cautious default and reported in result["warnings"]; this function does not
    raise on bad data. It raises RiskConfigError only for a bad *configuration*
    (including an unknown `weight_set` name).
    """
    cfg = _resolve_config(config)
    set_name = cfg["active_weight_set"] if weight_set is None else weight_set
    if not isinstance(set_name, str) or set_name not in cfg["weight_sets"]:
        raise RiskConfigError("unknown weight set")
    weights = cfg["weight_sets"][set_name]

    warns: List[str] = []

    def warn(code: str) -> None:
        if code not in warns:
            warns.append(code)

    if not isinstance(detection, Mapping):
        warn("invalid_detection")
        detection = {}
    if not isinstance(event, Mapping):
        warn("invalid_event")
        event = {}
    if not isinstance(device_profile, Mapping):
        warn("missing_device_profile")
        device_profile = {}

    # A benign verdict carries no risk (the policy engine will not act on it).
    label = _clean_label(detection.get("label"))
    if label == "BENIGN":
        return {"score": 0, "level": "Low", "factors": {}, "weight_set": set_name, "warnings": warns}
    if label is None:
        warn("label_missing_or_invalid")  # treated like an attack: cautious

    defaults = cfg["defaults"]
    values: Dict[str, Optional[float]] = {}
    details: Dict[str, str] = {}

    # 1. detection confidence (0..1 -> 0..100)
    confidence = _to_number(detection.get("confidence"))
    if confidence is None or confidence < 0.0 or confidence > 1.0:
        warn("invalid_confidence")
        confidence = defaults["confidence"]
    values["confidence"] = confidence * 100.0
    details["confidence"] = "model_confidence"

    # 2. attack severity and 7. potential impact (same attack lookup)
    attack = _canonical_attack(detection.get("attack_type"), cfg)
    if attack is None:
        warn("unknown_attack_type")
        values["attack_severity"] = defaults["attack_severity"]
        values["potential_impact"] = defaults["attack_impact"]
        details["attack_severity"] = details["potential_impact"] = "unknown_attack"
    else:
        values["attack_severity"] = cfg["attack_severity"][attack]
        values["potential_impact"] = cfg["attack_impact"][attack]
        details["attack_severity"] = details["potential_impact"] = attack

    # 3. device criticality
    crit_name = _normalize_name(device_profile.get("criticality"))
    if crit_name in cfg["device_criticality"]:
        values["device_criticality"] = cfg["device_criticality"][crit_name]
        details["device_criticality"] = crit_name
    else:
        warn("missing_device_criticality" if "criticality" not in device_profile else "unknown_device_criticality")
        values["device_criticality"] = defaults["device_criticality"]
        details["device_criticality"] = "default"

    # 4. persistence (how many attempts)
    attempts = []
    for key in ("failed_attempts", "connection_attempts"):
        number = _to_number(event.get(key))
        if number is None or number < 0:
            if event.get(key) is not None:
                warn("invalid_attempt_count")
        else:
            attempts.append(number)
    if attempts:
        count = max(attempts)
        cap = cfg["persistence"]["cap"]
        values["persistence"] = min(100.0, 100.0 * math.log1p(count) / math.log1p(cap))
        details["persistence"] = "attempts=%d" % int(min(count, 10 ** 9))
    else:
        warn("no_attempt_data")
        values["persistence"] = 0.0
        details["persistence"] = "attempts=0"

    # 5. source trust
    category, trust_value, trust_warning = _classify_source(event.get("src_ip"), cfg)
    if trust_warning:
        warn(trust_warning)
    values["source_trust"] = trust_value
    details["source_trust"] = category

    # 6. behavioural deviation (optional)
    deviation, why = _deviation(event, device_profile)
    values["behavioral_deviation"] = deviation
    details["behavioral_deviation"] = why

    # Weighted average over the factors that could be computed. Core factors
    # always can, so the total weight is always > 0 and the score stays 0..100.
    used = [f for f in ALL_FACTORS if values.get(f) is not None and weights[f] > 0.0]
    total_weight = sum(weights[f] for f in used)
    exact = sum(weights[f] * values[f] for f in used) / total_weight
    exact = min(100.0, max(0.0, exact))
    score = min(100, max(0, _round_half_up(exact)))

    factors: Dict[str, dict] = {}
    for factor in ALL_FACTORS:
        if factor in used:
            effective = weights[factor] / total_weight
            factors[factor] = {
                "value": round(values[factor], 2),
                "weight": round(effective, 4),
                "contribution": round(effective * values[factor], 2),
                "detail": details[factor],
            }
        else:
            factors[factor] = {"value": None, "weight": 0.0, "contribution": 0.0, "detail": details.get(factor, "not_used")}

    return {
        "score": score,
        "level": level_for(score, cfg),
        "factors": factors,
        "weight_set": set_name,
        "warnings": warns,
    }
