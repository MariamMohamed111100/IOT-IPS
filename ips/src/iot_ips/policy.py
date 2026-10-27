"""
policy.py - IoT-IPS policy engine

    decide(risk, detection, event=None, device_profile=None) -> decision

Turns the risk engine's verdict into a list of response actions using the
rules in policy.yaml. The policy is deterministic and explainable: the same
input always gives the same decision, and a decision can only contain actions
that are written in policy.yaml (an AI model never chooses an action).

Decision message (the shared contract):
    {
      "action":  [str, ...],      # actions to carry out, all from policy.yaml
      "reason":  str,             # which rule matched, with the numbers it used
      "command": [str, ...],      # firewall commands that WOULD run (dry run)
      "dry_run": True,
      "rule_id": str,
      "level":   "Low" | "Medium" | "High" | "Critical" | None,
      "targets": {"src_ip", "device_ip", "device_id"},   # validated, or None
      "skipped": [{"action", "why"}],   # actions left out, with a fixed reason code
      "warnings": [str, ...]            # fixed codes for bad or missing input
    }

Safety rules (also checked again by actions.py):
  * block_source / isolate_device need a Critical level, confidence >= 0.90 and
    a known attack type; temporary_block needs High or Critical and confidence
    >= 0.60. policy.yaml cannot be loaded if a rule breaks this.
  * "a known attack type" is what the risk engine recognises
    (risk.canonical_attack_name), so the policy and the score always agree: an
    attack the risk engine calls unknown is never blocked or isolated hard.
  * an allow-listed address, a loopback/multicast/link-local address, the
    device itself, or an unparseable address is never blocked.
  * isolate_device only for a private device address that is not allow-listed, and never when the
    source is allow-listed (a spoofed gateway/admin IP must not be able to get a device isolated).
  * bad input never raises: it falls back to the cautious `fallback` rule
    (log, create incident, notify admin) that blocks nothing.
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
from typing import Any, List, Optional

import yaml

from . import actions as _actions
from . import paths as _paths
from . import risk as _risk
from .actions import ACTION_NAMES, NETWORK_ACTIONS

__all__ = ["decide", "load_policy", "reload_policy", "policy_sha256", "PolicyConfigError", "LEVELS"]

DEFAULT_POLICY_PATH = str(_paths.CONFIG_DIR / "policy.yaml")
MAX_POLICY_BYTES = 64 * 1024
LEVELS = ("Low", "Medium", "High", "Critical")
_TEMP_ONLY = ("temporary_block",)
_HARSH = ("block_source", "isolate_device")

_ID_RE = re.compile(r"^[a-z0-9_]{1,40}$")
_DEVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$")
_VALIDATED = object()


class PolicyConfigError(ValueError):
    """policy.yaml is missing, malformed or unsafe."""


# ---------------------------------------------------------------------------
# Loading and validating policy.yaml
# ---------------------------------------------------------------------------

class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys."""


def _construct_unique_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _value in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in seen
        except TypeError:
            raise PolicyConfigError("unhashable key in policy")
        if duplicate:
            raise PolicyConfigError("duplicate key in policy: %r" % (key,))
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


def _is_real(value: Any) -> bool:
    return isinstance(value, numbers.Real) and not isinstance(value, bool)


def _num(value: Any, name: str, lo: float, hi: float) -> float:
    if not _is_real(value):
        raise PolicyConfigError("%s must be a number" % name)
    try:
        number = float(value)
    except (OverflowError, ValueError):
        raise PolicyConfigError("%s is not a usable number" % name)
    if not math.isfinite(number) or not lo <= number <= hi:
        raise PolicyConfigError("%s must be between %s and %s" % (name, lo, hi))
    return number


def _int(value: Any, name: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise PolicyConfigError("%s must be an integer between %d and %d" % (name, lo, hi))
    return value


def _mapping(value: Any, name: str) -> dict:
    if not isinstance(value, dict):
        raise PolicyConfigError("%s must be a mapping" % name)
    return value


def _exact(mapping: dict, keys, name: str) -> None:
    if set(mapping) != set(keys):
        raise PolicyConfigError("%s must have exactly the keys %s" % (name, ", ".join(sorted(keys))))


def _action_list(value: Any, name: str) -> tuple:
    if not isinstance(value, list) or not 1 <= len(value) <= 8:
        raise PolicyConfigError("%s must be a list of 1 to 8 actions" % name)
    for item in value:
        if not isinstance(item, str) or item not in ACTION_NAMES:
            raise PolicyConfigError("%s contains an action that is not in the catalog" % name)
    if len(set(value)) != len(value):
        raise PolicyConfigError("%s lists the same action twice" % name)
    return tuple(value)


def _validate_policy(raw: Any) -> dict:
    raw = _mapping(raw, "policy")
    top = {"version", "dry_run", "limits", "allow_list", "rules", "fallback"}
    if set(raw) != top:
        raise PolicyConfigError("policy keys wrong (unknown: %s; missing: %s)" % (
            sorted(str(k) for k in set(raw) - top), sorted(top - set(raw))))
    if isinstance(raw["version"], bool) or raw["version"] != 1:
        raise PolicyConfigError("unsupported policy version")
    if raw["dry_run"] is not True:
        raise PolicyConfigError("this version only supports dry_run: true (no real firewall changes)")

    lim = _mapping(raw["limits"], "limits")
    _exact(lim, ("block_min_confidence", "harsh_min_confidence", "temporary_block_seconds",
                 "max_active_blocks", "max_log_bytes"), "limits")
    limits = {
        "block_min_confidence": _num(lim["block_min_confidence"], "limits.block_min_confidence", 0.0, 1.0),
        "harsh_min_confidence": _num(lim["harsh_min_confidence"], "limits.harsh_min_confidence", 0.0, 1.0),
        "temporary_block_seconds": _int(lim["temporary_block_seconds"], "limits.temporary_block_seconds", 30, 86400),
        "max_active_blocks": _int(lim["max_active_blocks"], "limits.max_active_blocks", 1, 10000),
        "max_log_bytes": _int(lim["max_log_bytes"], "limits.max_log_bytes", 1024, 10 ** 9),
    }
    if limits["block_min_confidence"] < 0.5:
        raise PolicyConfigError("limits.block_min_confidence must be at least 0.5")
    if limits["harsh_min_confidence"] < limits["block_min_confidence"]:
        raise PolicyConfigError("limits.harsh_min_confidence must not be lower than block_min_confidence")

    allow_raw = raw["allow_list"]
    if not isinstance(allow_raw, list) or len(allow_raw) > 256:
        raise PolicyConfigError("allow_list must be a list of at most 256 entries")
    networks = []
    for text in allow_raw:
        if not isinstance(text, str):
            raise PolicyConfigError("allow_list entries must be strings")
        try:
            net = ipaddress.ip_network(text, strict=True)
        except ValueError:
            raise PolicyConfigError("bad address or network in allow_list")
        if net.prefixlen < (8 if net.version == 4 else 32):
            raise PolicyConfigError("allow_list network is too broad")
        networks.append(net)

    rules_raw = raw["rules"]
    if not isinstance(rules_raw, list) or not 1 <= len(rules_raw) <= 50:
        raise PolicyConfigError("rules must be a list of 1 to 50 rules")
    rules: List[dict] = []
    ids = set()
    for index, rule_raw in enumerate(rules_raw):
        where = "rules[%d]" % index
        rule_raw = _mapping(rule_raw, where)
        _exact(rule_raw, ("id", "when", "then"), where)
        rid = rule_raw["id"]
        if not isinstance(rid, str) or not _ID_RE.fullmatch(rid):
            raise PolicyConfigError("%s has a bad id" % where)
        if rid in ids:
            raise PolicyConfigError("duplicate rule id %r" % rid)
        ids.add(rid)
        when = _mapping(rule_raw["when"], where + ".when")
        extra = set(when) - {"level", "min_score", "min_confidence", "attack_known"}
        if extra or "level" not in when:
            raise PolicyConfigError("%s.when needs 'level' and may only add min_score, min_confidence, attack_known" % where)
        lv = when["level"]
        if not isinstance(lv, list) or not lv or len(set(lv)) != len(lv) or any(l not in LEVELS for l in lv if isinstance(l, str)) \
                or any(not isinstance(l, str) for l in lv):
            raise PolicyConfigError("%s.when.level must be a list of valid levels" % where)
        min_score = _num(when["min_score"], where + ".when.min_score", 0, 100) if "min_score" in when else None
        min_conf = _num(when["min_confidence"], where + ".when.min_confidence", 0.0, 1.0) if "min_confidence" in when else None
        known = None
        if "attack_known" in when:
            if not isinstance(when["attack_known"], bool):
                raise PolicyConfigError("%s.when.attack_known must be true or false" % where)
            known = when["attack_known"]
        then = _action_list(rule_raw["then"], where + ".then")

        network = [a for a in then if a in NETWORK_ACTIONS]
        if network:
            if not set(lv) <= {"High", "Critical"}:
                raise PolicyConfigError("%s: only High or Critical rules may block or isolate" % where)
            if "temporary_block" in then and (min_conf is None or min_conf < limits["block_min_confidence"]):
                raise PolicyConfigError("%s: temporary_block needs min_confidence >= limits.block_min_confidence" % where)
            if any(a in then for a in _HARSH):
                if min_conf is None or min_conf < limits["harsh_min_confidence"]:
                    raise PolicyConfigError("%s: block_source/isolate_device need min_confidence >= limits.harsh_min_confidence" % where)
                if known is not True:
                    raise PolicyConfigError("%s: block_source/isolate_device need attack_known: true" % where)
        rules.append({"id": rid, "levels": frozenset(lv), "min_score": min_score, "min_confidence": min_conf,
                      "attack_known": known, "then": then, "catch_all": set(when) == {"level"}})

    for level in LEVELS:
        if not any(r["catch_all"] and level in r["levels"] for r in rules):
            raise PolicyConfigError("no catch-all rule (only 'level') covers level %s" % level)

    fb = _mapping(raw["fallback"], "fallback")
    _exact(fb, ("id", "then"), "fallback")
    if not isinstance(fb["id"], str) or not _ID_RE.fullmatch(fb["id"]) or fb["id"] in ids:
        raise PolicyConfigError("fallback id is bad or not unique")
    fb_then = _action_list(fb["then"], "fallback.then")
    if any(a in NETWORK_ACTIONS for a in fb_then):
        raise PolicyConfigError("fallback must not block or isolate")

    return {"_validated": _VALIDATED, "dry_run": True, "limits": limits, "allow_networks": tuple(networks),
            "rules": tuple(rules), "fallback": {"id": fb["id"], "then": fb_then}}


def policy_sha256(path: Optional[str] = None) -> str:
    """SHA-256 of policy.yaml; pin it with load_policy(expected_sha256=...) to detect tampering."""
    path = DEFAULT_POLICY_PATH if path is None else str(path)
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read(MAX_POLICY_BYTES + 1)).hexdigest()


def load_policy(path: Optional[str] = None, expected_sha256: Optional[str] = None) -> dict:
    """Read, verify and validate policy.yaml. Raises PolicyConfigError on anything unsafe."""
    path = DEFAULT_POLICY_PATH if path is None else str(path)
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_POLICY_BYTES + 1)
    except OSError as exc:
        raise PolicyConfigError("cannot read policy file (%s)" % (exc.strerror or "error"))
    if len(data) > MAX_POLICY_BYTES:
        raise PolicyConfigError("policy file is too large")
    if expected_sha256 is not None:
        digest = hashlib.sha256(data).hexdigest()
        if not isinstance(expected_sha256, str) or not hmac.compare_digest(digest, expected_sha256.strip().lower()):
            raise PolicyConfigError("policy file hash does not match the expected value (tampered?)")
    if os.name == "posix":
        try:
            if os.stat(path).st_mode & 0o002:
                _pywarnings.warn("policy file %s is writable by everyone" % path, RuntimeWarning, stacklevel=2)
        except OSError:
            pass
    try:
        raw = yaml.load(data.decode("utf-8"), Loader=_UniqueKeyLoader)  # noqa: S506 (SafeLoader subclass)
    except (yaml.YAMLError, UnicodeDecodeError, RecursionError):
        raise PolicyConfigError("policy file is not valid safe YAML")
    return _validate_policy(raw)


_lock = threading.Lock()
_default_policy: Optional[dict] = None


def _get_default_policy() -> dict:
    global _default_policy
    with _lock:
        if _default_policy is None:
            _default_policy = load_policy()
        return _default_policy


def reload_policy() -> dict:
    """Drop the cached policy and load policy.yaml again."""
    global _default_policy
    with _lock:
        _default_policy = None
    return _get_default_policy()


def _resolve(policy: Any) -> dict:
    if policy is None:
        return _get_default_policy()
    if isinstance(policy, dict) and policy.get("_validated") is _VALIDATED:
        return policy
    raise PolicyConfigError("policy must be the result of load_policy()")


# ---------------------------------------------------------------------------
# Input helpers (all input is untrusted)
# ---------------------------------------------------------------------------

def _finite(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, numbers.Real):
        try:
            number = float(value)
        except (OverflowError, ValueError, TypeError):
            return None
    elif isinstance(value, str):
        text = value.strip()
        if not text or len(text) > 32:
            return None
        try:
            number = float(text)
        except ValueError:
            return None
    else:
        return None
    return number if math.isfinite(number) else None


def _canonical_attack(value: Any) -> Optional[str]:
    """The canonical attack name for a detector's attack_type, or None if the
    risk engine does not know it. The risk engine owns the attack names, so the
    policy asks the same engine the score comes from: the two can never disagree.
    If the engine fails, the attack counts as unknown, which is the safe side
    (an unknown attack is never blocked or isolated hard)."""
    try:
        return _risk.canonical_attack_name(value)
    except Exception:
        return None


def _attack_known(value: Any) -> bool:
    """True when the risk engine recognises the attack type.

    An attack the risk engine calls unknown gets the default severity, so it
    must not be blocked or isolated hard either."""
    return _canonical_attack(value) is not None


def _matches(rule: dict, level: Optional[str], score: Optional[float], confidence: Optional[float], known: bool) -> bool:
    if level not in rule["levels"]:
        return False
    if rule["min_score"] is not None and (score is None or score < rule["min_score"]):
        return False
    if rule["min_confidence"] is not None and (confidence is None or confidence < rule["min_confidence"]):
        return False
    if rule["attack_known"] is not None and known != rule["attack_known"]:
        return False
    return True


def _number_text(value: Optional[float], digits: int = 2) -> str:
    return "unknown" if value is None else ("%.*f" % (digits, value)).rstrip("0").rstrip(".")


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------

def decide(risk: Any, detection: Any, event: Any = None, device_profile: Any = None,
           policy: Optional[dict] = None) -> dict:
    """Choose the response actions for one event.

    risk       - Risk message from risk.assess (score, level, ...)
    detection  - Detection message (label, attack_type, confidence, ...)
    event      - optional event context; src_ip is needed to block a source
    device_profile - optional device profile; ip and device_id are used

    Bad data never raises; it makes the policy more cautious (nothing is
    blocked on unknown or invalid information). Raises PolicyConfigError only for
    a bad policy.
    """
    pol = _resolve(policy)
    warns: List[str] = []

    def warn(code: str) -> None:
        if code not in warns:
            warns.append(code)

    if not isinstance(risk, Mapping):
        warn("invalid_risk")
        risk = {}
    if not isinstance(detection, Mapping):
        warn("invalid_detection")
        detection = {}
    if not isinstance(event, Mapping):
        event = {}
    if not isinstance(device_profile, Mapping):
        device_profile = {}

    # Validated targets (never raw strings).
    src = _actions.parse_ip(event.get("src_ip"))
    dev_ip = _actions.parse_ip(device_profile.get("ip"))
    if dev_ip is None:
        dev_ip = _actions.parse_ip(event.get("dst_ip"))
    device_id = device_profile.get("device_id")
    if not (isinstance(device_id, str) and _DEVICE_RE.fullmatch(device_id)):
        device_id = event.get("device_id")
    if not (isinstance(device_id, str) and _DEVICE_RE.fullmatch(device_id)):
        device_id = None
    targets = {
        "src_ip": None if src is None else str(src),
        "device_ip": None if dev_ip is None else str(dev_ip),
        "device_id": device_id,
    }

    label = detection.get("label")
    label = label.strip().upper() if isinstance(label, str) else None
    level_raw = risk.get("level")
    level = level_raw.strip().capitalize() if isinstance(level_raw, str) else None
    if level not in LEVELS:
        level = None
    score = _finite(risk.get("score"))
    if score is not None and not 0 <= score <= 100:
        score = None
    confidence = _finite(detection.get("confidence"))
    if confidence is not None and not 0 <= confidence <= 1:
        confidence = None
    known = _attack_known(detection.get("attack_type"))

    def build(rule_id: str, chosen, reason: str, skipped: List[dict]) -> dict:
        commands: List[str] = []
        for name in chosen:
            for argv in _actions.build_commands(name, src_ip=src, device_ip=dev_ip):
                commands.append(_actions.format_command(argv))
        return {"action": list(chosen), "reason": reason, "command": commands, "dry_run": True,
                "rule_id": rule_id, "level": level, "targets": targets, "skipped": skipped, "warnings": warns}

    if label == "BENIGN":
        return build("benign", (), "benign verdict: no action", [])
    if label != "ATTACK":
        warn("label_missing_or_invalid")
    if confidence is None:
        warn("invalid_confidence")
    if score is None:
        warn("invalid_score")

    rule_id = pol["fallback"]["id"]
    chosen_actions = pol["fallback"]["then"]
    if level is None:
        warn("invalid_level")
        reason = "no valid risk level: cautious fallback rule %s" % rule_id
    else:
        reason = ""
        for rule in pol["rules"]:
            if _matches(rule, level, score, confidence, known):
                rule_id, chosen_actions = rule["id"], rule["then"]
                reason = "rule %s matched: level %s, score %s, confidence %s, attack %s" % (
                    rule_id, level, _number_text(score, 0), _number_text(confidence),
                    "known" if known else "unknown")
                break
        if not reason:  # cannot happen with a validated policy; stay cautious anyway
            rule_id, chosen_actions = pol["fallback"]["id"], pol["fallback"]["then"]
            reason = "no rule matched: cautious fallback rule %s" % rule_id

    # Guards on the network actions (the rules file decided WHAT; these decide whether it is SAFE).
    final: List[str] = []
    skipped: List[dict] = []
    for name in chosen_actions:
        why = None
        if name in ("block_source", "temporary_block"):
            if src is None:
                why = "no_valid_source"
            elif _actions.is_never_block(src):
                why = "source_never_block"
            elif _actions.is_allow_listed(src, pol["allow_networks"]):
                why = "source_allow_listed"
            elif dev_ip is not None and src == dev_ip:
                why = "source_is_device"
        elif name == "isolate_device":
            # A trusted source (gateway, admin PC) can be spoofed by an attacker; isolating the device
            # because of it would hand the attacker a way to cut the device off. So no isolation then.
            if src is not None and (_actions.is_never_block(src) or _actions.is_allow_listed(src, pol["allow_networks"])):
                why = "source_allow_listed"
            elif dev_ip is None:
                why = "no_valid_device_ip"
            elif not dev_ip.is_private or _actions.is_never_block(dev_ip):
                why = "device_ip_not_private"
            elif _actions.is_allow_listed(dev_ip, pol["allow_networks"]):
                why = "device_allow_listed"
        if why is None:
            final.append(name)
        else:
            skipped.append({"action": name, "why": why})
    return build(rule_id, final, reason, skipped)
