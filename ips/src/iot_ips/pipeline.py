"""
pipeline.py - the IoT-IPS pipeline: CSV events in, incidents and reports out.

    python -m iot_ips run  data/sample_events.csv [--db output/incidents.db] [--reset]
    python -m iot_ips show [--db output/incidents.db] [--level High] [--full INC-00007]
    python -m iot_ips verify [--db output/incidents.db]

For every row of the CSV:  detector -> risk -> policy -> actions -> incident database

    event (CSV row)
      -> detector.detect(event, profile)             rule-based detector (placeholder available for tests)
      -> risk.assess(detection, event, profile)      weighted risk score and level
      -> policy.decide(risk, detection, event, profile)   rules from config/policy.yaml
      -> ActionExecutor.run(decision)                simulated actions, written to the action log
      -> if the decision contains create_incident:
         IncidentDB.insert_incident(...)  with the reports from report.make_report

The CSV is untrusted input: it is size-limited, row-limited, decoded strictly and
every field is length-limited. A bad row is counted and skipped, a missing value
becomes a cautious default, and a failing module is reported without stopping the
run. Nothing in this program runs a real firewall command.

Exit status: 0 = clean run, 1 = verify found tampering, 2 = errors (bad file, rejected
rows, module failures).
"""

from __future__ import annotations

import argparse
import csv
import inspect
import ipaddress
import json
import math
import numbers
import os
import re
import sys
from collections.abc import Mapping
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from . import actions as _actions_module
from . import db as dbmod
from . import detector as _detector_module
from . import placeholders
from . import policy as _policy_module
from . import report as _report_module
from . import risk as _risk_module
from .paths import DEFAULT_DEVICES_PATH

MAX_CSV_BYTES = 20 * 1024 * 1024
DEFAULT_MAX_ROWS = 100_000
DEFAULT_MAX_INCIDENTS = 10_000
DEFAULT_GROUP_WINDOW_S = 300   # repeated events of one attack from one source within 5 minutes are one incident
MAX_COLUMNS = 300
MAX_FIELD_CHARS = 500
MAX_DEVICES_BYTES = 1024 * 1024
CONTEXT_FIELDS = ("device_id", "timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "failed_attempts", "connection_attempts")
EXPECTED_PREFIX = "expected_"   # columns such as expected_level are for humans and never reach the modules

_DEVICE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,39}")
_PROTOCOL_RE = re.compile(r"[A-Za-z0-9_-]{1,20}")
_DURATION_RE = re.compile(r"[A-Za-z0-9 .:,-]{1,60}")
_COLUMN_RE = re.compile(r"[A-Za-z0-9_ ./()%+-]{1,80}")
_CRIT_VALUES = ("low", "medium", "high", "critical")

csv.field_size_limit(MAX_FIELD_CHARS * 20)


class PipelineError(RuntimeError):
    """A problem that stops the run (bad input file, missing required module, bad configuration)."""


# ---------------------------------------------------------------------------
# The modules the pipeline calls
# ---------------------------------------------------------------------------

class Modules:
    """The functions the pipeline calls, and where the detector came from.

    use_placeholder_detector=True swaps the rule-based detector for the small threshold
    stand-in in placeholders.py. The unit tests use it so they do not depend on the
    detector's thresholds.
    """

    def __init__(self, use_placeholder_detector: bool = False) -> None:
        self.risk, self.policy, self.actions = _risk_module, _policy_module, _actions_module
        self.detect: Callable[..., Any] = placeholders.detect if use_placeholder_detector else _detector_module.detect
        self.make_report: Callable[[dict], Any] = _report_module.make_report
        self.build_incident: Callable[..., Any] = _report_module.build_incident
        try:
            params = [q for q in inspect.signature(self.detect).parameters.values()
                      if q.kind in (q.POSITIONAL_ONLY, q.POSITIONAL_OR_KEYWORD, q.VAR_POSITIONAL)]
            self.accepts_profile = len(params) >= 2 or any(q.kind == q.VAR_POSITIONAL for q in params)
        except (TypeError, ValueError):
            self.accepts_profile = False
        self.sources = {"detector": "placeholder" if use_placeholder_detector else "rules", "report": "templates"}


# ---------------------------------------------------------------------------
# Device profiles (config/devices.json)
# ---------------------------------------------------------------------------

def load_devices(path: str) -> Dict[str, dict]:
    """Read devices.json: a list of profiles (or {"devices": [...]}). Invalid entries are dropped."""
    try:
        if os.path.getsize(path) > MAX_DEVICES_BYTES:
            raise PipelineError("devices file is too large")
        with open(path, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle, parse_constant=lambda _c: (_ for _ in ()).throw(ValueError("constant")))
    except (OSError, ValueError, RecursionError) as exc:
        raise PipelineError("cannot read devices file (%s)" % type(exc).__name__)
    if isinstance(data, Mapping):
        data = data.get("devices")
    if not isinstance(data, list) or len(data) > 1000:
        raise PipelineError("devices file must hold a list of at most 1000 device profiles")
    devices: Dict[str, dict] = {}
    for entry in data:
        if not isinstance(entry, Mapping):
            continue
        device_id = entry.get("device_id")
        if not isinstance(device_id, str) or not _DEVICE_RE.fullmatch(device_id):
            continue
        if device_id in devices:
            raise PipelineError("devices file lists %s twice" % device_id)
        profile: Dict[str, Any] = {"device_id": device_id}
        device_type = entry.get("device_type")
        if isinstance(device_type, str) and re.fullmatch(r"[A-Za-z0-9_ -]{1,40}", device_type):
            profile["device_type"] = device_type.strip().lower().replace(" ", "_")
        ip = entry.get("ip")
        try:
            profile["ip"] = str(ipaddress.ip_address(ip.strip())) if isinstance(ip, str) else None
        except ValueError:
            profile["ip"] = None
        crit = entry.get("criticality")
        profile["criticality"] = crit.strip().lower() if isinstance(crit, str) and crit.strip().lower() in _CRIT_VALUES else None
        ports = entry.get("expected_ports", entry.get("expected_services"))
        profile["expected_ports"] = [int(p) for p in ports if isinstance(p, int) and not isinstance(p, bool) and 0 <= p <= 65535][:1024] \
            if isinstance(ports, list) else []
        protocols = entry.get("expected_protocols")
        profile["expected_protocols"] = [p for p in protocols if isinstance(p, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,20}", p)][:50] \
            if isinstance(protocols, list) else []
        devices[device_id] = profile
    return devices


# ---------------------------------------------------------------------------
# Reading the CSV (untrusted)
# ---------------------------------------------------------------------------

def read_events(path: str, max_rows: int = DEFAULT_MAX_ROWS) -> Iterator[Tuple[int, Optional[dict], Optional[str]]]:
    """Yield (line_number, event, None) for good rows and (line_number, None, error_code) for bad ones.

    Raises PipelineError for problems with the file itself.
    """
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise PipelineError("cannot read the events file (%s)" % (exc.strerror or "error"))
    if size > MAX_CSV_BYTES:
        raise PipelineError("events file is larger than %d MB" % (MAX_CSV_BYTES // (1024 * 1024)))
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle)
            try:
                header = [h.strip() for h in next(reader)]
            except StopIteration:
                raise PipelineError("events file is empty")
            if not header or len(header) > MAX_COLUMNS:
                raise PipelineError("events file needs between 1 and %d columns" % MAX_COLUMNS)
            if any(not _COLUMN_RE.fullmatch(h) for h in header):
                raise PipelineError("events file has a column name that is empty or has unusual characters")
            if len({h.lower() for h in header}) != len(header):
                raise PipelineError("events file has a duplicate column name")
            keep = [(i, h) for i, h in enumerate(header) if not h.lower().startswith(EXPECTED_PREFIX)]
            produced = 0
            for row in reader:
                line = reader.line_num
                if not row or all(not cell.strip() for cell in row):
                    continue
                if produced >= max_rows:
                    yield line, None, "row_limit_reached"
                    return
                produced += 1
                if len(row) > len(header):
                    yield line, None, "too_many_fields"
                    continue
                event: Dict[str, Optional[str]] = {}
                for i, name in keep:
                    cell = row[i].strip() if i < len(row) else ""
                    event[name] = cell[:MAX_FIELD_CHARS] if cell else None
                yield line, event, None
    except UnicodeDecodeError:
        raise PipelineError("events file is not valid UTF-8 text")
    except csv.Error:
        raise PipelineError("events file is not a valid CSV (control characters or a field that is far too long)")
    except OSError as exc:
        raise PipelineError("cannot read the events file (%s)" % (exc.strerror or "error"))


# ---------------------------------------------------------------------------
# The pipeline
# ---------------------------------------------------------------------------

def _finite(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, numbers.Real):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    return number if math.isfinite(number) else None


class Pipeline:
    """Runs events through the modules and stores incidents."""

    def __init__(self, database, modules: Modules, devices: Dict[str, dict], executor, policy_cfg: dict,
                 max_incidents: int = DEFAULT_MAX_INCIDENTS, group_window: float = DEFAULT_GROUP_WINDOW_S):
        self.group_window = group_window
        self.db = database
        self.m = modules
        self.devices = devices
        self.executor = executor
        self.policy_cfg = policy_cfg
        self.max_incidents = max_incidents

    def _detect(self, event: dict, profile: dict) -> Any:
        """detect(event, device_profile=None) uses the profile for its unexpected-port rule; a one-argument detect(event) also works."""
        if self.m.accepts_profile and profile:
            return self.m.detect(event, dict(profile))
        return self.m.detect(event)

    def _reports(self, incident: dict, context: tuple, event_count: int = 1) -> Any:
        """report.py wants the merged record from build_incident(), not the stored row."""
        raw_event, detection, risk_msg, decision, profile = context
        # The report module gets only values that were already validated (db.py cleaned them); free text from the CSV never reaches a report.
        protocol = raw_event.get("protocol")
        duration = raw_event.get("duration")
        event = {"timestamp": incident.get("timestamp"), "src_ip": incident.get("src_ip"), "dst_ip": incident.get("dst_ip"),
                 "dst_port": incident.get("dst_port"),
                 "protocol": protocol.upper() if isinstance(protocol, str) and _PROTOCOL_RE.fullmatch(protocol) else None,
                 "duration": duration if isinstance(duration, str) and _DURATION_RE.fullmatch(duration) else None,
                 "failed_attempts": incident.get("attempts"),
                 "event_count": event_count, "first_seen": incident.get("first_seen"), "last_seen": incident.get("last_seen")}
        merged = self.m.build_incident(event, detection, risk_msg, decision, profile,
                                       incident_id=incident["incident_id"], timestamp=incident.get("timestamp") or incident.get("created_at"),
                                       status=incident["status"].capitalize())
        return self.m.make_report(merged)

    # -- step 1: judge one event (no side effects) ----------------------------
    def _evaluate(self, event: Any, index: int = 0) -> Tuple[dict, Optional[dict]]:
        """detector -> risk -> policy for one event. Returns (result, candidate).

        Nothing is stored and no action runs here. The candidate is None unless the policy wants an
        incident; it carries everything _commit() needs.
        """
        result: Dict[str, Any] = {"index": index, "outcome": None, "error": None, "level": None, "score": None,
                                  "actions": [], "incident_id": None, "attack_type": None, "device_id": None}
        if not isinstance(event, Mapping):
            result.update(outcome="rejected", error="event_not_a_mapping")
            return result, None
        raw_device = event.get("device_id")
        device_id = raw_device if isinstance(raw_device, str) and _DEVICE_RE.fullmatch(raw_device) else None
        result["device_id"] = device_id
        profile = self.devices.get(device_id, {}) if device_id else {}

        try:
            detection = self._detect(dict(event), profile)
        except _detector_module.DetectorConfigError as exc:
            raise PipelineError("configuration problem: %s" % exc)   # a bad rules file stops the run, loudly
        except Exception as exc:
            result.update(outcome="error", error="detector_failed:" + type(exc).__name__.lower()[:30])
            return result, None
        label = detection.get("label") if isinstance(detection, Mapping) else None
        label = label.strip().upper() if isinstance(label, str) else None
        if label not in ("BENIGN", "ATTACK"):
            result.update(outcome="error", error="detector_invalid_output")
            return result, None
        if label == "BENIGN":
            result["outcome"] = "benign"
            return result, None

        try:
            risk_msg = self.m.risk.assess(detection, event, profile)
            decision = self.m.policy.decide(risk_msg, detection, event, profile, policy=self.policy_cfg)
        except (self.m.risk.RiskConfigError, self.m.policy.PolicyConfigError) as exc:
            raise PipelineError("configuration problem: %s" % exc)
        except Exception as exc:
            result.update(outcome="error", error="module_failed:" + type(exc).__name__.lower()[:30])
            return result, None

        result.update(level=risk_msg.get("level"), score=risk_msg.get("score"),
                      actions=list(decision.get("action", [])), attack_type=detection.get("attack_type"))
        candidate = {"result": result, "event": dict(event), "detection": detection, "risk": risk_msg,
                     "decision": decision, "profile": profile, "device_id": device_id,
                     "time": self._parse_time(event.get("timestamp"))}
        if "create_incident" not in decision.get("action", []):
            # nothing to store, so there is nothing to wait for: just run the actions
            self._run_actions(candidate)
            result["outcome"] = "no_incident"
            return result, None
        return result, candidate

    def _run_actions(self, candidate: dict) -> Optional[List[dict]]:
        """Run the (simulated) actions of one decision. A failing executor is reported, never raised."""
        try:
            return self.executor.run(candidate["decision"])
        except Exception as exc:
            candidate["result"]["error"] = "actions_failed:" + type(exc).__name__.lower()[:30]
            return None

    # -- step 2: store the incident, THEN act ----------------------------------
    def _incident_fields(self, group: List[dict]) -> Tuple[dict, dict]:
        """One incident record for a group of events (the highest-risk event is the representative)."""
        rep = max(enumerate(group), key=lambda ic: (ic[1]["risk"].get("score") or 0, -ic[0]))[1]
        event, detection, risk_msg, decision, profile = rep["event"], rep["detection"], rep["risk"], rep["decision"], rep["profile"]
        notes: List[str] = []
        attempts: List[float] = []
        for member in group:
            ev = member["event"]
            notes += ["missing_" + f for f in CONTEXT_FIELDS if ev.get(f) in (None, "")]
            if ev.get("timestamp") not in (None, "") and member["time"] is None:
                notes.append("invalid_timestamp")
            attempts += [n for n in (_finite(ev.get("failed_attempts")), _finite(ev.get("connection_attempts")))
                         if n is not None and n >= 0]
        notes = list(dict.fromkeys(notes))
        times = [c["time"] for c in group if c["time"] is not None]
        first = min(times).strftime("%Y-%m-%dT%H:%M:%SZ") if times else event.get("timestamp")
        last = max(times).strftime("%Y-%m-%dT%H:%M:%SZ") if times else event.get("timestamp")
        level = risk_msg.get("level")
        planned = ["%s:planned:not_run_yet" % a for a in decision.get("action", [])]
        return {
            "timestamp": first if len(group) > 1 else event.get("timestamp"),
            "first_seen": first, "last_seen": last, "event_count": len(group),
            "device_id": rep["device_id"],
            "device_type": profile.get("device_type"),
            "src_ip": event.get("src_ip"),
            "dst_ip": event.get("dst_ip"),
            "dst_port": event.get("dst_port"),
            "attack_type": detection.get("attack_type"),
            "confidence": detection.get("confidence"),
            "risk_score": risk_msg.get("score"),
            "risk_level": level,
            "risk_factors": risk_msg.get("factors"),
            "risk_warnings": list(risk_msg.get("warnings", [])) + list(decision.get("warnings", [])) + notes,
            "weight_set": risk_msg.get("weight_set"),
            "attempts": max(attempts) if attempts else None,
            "action": decision.get("action"),
            "action_result": planned,
            "reason": decision.get("reason"),
            "rule_id": decision.get("rule_id"),
            "status": "monitoring" if level == "Low" else "open",
        }, rep

    def _commit(self, group: List[dict]) -> None:
        """Save one incident for the group, and only then run the actions of its strongest event."""
        results = [c["result"] for c in group]
        fields, rep = self._incident_fields(group)
        if self.db.count() >= self.max_incidents:
            for r in results:
                r.update(outcome="error", error="incident_limit_reached")
            return
        try:
            context = (rep["event"], rep["detection"], rep["risk"], rep["decision"], rep["profile"])
            stored = self.db.insert_incident(fields, make_reports=lambda inc: self._reports(inc, context, len(group)))
        except Exception as exc:   # includes IncidentError for an unusable score or level
            for r in results:
                r.update(outcome="error", error="store_failed:" + type(exc).__name__.lower()[:30])
            return   # not saved, so nothing is blocked: an action without a record would be an unexplained block
        for c in group:
            c["result"].update(outcome="grouped", incident_id=stored["incident_id"])
        rep["result"]["outcome"] = "incident"
        records = self._run_actions(rep)
        if records is None:
            outcome = ["%s:failed:executor_error" % a for a in rep["decision"].get("action", [])]
        else:
            outcome = ["%s:%s:%s" % (r["action"], r["status"], r["note"]) for r in records]
        try:
            self.db.set_action_result(stored["incident_id"], outcome)
        except Exception:
            rep["result"]["error"] = "action_result_not_saved"

    def process_event(self, event: Any, index: int = 0) -> dict:
        """Handle one event on its own (no grouping). Never raises for bad data or a failing module
        (configuration errors still stop the run)."""
        result, candidate = self._evaluate(event, index)
        if candidate is not None:
            self._commit([candidate])
        return result

    @staticmethod
    def _parse_time(value: Any):
        return dbmod.parse_time(value)

    def _group(self, candidates: List[dict]) -> List[List[dict]]:
        """Put repeated events of one attack into one group.

        Same device, same source IP, same attack type, and each event within `group_window` seconds
        of the previous one in the group. Events without a usable time or source are never grouped.
        """
        groups: List[List[dict]] = []
        open_groups: Dict[tuple, List[dict]] = {}
        for cand in candidates:
            src = cand["event"].get("src_ip")
            key = (cand["device_id"], src, cand["detection"].get("attack_type"))
            current = open_groups.get(key)
            if (self.group_window > 0 and cand["time"] is not None and src not in (None, "") and current is not None
                    and abs((cand["time"] - current[-1]["time"]).total_seconds()) <= self.group_window):
                current.append(cand)
                continue
            current = [cand]
            groups.append(current)
            if self.group_window > 0 and cand["time"] is not None and src not in (None, ""):
                open_groups[key] = current
            else:
                open_groups.pop(key, None)
        return groups

    def process_csv(self, path: str, max_rows: int = DEFAULT_MAX_ROWS) -> Tuple[List[dict], dict]:
        results: List[dict] = []
        candidates: List[dict] = []
        summary = {"rows_read": 0, "rows_rejected": 0, "benign": 0, "attacks": 0, "incidents_stored": 0,
                   "events_grouped": 0, "errors": {}, "truncated": False}
        for line, event, problem in read_events(path, max_rows):
            if problem == "row_limit_reached":
                summary["truncated"] = True
                break
            summary["rows_read"] += 1
            if problem:
                summary["rows_rejected"] += 1
                summary["errors"][problem] = summary["errors"].get(problem, 0) + 1
                results.append({"index": line, "outcome": "rejected", "error": problem, "level": None, "score": None,
                                "actions": [], "incident_id": None, "attack_type": None, "device_id": None})
                continue
            res, cand = self._evaluate(event, line)
            results.append(res)
            if cand is not None:
                candidates.append(cand)
        for group in self._group(candidates):
            self._commit(group)
        for res in results:
            if res["outcome"] == "benign":
                summary["benign"] += 1
            elif res["outcome"] in ("incident", "no_incident", "grouped"):
                summary["attacks"] += 1
                if res["outcome"] == "incident":
                    summary["incidents_stored"] += 1
                elif res["outcome"] == "grouped":
                    summary["events_grouped"] += 1
            elif res["outcome"] == "error":
                code = res["error"].split(":")[0] if res["error"] else "error"
                summary["errors"][code] = summary["errors"].get(code, 0) + 1
            if res["outcome"] != "error" and res.get("error"):   # e.g. actions failed after the incident was saved
                code = res["error"].split(":")[0]
                summary["errors"][code] = summary["errors"].get(code, 0) + 1
        summary["by_level"] = self.db.summary_by_level()
        summary["modules"] = dict(self.m.sources)
        return results, summary


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def db_key_from_env() -> Optional[bytes]:
    """Optional secret for the incident hash chain: environment variable IOTIPS_DB_KEY (16+ characters)."""
    value = os.environ.get("IOTIPS_DB_KEY")
    if not value:
        return None
    if len(value) < 16:
        raise PipelineError("IOTIPS_DB_KEY must be at least 16 characters")
    return value.encode("utf-8")


def _safe_remove(path: str) -> None:
    if os.path.islink(path):
        raise PipelineError("refusing to delete a symbolic link: %s" % path)
    if os.path.isfile(path):
        os.remove(path)


def run_command(args: argparse.Namespace, out=None) -> int:
    out = out or sys.stdout
    modules = Modules(use_placeholder_detector=args.detector == "placeholder")
    policy_cfg = modules.policy.load_policy()
    devices = load_devices(args.devices) if args.devices and os.path.exists(args.devices) else {}
    if args.devices and not os.path.exists(args.devices):
        print("note: devices file %s not found; every device is treated as unknown (cautious defaults)" % args.devices, file=out)
    log_path = args.action_log or os.path.join(os.path.dirname(os.path.abspath(args.db)), "actions.jsonl")
    for path in (args.db, log_path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    if args.reset:
        for path in (args.db, log_path, log_path + ".1"):
            _safe_remove(path)
    key = db_key_from_env()
    try:
        database = dbmod.IncidentDB(args.db, hmac_key=key)
    except dbmod.IncidentDBError as exc:
        raise PipelineError(str(exc))
    with database:
        executor = modules.actions.ActionExecutor.from_policy(policy_cfg, log_path=log_path)
        pipeline = Pipeline(database, modules, devices, executor, policy_cfg, max_incidents=args.max_incidents,
                            group_window=args.group_window)
        results, summary = pipeline.process_csv(args.events, max_rows=args.max_rows)
        summary["head_hash"] = database.head_hash()
        summary["hash_mode"] = "hmac-sha256" if key else "sha256 (set IOTIPS_DB_KEY for a keyed chain)"
    _print_run_summary(summary, executor, log_path, args, out)
    return 2 if (summary["errors"] or summary["rows_rejected"]) else 0


def _print_run_summary(summary: dict, executor, log_path: str, args: argparse.Namespace, out) -> None:
    modules = summary["modules"]
    print("IoT-IPS pipeline run", file=out)
    print("  modules      : " + ", ".join("%s=%s" % (k, v) for k, v in sorted(modules.items())), file=out)
    print("  rows read    : %d (rejected %d)%s" % (summary["rows_read"], summary["rows_rejected"],
                                                    ", stopped at the row limit" if summary["truncated"] else ""), file=out)
    print("  benign       : %d" % summary["benign"], file=out)
    print("  attacks      : %d, incidents stored: %d (%d repeated events grouped into them)"
          % (summary["attacks"], summary["incidents_stored"], summary.get("events_grouped", 0)), file=out)
    print("  by level     : " + ", ".join("%s %d" % (k, v) for k, v in summary["by_level"].items()), file=out)
    if summary["errors"]:
        print("  problems     : " + ", ".join("%s x%d" % (k, v) for k, v in sorted(summary["errors"].items())), file=out)
    print("  action log   : %s (%d records, all simulated)" % (log_path, len(executor.records)), file=out)
    print("  database     : %s" % args.db, file=out)
    print("  chain head   : %s [%s]" % (summary["head_hash"][:16] + "...", summary["hash_mode"]), file=out)


def _clean_cell(value: Any, width: int) -> str:
    text = "-" if value is None else str(value)
    return re.sub(r"[^\x20-\x7e]", "?", text)[:width]


def format_table(incidents: List[dict]) -> str:
    columns = [("id", "incident_id", 9), ("time", "timestamp", 20), ("device", "device_id", 14), ("source", "src_ip", 15),
               ("attack", "attack_type", 14), ("events", "event_count", 6), ("conf", "confidence", 5), ("score", "risk_score", 5),
               ("level", "risk_level", 8), ("actions", "action", 44), ("status", "status", 10)]
    lines = ["  ".join(title.ljust(width) for title, _k, width in columns)]
    lines.append("  ".join("-" * width for _t, _k, width in columns))
    for inc in incidents:
        cells = []
        for _title, key, width in columns:
            value = inc.get(key)
            if key == "action":
                value = ",".join(value or [])
            elif key == "confidence" and value is not None:
                value = "%.2f" % value
            cells.append(_clean_cell(value, width).ljust(width))
        lines.append("  ".join(cells))
    return "\n".join(lines)


def show_command(args: argparse.Namespace, out=None) -> int:
    out = out or sys.stdout
    if not os.path.isfile(args.db):
        raise PipelineError("database %s does not exist; run the pipeline first" % args.db)
    try:
        database = dbmod.IncidentDB(args.db, hmac_key=db_key_from_env())
    except dbmod.IncidentDBError as exc:
        raise PipelineError(str(exc))
    with database:
        if args.full:
            try:
                inc = database.get_incident(args.full)
            except (KeyError, ValueError):
                raise PipelineError("incident not found or id not valid (use INC-00001)")
            print(format_table([inc]), file=out)
            print("\nreason : %s" % _clean_cell(inc["reason"], 300), file=out)
            print("rule   : %s   weight set: %s   dry run: %s" % (_clean_cell(inc["rule_id"], 40), _clean_cell(inc["weight_set"], 32), inc["dry_run"]), file=out)
            print("results: %s" % ", ".join(inc["action_result"]), file=out)
            print("notes  : %s" % (", ".join(inc["risk_warnings"]) or "none"), file=out)
            print("\n--- technical report ---\n%s\n\n--- executive report ---\n%s" % (inc["report_technical"], inc["report_plain"]), file=out)
            if inc.get("report_notification"):
                print("\n--- notification ---\n%s" % inc["report_notification"], file=out)
            return 0
        try:
            rows = database.query_incidents(level=args.level, device_id=args.device, src_ip=args.source,
                                            attack_type=args.attack, status=args.status, since=args.since, limit=args.limit)
        except ValueError as exc:
            raise PipelineError(str(exc))
        print(format_table(rows) if rows else "(no incidents match)", file=out)
        print("\nIncidents by level: " + ", ".join("%s %d" % (k, v) for k, v in database.summary_by_level().items())
              + "   (total %d)" % database.count(), file=out)
        print("By status         : " + ", ".join("%s %d" % (k, v) for k, v in database.summary_by_status().items()), file=out)
    return 0


def verify_command(args: argparse.Namespace, out=None) -> int:
    out = out or sys.stdout
    if not os.path.isfile(args.db):
        raise PipelineError("database %s does not exist" % args.db)
    try:
        database = dbmod.IncidentDB(args.db, hmac_key=db_key_from_env())
    except dbmod.IncidentDBError as exc:
        raise PipelineError(str(exc))
    with database:
        report = database.verify_chain(expected_head=args.head)
    print("incidents checked: %d" % report["rows"], file=out)
    print("head hash        : %s" % report["head"], file=out)
    if report["ok"]:
        print("RESULT: chain is intact", file=out)
        return 0
    print("RESULT: TAMPERING OR CORRUPTION FOUND", file=out)
    for problem in report["problems"]:
        print("  - " + problem, file=out)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iot-ips", description="IoT-IPS pipeline: CSV events to incidents.")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="process a CSV of events")
    run.add_argument("events", help="events CSV (for example data/sample_events.csv)")
    run.add_argument("--db", default=os.path.join("output", "incidents.db"))
    run.add_argument("--devices", default=str(DEFAULT_DEVICES_PATH), help="device profiles (default: config/devices.json)")
    run.add_argument("--action-log", default=None, help="action log file (default: actions.jsonl beside the database)")
    run.add_argument("--max-rows", type=int, default=DEFAULT_MAX_ROWS)
    run.add_argument("--max-incidents", type=int, default=DEFAULT_MAX_INCIDENTS)
    run.add_argument("--group-window", type=int, default=DEFAULT_GROUP_WINDOW_S, metavar="SECONDS",
                     help="events of one attack from one source this close in time become one incident (0 = never group; default 300)")
    run.add_argument("--detector", choices=("auto", "placeholder"), default="auto",
                     help="auto = the rule-based detector; placeholder = the built-in threshold stand-in (used by the tests)")
    run.add_argument("--reset", action="store_true", help="delete the database and action log first")
    run.set_defaults(func=run_command)

    show = sub.add_parser("show", help="print stored incidents and a count by level")
    show.add_argument("--db", default=os.path.join("output", "incidents.db"))
    show.add_argument("--level")
    show.add_argument("--device")
    show.add_argument("--source", help="source IP")
    show.add_argument("--attack")
    show.add_argument("--status")
    show.add_argument("--since", help="ISO date or time, for example 2026-10-20")
    show.add_argument("--limit", type=int, default=50)
    show.add_argument("--full", metavar="INC-00001", help="print one incident with both reports")
    show.set_defaults(func=show_command)

    verify = sub.add_parser("verify", help="check the incident database for tampering")
    verify.add_argument("--db", default=os.path.join("output", "incidents.db"))
    verify.add_argument("--head", help="head hash saved earlier")
    verify.set_defaults(func=verify_command)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    for name in ("max_rows", "max_incidents", "limit"):
        value = getattr(args, name, None)
        if value is not None and not 1 <= value <= 10_000_000:
            print("error: --%s must be between 1 and 10000000" % name.replace("_", "-"), file=sys.stderr)
            return 2
    window = getattr(args, "group_window", None)
    if window is not None and not 0 <= window <= 86_400:
        print("error: --group-window must be between 0 and 86400 seconds", file=sys.stderr)
        return 2
    try:
        return args.func(args)
    except PipelineError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
