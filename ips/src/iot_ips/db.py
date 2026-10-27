"""
db.py - SQLite incident database for the IoT-IPS

    db = IncidentDB("incidents.db")
    incident = db.insert_incident(raw_fields, make_reports=report_function)
    db.query_incidents(level="High")      db.summary_by_level()      db.verify_chain()

Design rules (the database holds the evidence, so it is treated as a target):
  * Every value is cleaned before it is stored: IPs go through `ipaddress`,
    identifiers and names must match a strict pattern, numbers are range-checked,
    free text is reduced to a safe character set. The cleaner never raises for a
    bad optional field (it stores NULL or a placeholder); it raises
    IncidentError only when the risk score or level is missing, because an
    incident without them is meaningless.
  * Only parameterised SQL is used; column names that appear in a query come
    from fixed lists in this file, never from input.
  * The table has CHECK constraints, so even a buggy caller cannot store a score
    of 500 or a level called "Severe".
  * Tamper evidence: every row stores the hash of the previous row and its own
    hash (SHA-256, or HMAC-SHA256 when a key is given). Editing, deleting or
    reordering a stored incident is detected by verify_chain(). Without a key an
    attacker who can write the file can recompute the whole chain, so for real
    protection pass a secret key and/or keep the head hash somewhere else.
  * The database file is created with owner-only permissions and a symbolic link
    is refused.
  * Status and action_result are the only columns that may change later: an analyst closes an
    incident, and the outcome of the simulated actions is written after the incident was saved
    (the incident is stored first, then the actions run). Neither is part of the hash; the action
    log (actions.jsonl) is the evidence for what was executed.
  * One incident can stand for several events (same device, source and attack within a time
    window): event_count, first_seen and last_seen say how many and when.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import ipaddress
import json
import math
import numbers
import os
import re
import sqlite3
from typing import Any, Callable, Dict, List, Optional

__all__ = ["IncidentDB", "IncidentError", "IncidentDBError", "clean_incident", "parse_time", "LEVELS", "STATUSES"]

SCHEMA_VERSION = 2   # 2: event_count, first_seen, last_seen (grouped incidents); action_result is filled in after the incident is saved
LEVELS = ("Low", "Medium", "High", "Critical")
STATUSES = ("open", "monitoring", "contained", "resolved")
FACTOR_NAMES = ("confidence", "attack_severity", "device_criticality", "persistence",
                "source_trust", "behavioral_deviation", "potential_impact")
GENESIS_HASH = "0" * 64
MAX_QUERY_LIMIT = 1000
MAX_REPORT_CHARS = 20000

_DEVICE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,39}")
_NAME_RE = re.compile(r"[a-z0-9_]{1,40}")
_SET_RE = re.compile(r"[a-z0-9_]{1,32}")
_WARN_RE = re.compile(r"[a-z0-9_:]{1,64}")
_ACTION_RE = re.compile(r"[a-z_]{1,32}")
_RESULT_RE = re.compile(r"[a-z_]{1,32}:[a-z_]{1,16}:[a-z_]{1,40}")
_DETAIL_RE = re.compile(r"[A-Za-z0-9_=]{1,64}")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
_UNSAFE_TEXT_RE = re.compile(r"[^A-Za-z0-9 .,:;()_/%=+-]")
_UNSAFE_REPORT_RE = re.compile(r"[^\x20-\x7e\n]")


class IncidentError(ValueError):
    """The incident data is unusable (no valid risk score or level)."""


class IncidentDBError(RuntimeError):
    """The database file or its settings are unsafe or inconsistent."""


# ---------------------------------------------------------------------------
# Cleaning
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


def _clean_ip(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 64:
        return None
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def _clean_port(value: Any) -> Optional[int]:
    number = _finite(value)
    if number is None or not number.is_integer() or not 0 <= number <= 65535:
        return None
    return int(number)


def _clean_name(value: Any, fallback: str) -> str:
    if not isinstance(value, str):
        return fallback
    text = _NON_ALNUM_RE.sub("_", value.strip()[:100].lower()).strip("_")
    return text if _NAME_RE.fullmatch(text) else fallback


def _parse_time(value: Any) -> Optional[_dt.datetime]:
    """Naive UTC datetime from a datetime or a short ISO string, else None."""
    moment = None
    if isinstance(value, _dt.datetime):
        moment = value
    elif isinstance(value, str) and 0 < len(value.strip()) <= 40:
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            moment = _dt.datetime.fromisoformat(text)
        except ValueError:
            return None
    if moment is None:
        return None
    if moment.tzinfo is not None:
        moment = moment.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    return moment if 1970 <= moment.year <= 2200 else None


parse_time = _parse_time   # public alias: naive UTC datetime or None


def _clean_time(value: Any, now: _dt.datetime) -> str:
    moment = _parse_time(value)
    if moment is None:
        moment = _parse_time(now) or _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None, microsecond=0)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _clean_list(value: Any, pattern, limit: int) -> List[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    out: List[str] = []
    for item in value[:limit]:
        if isinstance(item, str) and pattern.fullmatch(item) and item not in out:
            out.append(item)
    return out


def _clean_factors(value: Any) -> Dict[str, dict]:
    if isinstance(value, str) and len(value) <= 16384:
        try:
            value = json.loads(value, parse_constant=lambda _c: (_ for _ in ()).throw(ValueError()))
        except (ValueError, RecursionError):
            value = None
    if not isinstance(value, dict):
        return {}
    out: Dict[str, dict] = {}
    for name in FACTOR_NAMES:
        entry = value.get(name)
        if not isinstance(entry, dict):
            continue
        number = {}
        for key, hi in (("value", 100.0), ("weight", 1.0), ("contribution", 100.0)):
            n = _finite(entry.get(key))
            number[key] = round(n, 4) if n is not None and 0 <= n <= hi else None
        detail = entry.get("detail")
        number["detail"] = detail if isinstance(detail, str) and _DETAIL_RE.fullmatch(detail) else None
        out[name] = number
    return out


def _clean_text(value: Any, limit: int) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text = " ".join(_UNSAFE_TEXT_RE.sub(" ", value[: limit * 2]).split())[:limit]
    return text or None


def _clean_report(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text = _UNSAFE_REPORT_RE.sub("?", value[:MAX_REPORT_CHARS])
    return text or None


def clean_incident(raw: Any, now: Optional[_dt.datetime] = None) -> dict:
    """Turn raw incident data into storable, validated fields.

    Raises IncidentError only if there is no valid risk score and level.
    """
    if not isinstance(raw, dict):
        raise IncidentError("incident must be a dict")
    now = now or _dt.datetime.now(_dt.timezone.utc)

    score = _finite(raw.get("risk_score"))
    if score is None or not 0 <= score <= 100:
        raise IncidentError("risk_score must be a number from 0 to 100")
    level_raw = raw.get("risk_level")
    level = level_raw.strip().capitalize() if isinstance(level_raw, str) else None
    if level not in LEVELS:
        raise IncidentError("risk_level must be Low, Medium, High or Critical")

    confidence = _finite(raw.get("confidence"))
    attempts = _finite(raw.get("attempts"))
    count = _finite(raw.get("event_count"))
    status = raw.get("status")
    first_seen = _clean_time(raw.get("first_seen") or raw.get("timestamp"), now)
    device_id = raw.get("device_id")
    rule_id = raw.get("rule_id")
    weight_set = raw.get("weight_set")
    return {
        "timestamp": _clean_time(raw.get("timestamp"), now),
        "first_seen": first_seen,
        "last_seen": _clean_time(raw.get("last_seen") or raw.get("timestamp"), now),
        "event_count": int(count) if count is not None and count.is_integer() and 1 <= count <= 10 ** 6 else 1,
        "device_id": device_id if isinstance(device_id, str) and _DEVICE_RE.fullmatch(device_id) else "unknown-device",
        "device_type": _clean_name(raw.get("device_type"), "unknown"),
        "src_ip": _clean_ip(raw.get("src_ip")),
        "dst_ip": _clean_ip(raw.get("dst_ip")),
        "dst_port": _clean_port(raw.get("dst_port")),
        "attack_type": _clean_name(raw.get("attack_type"), "unknown"),
        "confidence": round(confidence, 4) if confidence is not None and 0 <= confidence <= 1 else None,
        "risk_score": int(math.floor(score + 0.5)),
        "risk_level": level,
        "risk_factors": _json(_clean_factors(raw.get("risk_factors"))),
        "risk_warnings": _json(_clean_list(raw.get("risk_warnings"), _WARN_RE, 32)),
        "weight_set": weight_set if isinstance(weight_set, str) and _SET_RE.fullmatch(weight_set) else None,
        "attempts": int(attempts) if attempts is not None and 0 <= attempts <= 10 ** 9 else None,
        "action": _json(_clean_list(raw.get("action"), _ACTION_RE, 16)),
        "action_result": _json(_clean_list(raw.get("action_result"), _RESULT_RE, 32)),
        "reason": _clean_text(raw.get("reason"), 300),
        "rule_id": rule_id if isinstance(rule_id, str) and re.fullmatch(r"[a-z0-9_]{1,40}", rule_id) else None,
        "status": status if isinstance(status, str) and status in STATUSES else "open",
        "dry_run": 1,   # this version only simulates actions
    }


# ---------------------------------------------------------------------------
# The database
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id      TEXT    NOT NULL UNIQUE,
    timestamp        TEXT    NOT NULL,
    device_id        TEXT    NOT NULL,
    device_type      TEXT    NOT NULL,
    src_ip           TEXT,
    dst_ip           TEXT,
    dst_port         INTEGER CHECK (dst_port IS NULL OR (dst_port BETWEEN 0 AND 65535)),
    attack_type      TEXT    NOT NULL,
    confidence       REAL    CHECK (confidence IS NULL OR (confidence BETWEEN 0 AND 1)),
    risk_score       INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_level       TEXT    NOT NULL CHECK (risk_level IN ('Low','Medium','High','Critical')),
    risk_factors     TEXT    NOT NULL,
    risk_warnings    TEXT    NOT NULL,
    weight_set       TEXT,
    attempts         INTEGER CHECK (attempts IS NULL OR attempts >= 0),
    event_count      INTEGER NOT NULL CHECK (event_count >= 1),
    first_seen       TEXT    NOT NULL,
    last_seen        TEXT    NOT NULL,
    action           TEXT    NOT NULL,
    action_result    TEXT    NOT NULL,
    reason           TEXT,
    rule_id          TEXT,
    status           TEXT    NOT NULL CHECK (status IN ('open','monitoring','contained','resolved')),
    dry_run          INTEGER NOT NULL CHECK (dry_run IN (0,1)),
    report_technical TEXT,
    report_plain     TEXT,
    report_notification TEXT,
    created_at       TEXT    NOT NULL,
    prev_hash        TEXT    NOT NULL,
    row_hash         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_level  ON incidents (risk_level);
CREATE INDEX IF NOT EXISTS idx_incidents_device ON incidents (device_id);
CREATE INDEX IF NOT EXISTS idx_incidents_src    ON incidents (src_ip);
"""

# Columns written by insert_incident(), in order (id is added separately).
_STORED = ("incident_id", "timestamp", "device_id", "device_type", "src_ip", "dst_ip", "dst_port", "attack_type",
           "confidence", "risk_score", "risk_level", "risk_factors", "risk_warnings", "weight_set", "attempts",
           "event_count", "first_seen", "last_seen", "action", "action_result", "reason", "rule_id", "status", "dry_run", "report_technical", "report_plain",
           "report_notification", "created_at")
_HASHED = tuple(c for c in _STORED if c not in ("status", "action_result"))   # these two may be filled in later
_JSON_COLUMNS = ("risk_factors", "risk_warnings", "action", "action_result")
_LIST_COLUMNS = (("risk_warnings",), ("action",), ("action_result",))
_FILTERS = {"level": "risk_level", "device_id": "device_id", "src_ip": "src_ip",
            "attack_type": "attack_type", "status": "status"}


class IncidentDB:
    """SQLite incident store. Use as a context manager or call close()."""

    def __init__(self, path: str = ":memory:", hmac_key: Optional[bytes] = None):
        if hmac_key is not None and (not isinstance(hmac_key, (bytes, bytearray)) or len(hmac_key) < 16):
            raise IncidentDBError("hmac_key must be at least 16 bytes")
        self._key = bytes(hmac_key) if hmac_key else None
        self.path = path
        if path != ":memory:":
            self._prepare_file(path)
        self._conn = sqlite3.connect(path, timeout=10, isolation_level=None)   # we manage transactions
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        try:
            self._conn.execute("PRAGMA trusted_schema = OFF")
        except sqlite3.DatabaseError:
            pass
        try:
            self._conn.executescript(_SCHEMA)
            self._check_meta()
        except Exception:
            self._conn.close()
            raise

    @staticmethod
    def _prepare_file(path: str) -> None:
        if os.path.islink(path):
            raise IncidentDBError("refusing to use a symbolic link as the database file")
        if not os.path.exists(path):
            flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            try:
                os.close(os.open(path, flags, 0o600))
            except OSError as exc:
                raise IncidentDBError("cannot create database file (%s)" % (exc.strerror or "error"))
        elif os.path.isdir(path):
            raise IncidentDBError("database path is a directory")

    def _check_meta(self) -> None:
        mode = "hmac-sha256" if self._key else "sha256"
        rows = dict(self._conn.execute("SELECT key, value FROM meta").fetchall())
        if not rows:
            self._conn.executemany("INSERT INTO meta (key, value) VALUES (?, ?)",
                                   [("schema_version", str(SCHEMA_VERSION)), ("hash_mode", mode)])
            return
        if rows.get("schema_version") != str(SCHEMA_VERSION):
            raise IncidentDBError("database has an unsupported schema version")
        if rows.get("hash_mode") != mode:
            raise IncidentDBError("database was created with hash mode %r but this run uses %r (key missing or unexpected)"
                                  % (rows.get("hash_mode"), mode))

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "IncidentDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- hashing -------------------------------------------------------------
    def _digest(self, row_id: int, values: Dict[str, Any], prev_hash: str) -> str:
        payload = _json({"id": row_id, "prev": prev_hash, "fields": {c: values[c] for c in _HASHED}}).encode("ascii")
        if self._key:
            return hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        return hashlib.sha256(payload).hexdigest()

    def head_hash(self) -> str:
        row = self._conn.execute("SELECT row_hash FROM incidents ORDER BY id DESC LIMIT 1").fetchone()
        return row["row_hash"] if row else GENESIS_HASH

    # -- writing -------------------------------------------------------------
    def insert_incident(self, raw: Any, make_reports: Optional[Callable[[dict], Any]] = None,
                        now: Optional[_dt.datetime] = None) -> dict:
        """Clean and store one incident; return the stored record.

        make_reports(incident) is called inside the transaction, after the
        incident id is known, and may return a dict with 'technical' and
        'non_technical' texts (or one string). A failing report function never
        stops the incident from being stored.
        """
        now = now or _dt.datetime.now(_dt.timezone.utc)
        fields = clean_incident(raw, now)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            seq = self._conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'incidents'").fetchone()
            row_id = (seq["seq"] if seq else 0) + 1
            fields["incident_id"] = "INC-%05d" % row_id
            fields["created_at"] = now.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if now.tzinfo \
                else now.strftime("%Y-%m-%dT%H:%M:%SZ")
            technical = plain = notification = None
            if make_reports is not None:
                try:
                    produced = make_reports(self._row_to_incident(dict(fields, id=row_id)))
                except Exception:   # a broken report module must not lose the incident
                    produced = None
                if isinstance(produced, dict):
                    technical = _clean_report(produced.get("technical"))
                    plain = _clean_report(produced.get("executive", produced.get("non_technical", produced.get("plain"))))
                    notification = _clean_report(produced.get("notification"))
                elif isinstance(produced, str):
                    technical = plain = _clean_report(produced)
            fields["report_technical"], fields["report_plain"], fields["report_notification"] = technical, plain, notification
            prev = self.head_hash()
            fields["prev_hash"] = prev
            fields["row_hash"] = self._digest(row_id, fields, prev)
            columns = ("id",) + _STORED + ("prev_hash", "row_hash")
            values = (row_id,) + tuple(fields[c] for c in _STORED) + (prev, fields["row_hash"])
            self._conn.execute("INSERT INTO incidents (%s) VALUES (%s)" % (", ".join(columns), ", ".join("?" * len(columns))),
                               values)
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        return self.get_incident(row_id)

    def set_status(self, incident: Any, status: str) -> None:
        """Change the status of one incident (the only editable field)."""
        if not isinstance(status, str) or status not in STATUSES:
            raise ValueError("status must be one of: %s" % ", ".join(STATUSES))
        row_id = self._resolve_id(incident)
        cur = self._conn.execute("UPDATE incidents SET status = ? WHERE id = ?", (status, row_id))
        if cur.rowcount != 1:
            raise KeyError("no such incident")

    def set_action_result(self, incident: Any, results: Any) -> None:
        """Record what the actions did, after the incident was saved (list of 'action:status:note')."""
        row_id = self._resolve_id(incident)
        cleaned = _clean_list(results, _RESULT_RE, 32)
        cur = self._conn.execute("UPDATE incidents SET action_result = ? WHERE id = ?", (_json(cleaned), row_id))
        if cur.rowcount != 1:
            raise KeyError("no such incident")

    # -- reading -------------------------------------------------------------
    @staticmethod
    def _resolve_id(incident: Any) -> int:
        if isinstance(incident, bool):
            raise ValueError("bad incident id")
        if isinstance(incident, int):
            return incident
        if isinstance(incident, str):
            match = re.fullmatch(r"INC-(\d{1,9})", incident.strip())
            if match:
                return int(match.group(1))
        raise ValueError("incident id must look like INC-00012")

    @staticmethod
    def _row_to_incident(row: Any, include_reports: bool = True) -> dict:
        data = dict(row)
        for column in _JSON_COLUMNS:
            data[column] = json.loads(data[column])
        data["dry_run"] = bool(data["dry_run"])
        if not include_reports:
            data.pop("report_technical", None)
            data.pop("report_plain", None)
            data.pop("report_notification", None)
        return data

    def get_incident(self, incident: Any, include_reports: bool = True) -> dict:
        row = self._conn.execute("SELECT * FROM incidents WHERE id = ?", (self._resolve_id(incident),)).fetchone()
        if row is None:
            raise KeyError("no such incident")
        return self._row_to_incident(row, include_reports)

    def query_incidents(self, level: Optional[str] = None, device_id: Optional[str] = None, src_ip: Optional[str] = None,
                        attack_type: Optional[str] = None, status: Optional[str] = None, since: Optional[str] = None,
                        limit: int = 100, include_reports: bool = False) -> List[dict]:
        """Newest first. Filters are validated, then used as query parameters."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_QUERY_LIMIT:
            raise ValueError("limit must be an integer from 1 to %d" % MAX_QUERY_LIMIT)
        clauses, params = [], []
        given = {"level": level, "device_id": device_id, "src_ip": src_ip, "attack_type": attack_type, "status": status}
        for name, value in given.items():
            if value is None:
                continue
            if name == "level":
                value = value.strip().capitalize() if isinstance(value, str) else None
                if value not in LEVELS:
                    raise ValueError("level must be one of: %s" % ", ".join(LEVELS))
            elif name == "status":
                if not isinstance(value, str) or value not in STATUSES:
                    raise ValueError("status must be one of: %s" % ", ".join(STATUSES))
            elif name == "src_ip":
                value = _clean_ip(value)
                if value is None:
                    raise ValueError("src_ip is not a valid address")
            elif name == "device_id":
                if not isinstance(value, str) or not _DEVICE_RE.fullmatch(value):
                    raise ValueError("device_id is not a valid identifier")
            else:
                value = _clean_name(value, "")
                if not value:
                    raise ValueError("attack_type is not valid")
            clauses.append("%s = ?" % _FILTERS[name])   # column name comes from the fixed dict above
            params.append(value)
        if since is not None:
            moment = _parse_time(since)
            if moment is None or not isinstance(since, str) or len(since.strip()) < 10:
                raise ValueError("since must be an ISO date or time")
            clauses.append("timestamp >= ?")
            params.append(moment.strftime("%Y-%m-%dT%H:%M:%SZ"))
        sql = "SELECT * FROM incidents" + (" WHERE " + " AND ".join(clauses) if clauses else "") + " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [self._row_to_incident(r, include_reports) for r in self._conn.execute(sql, params).fetchall()]

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) AS n FROM incidents").fetchone()["n"]

    def summary_by_level(self) -> Dict[str, int]:
        counts = {level: 0 for level in LEVELS}
        for row in self._conn.execute("SELECT risk_level, COUNT(*) AS n FROM incidents GROUP BY risk_level"):
            counts[row["risk_level"]] = row["n"]
        return counts

    def summary_by_status(self) -> Dict[str, int]:
        counts = {status: 0 for status in STATUSES}
        for row in self._conn.execute("SELECT status, COUNT(*) AS n FROM incidents GROUP BY status"):
            counts[row["status"]] = row["n"]
        return counts

    # -- integrity -----------------------------------------------------------
    def verify_chain(self, expected_head: Optional[str] = None) -> dict:
        """Recompute every hash. Returns {"ok", "rows", "head", "problems"}.

        Detects edited, deleted (also the newest one) and reordered incidents.
        `expected_head` is a head hash saved earlier; if given it must match.
        """
        problems: List[str] = []
        prev = GENESIS_HASH
        rows = 0
        last_id = 0
        for row in self._conn.execute("SELECT * FROM incidents ORDER BY id ASC"):
            rows += 1
            data = dict(row)
            if data["incident_id"] != "INC-%05d" % data["id"]:
                problems.append("row %d: incident_id does not match its number" % data["id"])
            if data["prev_hash"] != prev:
                problems.append("row %d: previous hash does not match (an earlier incident was changed or removed)" % data["id"])
            try:
                expected = self._digest(data["id"], data, data["prev_hash"])
            except (KeyError, ValueError, TypeError):
                expected = None
            if expected is None or not hmac.compare_digest(str(data["row_hash"]), expected):
                problems.append("row %d: content does not match its hash (edited)" % data["id"])
            prev = data["row_hash"]
            last_id = data["id"]
        seq = self._conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'incidents'").fetchone()
        if seq is not None and seq["seq"] != last_id:
            problems.append("the newest incident (INC-%05d) was deleted" % seq["seq"] if seq["seq"] > last_id
                            else "the id counter is behind the newest row")
        head = self.head_hash()
        if expected_head is not None and (not isinstance(expected_head, str) or not hmac.compare_digest(head, expected_head.strip().lower())):
            problems.append("head hash does not match the saved value (the log was cut short or replaced)")
        return {"ok": not problems, "rows": rows, "head": head, "problems": problems}
