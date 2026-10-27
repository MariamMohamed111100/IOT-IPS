# The pipeline and the incident database

```
CSV row -> detect -> risk.assess -> policy.decide -> group repeats -> (create_incident?) -> IncidentDB + reports -> ActionExecutor.run -> action result saved
```

* A benign verdict stores nothing.
* An incident is stored only when the policy's actions contain `create_incident`.
* **The incident is saved first, then the actions run.** If the incident cannot be saved (database error, incident limit) no action runs: a block without a record would be an unexplained block once real blocking exists. The outcome of the actions (`block_source:simulated:ok`, ...) is written to the incident's `action_result` afterwards; until then it reads `action:planned:not_run_yet`. If the executor crashes the incident stays and its result reads `action:failed:executor_error`.
* **Repeated events become one incident.** Events with the same device, source IP and attack type, each within `--group-window` seconds (default 300) of the previous one, are one incident. `event_count`, `first_seen` and `last_seen` say how many and when; the score, actions and report are those of the highest-risk event, and the attempt count is the largest seen. Events without a usable time or source are never grouped. `--group-window 0` gives one incident per event. Grouping works on the file as a whole (batch); a live service would need to update an open incident instead.
* Everything is a simulation. `dry_run` is always true and no firewall command runs, so an incident's status is `open` (or `monitoring` for Low), never `contained`.

## Commands

| Command | What it does |
|---|---|
| `python run_demo.py` | Whole demo: run `data/sample_events.csv`, print the incidents and a count by level, verify the database. Output goes to `output/`. |
| `python -m pytest` | Every unit test. |
| `iot-ips run data/sample_events.csv` | Process a CSV into `output/incidents.db` (add `--reset` to start clean). Without installing: `python -m iot_ips run ...` with `PYTHONPATH=src`. |
| `iot-ips show` | Table of stored incidents plus the count by level and by status. Filters: `--level`, `--device`, `--source`, `--attack`, `--status`, `--since`, `--limit`. |
| `iot-ips show --full INC-00005` | One incident with its technical report, executive report and notification. |
| `iot-ips verify` | Checks the hash chain for edited or deleted rows. Exit code 1 if tampering is found. |

Options of `run`: `--db`, `--devices` (default `config/devices.json`), `--action-log`, `--max-rows`, `--max-incidents`, `--group-window SECONDS` (default 300, 0 = off), `--detector placeholder` (use the small threshold stand-in from `placeholders.py`; the tests use it so they do not depend on the detector's thresholds).

Exit codes: 0 clean, 1 tampering found, 2 bad input or errors.

## Incident table

`incident_id, timestamp, device_id, device_type, src_ip, dst_ip, dst_port, attack_type, confidence, risk_score, risk_level, risk_factors, risk_warnings, weight_set, attempts, event_count, first_seen, last_seen, action, action_result, reason, rule_id, status, dry_run, report_technical, report_plain, report_notification, created_at, prev_hash, row_hash`

The design in the task plan has one `report` column; the database has three (technical report, executive report, notification for High and Critical). Risk and action fields are split into separate columns.

```python
from iot_ips.db import IncidentDB

with IncidentDB("output/incidents.db") as d:
    d.query_incidents(level="Critical")
    d.summary_by_level()
    d.set_status("INC-00005", "resolved")      # editable: status, and action_result (filled in after the actions ran)
```

## Input format (CSV)

Columns used: `device_id, timestamp, src_ip, dst_ip, dst_port, protocol, direction (inbound/outbound), failed_attempts, connection_attempts, unique_dst_ports, unique_dst_ips` plus the CICIoT2023 feature columns (`Rate`, `syn_count`, ...). Columns starting with `expected_` are for humans and are never passed on. A missing value becomes a cautious default and a note such as `missing_src_ip` in the incident's warnings.

Device profiles come from `config/devices.json` (`{"devices": [...]}` or a plain list). Each needs `device_id, device_type, ip, criticality, expected_protocols, expected_ports`. A device that is not in the file is handled with cautious defaults: no unexpected-port rule, no deviation score, no isolation.

## Safety

* Only parameterised SQL. Every field is validated and length-limited before it is stored.
* Rows are hash-chained (SHA-256). `status` and `action_result` are not part of the hash because they are filled in or changed after the row is written; the action log is the evidence for what was executed. Set the environment variable `IOTIPS_DB_KEY` (16+ characters) for an HMAC chain that someone who can edit the file cannot recompute. Keep the head hash that `run` prints somewhere else and pass it to `verify --head` to also catch deleted last rows. The hash includes the creation time, so it differs between runs.
* The database file is created with owner-only permissions; symbolic links are refused.
* CSV limits: 20 MB, 100,000 rows, 300 columns; bad rows are skipped and counted; text from the CSV is never printed back in errors.
* Free text from the CSV never reaches a report: the report module receives only values the database layer has already validated.

## Result on the 14 sample events

4 benign events: 0 false alarms. 10 attacks: 7 are detected; 3 are missed (`EVT-007` vulnerability scanner and `EVT-013` command injection through web requests: threshold rules cannot see them, the ML model should; `EVT-012` fake camera upload, a rate without many connections, is no longer a DoS). With `--group-window 0` the 7 detections are 7 incidents (Medium 2, High 1, Critical 4). With the default window the two floods from `203.0.113.45` (`EVT-010`, `EVT-011`, 45 s apart) become one incident with `event_count` 2: **6 incidents** (Medium 2, High 1, Critical 3). The run prints `benign: 7` because it counts every event the detector called benign: the 4 real benign events plus those 3 missed attacks.

Three of the seven detected attacks carry a different attack type from `expected_attack_type`: `EVT-006` slow scan and `EVT-009` six password guesses (both reported as "unexpected port", because the camera does not expect port 22 or 8080) and `EVT-014` Mirai flood (reported as DoS). The risk level is still sensible for each. The thresholds were set looking at these 14 events, so this table is a check that the chain works, not a measurement of accuracy.
