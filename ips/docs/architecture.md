# Architecture

```
CSV event ──> detector ──> risk engine ──> policy ──> actions ──> incident database ──> reports
              detector.py   risk.py        policy.py  actions.py   db.py                report.py
                 ▲             ▲              ▲          ▲
          detector_rules.yaml  risk_weights.yaml  policy.yaml      devices.json (profiles, used by all)
```

`pipeline.py` connects the stages. Configuration lives in `config/`; each stage validates its file strictly when it loads it.

## Messages between the stages

Plain Python dicts (or JSON).

| Message | Fields | Produced by |
|---|---|---|
| Event features | CICIoT2023 columns: rates, flag counts, protocol shares, sizes | `data/sample_events.csv` |
| Event context | `device_id, timestamp, src_ip, dst_ip, dst_port, protocol, direction, failed_attempts, connection_attempts, unique_dst_ports, unique_dst_ips` (`direction` = `inbound` or `outbound`, relative to the device) | the same CSV (CICIoT2023 has none of these, so the sample events supply them) |
| Detection | `label` (BENIGN/ATTACK), `attack_type`, `confidence`, `mitre_technique` | `detector.detect(event, profile)` |
| Risk | `score` 0-100, `level` (Low < 30, Medium < 60, High < 80, Critical), `factors`, `weight_set`, `warnings` | `risk.assess(detection, event, profile)` |
| Decision | `action` list, `reason`, `command` (dry run), `rule_id`, `targets`, `skipped`, `warnings` | `policy.decide(risk, detection, event, profile)` |
| Incident | the database columns, see [pipeline.md](pipeline.md) | `db.IncidentDB.insert_incident` |

The decision and the action log are described in [action-log-format.md](action-log-format.md).

## Design rules

* **Simulation only.** Nothing in `src/` runs a real firewall command or opens a socket, and `dry_run: false` is rejected. A test checks that the source contains no `subprocess`.
* **Rules, not a model, choose actions.** The policy can only pick actions written in `config/policy.yaml`. Blocking and isolation need a confident, known attack and are never aimed at allow-listed addresses.
* **Every input is untrusted.** CSV fields, device files and config files are validated, length-limited and never copied into outputs unescaped.
* **One list of attack names.** The risk engine decides which names are known; the policy and the reports ask it.
* **The detector is replaceable.** Any function `detect(event, device_profile=None)` returning the Detection message can replace `detector.py` (for example an ML model).

## Package layout

| Module | Role |
|---|---|
| `detector.py` | Threshold rules with MITRE ATT&CK tags |
| `risk.py` | Weighted risk score, level and factor breakdown |
| `policy.py` | Ordered rules from the policy file, allow-list, safety checks |
| `actions.py` | Simulated actions, firewall commands in dry-run mode, action log |
| `db.py` | SQLite incident store with hash chain |
| `report.py` | Technical report, executive report, notification |
| `pipeline.py` | CSV in, incidents out; the `iot-ips` command |
| `scenarios.py` | Reference scenarios used by the tests and the weight comparison |
| `placeholders.py` | Threshold stand-in detector for tests |
| `paths.py` | Locations of config, data and examples |
