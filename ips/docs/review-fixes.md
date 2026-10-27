# Review fixes: what changed, what is still open

The deeper review found six problems. This is how each was handled in this repository, with the tests that now guard it.

| # | Problem | Fix | Where | Tests |
|---|---|---|---|---|
| 1 | Normal camera viewing (150 connections to port 554, 0 failed logins) was a Brute Force at 0.84 | Brute force counts `failed_attempts` only | `detector.py`, `detector_rules.yaml` | `test_many_plain_connections_to_rtsp_are_not_brute_force`, `test_brute_force_counts_failed_attempts_only` |
| 2 | A misspelled key in `rules.yaml` silently disabled a rule (300 failed logins became "Unexpected port") | The file is validated when loaded: missing, unknown or out-of-range keys raise `DetectorConfigError`; the pipeline stops with `configuration problem` | `detector.py` (`validate_config`), `pipeline.py` | `test_misspelled_threshold_key_raises_...`, `test_bad_rules_files_are_refused` (14 cases), `TestLoudConfigurationErrors` |
| 3 | The contract had no direction: outbound camera traffic (8883, 123) was "unexpected" | `direction` (inbound/outbound) is part of the event; the unexpected-port rule judges inbound traffic only; a missing value is derived from the device IP, else treated as inbound | `detector.py`, `data/sample_events.csv`, `baseline.py`, `docs/` | `test_outbound_traffic_is_not_unexpected`, `test_unknown_direction_is_treated_as_inbound`, `test_outbound_dns_and_ntp_need_no_entry_in_the_profile` |
| 4 | Every stored report said "(see risk factors)" after the source IP | The label comes from the risk engine's `source_trust` detail through a fixed word list (external, internal not a known device, trusted internal device); free text can never reach it | `report.py` (`source_kind`) | `TestReportsFromThePipeline` |
| 5 | Each event was its own incident | Same device + source + attack within 5 minutes (`--group-window`) is one incident with `event_count`, `first_seen`, `last_seen`; schema version 2 | `pipeline.py`, `db.py`, `report.py` | `TestGrouping`, `TestGroupedIncidentsAndActionResult` |
| 6 | The pipeline ran the actions before saving the incident | Save first, then act; no action if the incident could not be saved; the outcome is written to `action_result` afterwards | `pipeline.py`, `db.py` | `TestSaveBeforeAct` |

Also done: DoS needs a high connection count as well as a high rate (removes the false alarms on fast uploads); the MITRE tag of unexpected traffic is T1571 in the reports too (was T1071); the CI fails if the demo uses the placeholder detector, and checks that no stored incident still has planned actions; the sample reports, the demo database and the calibration report were rebuilt; `requirements.txt` added.

## Numbers that changed

* Sample events: 7 of 10 attacks detected (was 8). `EVT-012` (a fake camera upload at 4,367 packets/s with 3 connections) is no longer a DoS. 0 false alarms on the 4 benign events.
* Incidents on the sample events: 6 with the default grouping (Medium 2, High 1, Critical 3); 7 with `--group-window 0`.
* Generated normal camera traffic (120 hours): 0 alerts (was 374 a day with the first profile and 1 a day after the profile fix). The zero is partly by construction, see `docs/calibration-report.md`.
* Tests: all pass on Python 3.11 and 3.13 (syntax checked for 3.10; CI runs 3.10 and 3.12).

## Still open (not done here)

* **Person 2:** a capture-aware train/test split and a separate hold-out file need the CICIoT2023 files, which are not in this repository. The Python version is stated once: the pipeline needs 3.10, only `scripts/data` needs 3.11 (`data/README.md`); the exact data pins still have to be checked on 3.10 and 3.11 by whoever has the dataset.
* **Person 1:** the Word/PDF design document and the task plan are outside the repository. They still have to be updated: the `direction` field in the contract, the new test counts, grouping and save-before-act in the pipeline description, and the weakened DoS rule in the threat model (a flood with few connections is missed).
* **Person 7:** the sample reports are rebuilt from the pipeline, but the wording of the "Source IP" label and the grouped-incident row should be reviewed by the report owner.
* **Live use:** `connection_attempts` and `direction` must come from the flow engine on real traffic; grouping must update an open incident instead of working on a whole file; none of this has been run against recorded lab traffic.
