# Integration checklist (status after the integration release)

> Written for the earlier layout with one folder per person. Today: `python -m pytest` (in `ips/`) runs the tests and `python scripts/evaluate.py` checks the 14 events; `Person 1..7` folders are now `src/iot_ips`, `config`, `data`, `docs`, `tests`.

Every item below was checked by running the code. `python run_tests.py` (in `Person 6`) runs 288 tests and `python evaluate.py` (in this folder) checks all 14 events.

| # | Person | Item | Status |
|---|---|---|---|
| 1 | 2 | `sample_events.csv` in Person 2's folder is now the integrated version (adds `direction`, `unique_dst_ports`, `unique_dst_ips`); `check_data.py` reports 32/32 | done |
| 2 | 3 | Brute force counts failed logins only. Normal viewing of the camera stream (port 554, many connections, no failed logins) is no longer an alert | done, tested |
| 3 | 3 | DoS also needs many connections when the event carries the count. The benign cloud upload (EVT-002) and the ARP-spoofing event (EVT-012) no longer fire the DoS rule | done, tested |
| 4 | 3 | `rules.yaml` is validated on load. A misspelled or missing key stops the run with a clear message (before, it silently switched the rule off) | done, tested |
| 5 | 3 | `test_detector.py` is now unittest (35 tests) and is counted by `run_tests.py` | done |
| 6 | 3 / 1 | New `direction` field (`inbound` / `outbound`) and `expected_outbound_ports` in the device profiles, so normal outbound traffic (cloud, DNS, NTP) is not "unexpected" | done, tested |
| 7 | 3 / 7 | MITRE tag for unexpected traffic is T1571 in both modules. The report now uses the detector's own tag as the source of truth | done, tested |
| 8 | 6 | `detect(event, profile)`: the profile is passed, so the unexpected port/protocol rule runs | done, tested |
| 9 | 6 | Tests no longer depend on which detector is installed (`--placeholders detector`); 57 tests pass | done |
| 10 | 6 | `run_demo.py` uses this folder's events and devices and the real modules. It refuses to run on placeholders (`--require-real`) | done |
| 11 | 6 | Option `--dedup-window` groups repeats of one attack into one incident (off by default) | done, tested |
| 12 | 6 | `rules.yaml` problems are reported when the run starts | done, tested |
| 13 | 7 | Source labels in the reports come from the risk engine (external / unknown internal / trusted internal host) instead of "see risk factors" | done, tested |
| 14 | 7 | Missing score no longer crashes the report; action wording says decided / simulated | done before this release |
| 15 | 7 | Scripts accept both `devices.json` formats; sample reports regenerated | done |
| 16 | 4, 5 | No code change needed | unchanged |

## Still open (decisions and next steps, not bugs)
- **Isolating the victim device.** For a Critical brute force the policy blocks the source and also isolates the camera, which cuts your own camera off. Consider isolating only when there is evidence the device itself is compromised (for example an outbound flood such as EVT-014). This is a policy decision for the team; `policy.yaml` was not changed.
- **The PDF itself** was not regenerated. Apply `Design_Document_Addendum.md` to it.
- **ML model** (next week): it must expose `detect(event, device_profile)` and return the same four keys. Train with a capture-aware split or a separate hold-out file; random-row metrics on CICIoT2023 are optimistic.
- **Real traffic:** thresholds are starting values; calibrate them on the real camera before enabling real blocking. Blocking by IP can be tricked by spoofed addresses on a LAN.
