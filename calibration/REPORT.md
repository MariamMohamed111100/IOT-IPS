# Baseline and calibration on UNSW IoT traffic (Person 4, Task 7)

## 1. Data

- **Dataset:** UNSW IoT traffic traces (IEEE TMC 2018 testbed), https://iotanalytics.unsw.edu.au/iottraces.html
- **License:** MIT-0 (SPDX-License-Identifier: MIT-0), Copyright 2021 IoT Traffic Analytics Research Group, School of EE&T, UNSW Sydney. Free to use, modify and redistribute; no warranty.
- **Which days/files:** one day, `16-09-23` (file `16-09-23.tar.gz`, ~250 MB compressed; extracted to `data/real/16-09-23.pcap`). Role: **tune**.
- **Capture:** 947,072 packets, 369 MB, duration 86,397.7 s (23.999 h). Extracted camera traffic with tshark to `data/real/16-09-23_cams.pcap`: 377,658 packets, 78 MB, same duration.
- **Cameras present:** Netatmo Welcome (70:ee:50:18:34:43, 192.168.1.241), TP-Link Day Night Cloud camera (f4:f2:6d:93:51:f1, 192.168.1.143), Samsung SmartCam (00:16:6c:ab:6b:88, 192.168.1.249), Dropcam (30:8c:fb:2f:e4:b2, 192.168.1.106). Nest Dropcam (30:8c:fb:b6:ea:45) did **not** appear that day and is not included. Gateway 14:cc:20:51:33:ea (192.168.1.1).
- **Benign-only assumption:** the traffic-traces page lists 20 daily traces of a mixed set of consumer IoT devices from the testbed; attack traces are published separately on the "Attack Traces" page (ACM SOSR 2019). These daily traces are treated as benign testbed traffic. The page does not state "benign" explicitly for this page, so this is an assumption, not a guarantee. **Verified: not verified** (no labels for 16-09-23).
- **IPs/expected ports derived:** most frequent IP per camera MAC from `eth.src`. Expected ports/protocols derived from the camera's actual traffic (top outbound destination ports plus the inbound listening port observed for Samsung, 49152). Full derivation notes are in `calibration/port_derivation.txt`. Device profile copy: `calibration/devices_unsw_16-09-23.json`. `ips/config/devices.json` was not edited.
- **Filtering:** `tshark -Y "eth.addr==<camera MACs>"`. No PCAPs are committed (see .gitignore).

## 2. Method

- Sensor run from `services/ips_cyber`: `python main.py --source pcap --file ... --devices ... --detector ... --publisher file --out ...`, with a calibration config (`calibration/config_unsw.yaml`) that raises `max_capture_seconds` to 100000 so the full 24 h capture replays (default cap is 6 h).
- Three modes per PCAP:
  - A: `--detector rules`
  - B: `--detector combined` (rules + ML on flow events)
  - C: `--detector combined --ml-windows` (also 10-packet ML windows, gated 3-in-30 s)
- **Modes A and B are identical on PCAP input:** mode B without `--ml-windows` does not run the ML window path, so only rules fire. ML only participates in mode C.
- Alerts counted from the JSONL output: total, per type, per device, per detector (rules/ml). Hours = capture duration (23.999 h), not wall clock.
- Traffic is assumed benign, so every alert is a false alarm. Zero-alert upper bound: if 0 alerts over N hours, 95% upper bound ~3/N per hour.

## 3. Results (tune day 16-09-23 only)

### Before tuning

| Mode | Alerts | Alerts/h | By type | By detector |
|---|---|---|---|---|
| A rules | 15 | 0.625 | unexpected_traffic 13, port_scan 2 | rules 15 |
| B combined | 15 | 0.625 | unexpected_traffic 13, port_scan 2 | rules 15 |
| C combined+ml-windows | 2693 | 112.21 | unexpected_traffic 2677, port_scan 16 | rules 1544, ml 1149 |

### After tuning (A and B re-run; C not re-run after tuning)

| Mode | Alerts | Alerts/h | 95% upper bound if 0 |
|---|---|---|---|
| A rules | 0 | 0.000 | 0.125/h (3/24) |
| B combined | 0 | 0.000 | 0.125/h (3/24) |

Mode C baseline (before tuning) remains 2693 alerts/h-heavy because of unsolicited reply misclassification in the 10-packet windows; the flow-engine and live.py fixes were applied after that run. A re-run of mode C is pending and will be added when complete.

## 4. Changes (calibration/changes.csv)

| Parameter | File | Old | New | Reason (plain words) | Alerts/h before | Alerts/h after | Effect on attack detection |
|---|---|---|---|---|---|---|---|
| Flow reply classification | services/ips_cyber/ips_cyber/flow_engine.py | every flow with the device as destination counted as inbound | stateful: reply only if device sent to same remote ip:port earlier; SYN from remote stays inbound; unsolicited floods stay inbound | 13 of the 15 alerts were replies to connections the camera opened (cloud on 443/53/67 to ephemeral device ports); the capture starts mid-flow so orientation was wrong | 0.5417 | 0.0000 | Attacks unchanged: `evaluate.py` still 7/10; unsolicited reflection floods stay inbound and detectable (unit tests) |
| min_unique_destinations | ips/config/detector_rules.yaml | 10 | 15 | The camera legitimately talks to ~11 cloud endpoints inside one 60 s window, so 10 flagged it as a port scan | 0.0833 | 0.0000 | `evaluate.py` still detects EVT-005 (port scan) and 7/10 attacks; only IP-count scans with 10-14 unique IPs are no longer flagged |
| ML window orientation | services/ml/ids_ml/live.py | whoever speaks first decides inbound/outbound | stateful reply: a window starting with the remote is a reply only if the device sent to that remote service port earlier; unsolicited floods stay inbound | Mode C rules alerts on the 2 h slice were replies misclassified as inbound (2 rules alerts on slice) | n/a | n/a | unit tests `test_reply_window_becomes_outbound_with_state` and `test_unsolicited_inbound_window_stays_inbound` pass |
| ml-min-confidence | services/ips_cyber/ips_cyber/service.py (default) | 0.90 | 0.98 | ML flagged 1149 windows on 24 h of presumed-benign traffic at 0.90; raising to 0.98 cut the 2 h slice from 126 to 2 ML alerts | 63.0 | 1.0 (2 h slice) | sample_events combined alerts 9 -> 8 (one attack no longer caught by ML); ML still enabled |
| ml-confirm | services/ips_cyber/ips_cyber/service.py (default) | 3 | 5 (trial only, not applied) | Larger confirm count reduced 2 h slice from 128 to 87 alerts | 64.0 | 43.5 (2 h slice) | not measured on attacks; not adopted because confidence 0.98 is more effective |
| ml-gate-per-device | services/ips_cyber/ips_cyber/service.py (trial) | per (device, remote, type) | per (device, type) | Aggregating the gate per device was tested | 64.0 | 64.5 (2 h slice) | no benefit; not adopted |

No risk weights were changed: with the detector fixed there were no false alarms left on this traffic to tune weights against, and weights decide how an attack ranks, not whether an alarm is false (see ips/docs/calibration-report.md section G).

## 5. Attack detection check after tuning

- `cd ips && python scripts/evaluate.py`: 14/14 events behaved as expected; 7/10 attacks detected; 0 false alarms on 4 benign events; precision 1.00, recall 0.70, F1 0.82. Same result on origin/main (7/10) and on this branch (7/10).
- `python -m pytest services/ips_cyber ips`: 452 passed, 1 failed. The single failure is `ips/tests/test_lab_e2e_logic.py::test_attack_refuses_targets_outside_the_lab`, which needs `bash` + `nmap` (not available on this Windows host); it is pre-existing and unrelated to these changes. Flow-engine tests: 29 passed. ML window tests: 10 passed.
- `ruff check .`: passed.
- `make lab-e2e`: not run successfully. Docker client is installed but the lab stack did not start within the available time (compose up timed out; no containers running). `scripts/ips/ips_e2e.py` could not connect to the API.

## 6. Limits

- Public dataset from a different network, 2016 devices, not our camera. Numbers apply only to this captured traffic.
- Benign-only assumption is unverified for this specific day; the page does not label the daily traces "benign" explicitly.
- After-tuning 0 alerts over 24 h gives a 95% upper bound of ~0.125/h, not a measured rate. A holdout PCAP is required before any final claim.
- Thresholds must be re-calibrated on real captured home traffic before any claim about real homes.