# Calibration report: false alarms on normal traffic

Task 7 (Person 4). Question: how many false alarms does a healthy camera cause, and are the thresholds and risk weights in the right place?

Reproduce every number below with `python scripts/calibrate.py` (5 seeds x 24 h, about 5 seconds).

## Summary

* **The first real problem was not a threshold but the contract.** The camera's DNS lookups (53) and clock sync (123) raised an "Unexpected Protocol/Port" alert every time: **374 alerts a day**, all Medium, each one an incident and an admin notification. The first fix was to add ports 53 and 123 to the camera profile. That fixed the symptom, not the cause: the camera also calls its cloud on MQTT/TLS (8883) and anything else outbound, and the event had no direction. **The contract now has a `direction` field and the unexpected-port rule judges inbound traffic only.** With it the old profile (554 and 443 only) raises 0 alerts on the generated traffic, and so does the current one.
* **The remaining alert was a DoS alert on a fast clip upload** (Rate 2,400-3,000 packets/s, about 1 a day, High, admin notified, never blocked because the policy refuses to block the camera itself). It came from a rate with no other sign. **DoS now needs many connections as well as a high rate** (100 at first, 500 since the live flow engine showed 100 is reached by 150 normal viewer sessions); an upload has 1-3. On the generated traffic the false DoS alerts fall from 1.0 a day to 0.0, even with a three times heavier Rate tail.
* **Brute force now counts failed logins only.** 150 plain connections to the camera's RTSP port (live viewing, 0 failed logins) used to be a Brute Force alert at 0.84 confidence and score 68 (High).
* **No weight was changed.** The weight sets cannot separate a false alarm from an attack that looks the same (section G), and with the detector fixed there are no false alarms left on the generated traffic to tune against.
* **Risk scale:** a translation to the backend's 0/31/61/91 levels is implemented (`risk.to_backend_score`). It keeps every level the same on both scales. The team still has to confirm the choice (see below).
* **The price:** a flood that arrives as one stream (few counted connections) is no longer a DoS. Sample event EVT-012 (a fake camera upload at 4,367 packets/s with 3 connections) was an alert before and is now a miss. Real attacks that keep their volume (EVT-010, 011, 014: 9,000-25,000 connections) are still caught.

## Method and limits

`src/iot_ips/baseline.py` generates a day of normal traffic for CAM-001: the Pi pulls the video all day, owners watch live view (mostly evenings), the camera uploads clips after motion (mostly by day), plus DNS every 5 minutes, NTP every 17 minutes, a cloud heartbeat every 10 minutes, and rare password typos. Every event has a `direction` (from the camera: outbound; to it: inbound). Each event goes through the real `detect`, `risk.assess` and `policy.decide`, exactly as the pipeline calls them (nothing is stored or executed). Run: 5 seeds x 24 h = 120 hours, 10,971 events, about 91 per hour.

What this does and does not tell us:

* **"0 alerts" is partly by construction.** The generator gives normal traffic 1-4 connections per event, so a rule that needs 500 connections cannot fire on it. Whether real normal traffic stays under 500 connections per event depends on how the flow engine counts them. Treat the zero as "the rules no longer fire on a rate alone", not as a measured false-alarm rate.
* **Real data is thin.** CICIoT2023 gives only 4 benign rows with all the fields the detector reads (Rate 31, 61, 73 and 1,040 packets/s). The generator puts its medians near those rows; the spread of Rate is a guess (section F shows what happens when it is wrong).
* **Only the camera is simulated.** The other five profiles were not baselined.
* **The attack side is the same 14 sample events** that the thresholds were first tuned on, so "attacks caught" below checks that we did not break anything; it is not a measure of accuracy.
* Replace the generated traffic with recorded benign lab traffic as soon as Task 8 can produce it: `python scripts/calibrate.py --events lab_benign.csv --hours 3`.

## Results

### A. Camera profile with only ports 554 and 443

120 hours: **0 alerts**. Before the `direction` field the same profile gave 1,869 alerts = 374 a day (DNS 1,442, NTP 422, all Medium, plus 5 DoS alerts on uploads).

### B. Current profile (ports 554, 443, 53, 123)

120 hours: **0 alerts**; 0 blocked, 0 admin notifications. 120 of 120 clock-hours were quiet.

### C. Headroom: how close normal traffic comes to each threshold

| Rule | Feature | Threshold | Highest generated normal value | Highest of the 4 real normal rows | Weakest sample attack that reaches it |
|---|---|---|---|---|---|
| DoS | Rate | 2000 | 3030 (152%) | 1040 (52%) | 2560 (128%) |
| DoS | syn_count | 100 | 4 (4%) | 0 | none reaches it |
| DoS | connection_attempts | 100 | 4 (4%) | 2 (2%) | 9000 (9000%) |
| Brute Force | failed_attempts | 50 | 3 (6%) | 1 | 300 (600%) |
| Port Scan | unique_dst_ports | 20 | 1 (5%) | 1 | 1000 (5000%) |
| Port Scan | unique_dst_ips | 10 | 2 (20%) | 1 | none reaches it |

The Rate alone would still fire on normal uploads (152% of the threshold); the connection condition is what keeps it quiet. Brute force, port scan and the connection count have a wide gap between normal and attack.

### D. DoS Rate threshold sweep (with the connection condition)

| min_rate | False DoS alerts per day | Sample attacks caught (any rule) | Alerted as DoS (EVT-) | Benign sample rows flagged |
|---|---|---|---|---|
| 1000 | 0.0 | 7/10 | 010, 011, 014 | none |
| 1500 | 0.0 | 7/10 | 010, 011, 014 | none |
| 2000 (current) | 0.0 | 7/10 | 010, 011, 014 | none |
| 2500 | 0.0 | 7/10 | 010, 011, 014 | none |
| 3000 | 0.0 | 6/10 | 010, 011 | none |
| 4000 | 0.0 | 6/10 | 010, 011 | none |

The Rate threshold no longer decides the false-alarm rate, so it can stay at 2000 (3000 would lose EVT-014).

### E. Direction check

| Traffic | Direction | Port | Old behaviour | Now |
|---|---|---|---|---|
| camera DNS lookup | outbound | 53 | Unexpected port (Medium) | normal |
| camera clock sync | outbound | 123 | Unexpected port (Medium) | normal |
| camera to cloud MQTT/TLS | outbound | 8883 | Unexpected port (Medium) | normal |
| someone connecting to the camera | inbound | 4444 | Unexpected port | Unexpected port |
| 150 connections to RTSP, 0 failed logins | inbound | 554 | Brute Force 0.84 (High) | normal |

### F. What if normal Rate has a heavier tail than assumed

| Spread | Alerts per day | Blocking per day | Admin notified per day | Highest normal Rate |
|---|---|---|---|---|
| x0.5 | 0.0 | 0.0 | 0.0 | 1,030 |
| x1 (assumed) | 0.0 | 0.0 | 0.0 | 3,030 |
| x1.5 | 0.0 | 0.0 | 0.0 | 8,916 |
| x2 | 0.0 | 0.0 | 0.0 | 26,233 |
| x3 | 0.0 | 0.0 | 0.0 | 227,115 |

Before the connection condition: 1.0, 6.2, 13.4 and 32.6 alerts a day at x1, x1.5, x2 and x3, and at x3 a family phone could reach a temporary block.

### G. Do the weights separate false alarms from attacks?

With no false alarms left on the generated traffic there is nothing to separate in this run. Before the detector fix the three weight sets gave the same levels on the false alarms (score ranges 50-68, 53-67 and 46-69) and the false DoS alarms (61-67) overlapped with real attacks (EVT-012 at 65, EVT-005 at 67): the weights decide how an attack ranks, not whether a detector alarm is false. Scores of the sample alerts now:

| Alert | Rule | Confidence | Score | Level |
|---|---|---|---|---|
| sample EVT-006 | Unexpected Protocol/Port | 0.60 | 56 | Medium |
| sample EVT-009 | Unexpected Protocol/Port | 0.60 | 57 | Medium |
| sample EVT-005 | Port Scan | 0.97 | 67 | High |
| sample EVT-014 | DoS | 0.83 | 80 | Critical |
| sample EVT-010 | DoS | 0.99 | 81 | Critical |
| sample EVT-008 | Brute Force | 0.98 | 85 | Critical |
| sample EVT-011 | DoS | 0.99 | 86 | Critical |

## Decisions and reasons

| Setting | Before | After | Why |
|---|---|---|---|
| Event contract | no direction | `direction` = inbound / outbound | A device's outbound traffic (cloud, DNS, NTP, MQTT) cannot be judged by the ports it listens on. Port lists per device would never be complete. |
| `CAM-001` expected ports and protocols | 554, 443 / RTSP, HTTPS, DNS | 554, 443, 53, 123 / + NTP | Kept: they are legitimate. Trade-off: inbound traffic on 53 or 123 is now "expected" for the camera. |
| `dos` | rate OR syn count | (rate OR syn count) AND `min_connection_attempts` 500 | A high rate alone is what a fast upload looks like. Cost: a few-connection flood is missed (EVT-012). |
| `brute_force` | `failed_attempts` 50 OR `connection_attempts` 100 | `failed_attempts` 50 | Live viewing opens many connections and no failed logins. |
| `dos.min_rate` | 2000 | 2000 (kept) | The valid range is set by two real rows: normal 1,040 and the weakest flood 2,560 (EVT-014). |
| `port_scan` 20 / 10 | as is | as is | Normal traffic stays under 20% of each. Slow attacks need a time window, not a lower count. |
| Weight sets, `levels` | balanced; 30/60/80 | unchanged | The weights decide how an attack ranks, not whether an alarm is false. |

## Risk scale: ours (0/30/60/80) or the backend's (0/31/61/91)?

The backend reads a level from the score with its own limits, so publishing our score as it is would show an 81 (Critical for us) as High.

Option 1, **use the backend's limits inside our system**: our strongest sample attacks score 80-86, so with `critical: 91` none would be Critical; all 4 Critical sample incidents become High, they lose `block_source`/`isolate_device` (`min_score: 80` in `policy.yaml` would also have to change). To get Critical back the weights would have to be re-tuned on the same 14 events.

Option 2, **keep our scale and translate when publishing** (implemented, recommended): `risk.to_backend_score(score)` maps 0-29 to 0-30, 30-59 to 31-60, 60-79 to 61-89, and 80-100 to 91-100 (it never goes down, 0 stays 0 and 100 stays 100). A test checks all 101 scores: every internal level is the same level on the backend. Our decisions, policy and database keep using the internal score.

| Sample | Internal score / level | Published score / backend level |
|---|---|---|
| EVT-006 | 56 Medium | 57 Medium |
| EVT-005 | 67 High | 71 High |
| EVT-014 | 80 Critical | 91 Critical |
| EVT-010 | 81 Critical | 91 Critical |
| EVT-011 | 86 Critical | 93 Critical |

What is needed from the others: Person 1 confirms the choice in the contract (Task 1). Person 6 calls `to_backend_score` when the engine publishes `security/risk` and puts the internal score in `details`. If the team prefers Option 1, change `levels` and `backend_scale` in `config/risk_weights.yaml` and `min_score` in `config/policy.yaml`, then re-run `python scripts/compare_weights.py`.

Note that EVT-014 (a Mirai flood) scores exactly 80, the Critical limit. A small change in one weight tips it to High.

## Recommendations for the others

* **Person 3:** done in this version: DoS now needs a high connection count as well as a high rate, and brute force counts only failed logins. What is left is to make `connection_attempts` mean something on live traffic: define it in the flow engine (sessions or packets per source in the window) and re-run this calibration on recorded lab traffic.
* **Person 1 (devices.json, Task 1):** `config/devices.json` is the version with the camera fix. The copies in the Person 1 folders list `TCP`/`UDP` as protocols and the old ports; please take this one. The `direction` field makes the DNS/NTP ports optional for outbound traffic, but keep them listed: they are legitimate. Baseline the other five devices in the lab.
* **Person 5:** the policy refused to block the camera itself in every false DoS alert. Keep `source_is_device`. Add the cloud and DNS servers the devices depend on to the allow-list when known.
* **Person 6/8:** record 24 hours of real benign traffic from the lab camera and run `python scripts/calibrate.py --events <file> --hours 24`. Then repeat the DoS sweep with real Rate values.
