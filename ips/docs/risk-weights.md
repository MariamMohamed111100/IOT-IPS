# Risk engine: weight-set comparison

## What was compared

`config/risk_weights.yaml` holds three weight sets. Each sums to 1; the score is the weighted average of the factors (each 0–100), so it stays between 0 and 100.

| Factor | balanced | device_centric | severity_centric |
|---|---|---|---|
| Detection confidence | 0.20 | 0.15 | 0.25 |
| Attack severity | 0.25 | 0.20 | 0.35 |
| Device criticality | 0.20 | 0.30 | 0.10 |
| Persistence (attempt count) | 0.15 | 0.15 | 0.15 |
| Source trust | 0.10 | 0.10 | 0.05 |
| Behavioral deviation (optional) | 0.05 | 0.05 | 0.05 |
| Potential impact (optional) | 0.05 | 0.05 | 0.05 |

## How they were compared

`scripts/compare_weights.py` scores 10 reference scenarios from `iot_ips/scenarios.py` (device profiles: camera = high, smart bulb = low, temperature sensor = medium, industrial sensor = critical). Each scenario has an expected level that a human wrote from the story ("weak scan of a bulb from a trusted PC = Low"). Run it with `python scripts/compare_weights.py`.

| Scenario | Story | Expected | balanced | device_centric | severity_centric |
|---|---|---|---|---|---|
| L1 | weak scan of a bulb, trusted source | Low | 28 Low | 26 Low | 29 Low |
| L2 | very weak recon of a bulb, trusted source | Low | 24 Low | 23 Low | 25 Low |
| M1 | scan of the camera, unknown LAN device, odd port | Medium | 57 Medium | 59 Medium | 52 Medium |
| M2 | light brute force on a bulb, unknown LAN device | Medium | 57 Medium | 53 Medium | 62 High ✗ |
| H1 | brute force on the camera from the internet | High | 77 High | 77 High | 76 High |
| H2 | DoS on a temperature sensor from the internet | High | 71 High | 68 High | 74 High |
| C1 | 431 failed logins on the camera, 94% (PDF example) | Critical | 81 Critical | 80 Critical | 82 Critical |
| C2 | Mirai on an industrial sensor, internet | Critical | 97 Critical | 97 Critical | 97 Critical |
| C3 | device takeover on the camera, internet | Critical | 88 Critical | 86 Critical | 90 Critical |
| B1 | benign verdict | Low | 0 Low | 0 Low | 0 Low |

| Measure | balanced | device_centric | severity_centric |
|---|---|---|---|
| Levels matched | 10 / 10 | 10 / 10 | 9 / 10 |
| Gap between levels (lowest score of the higher level minus highest score of the lower level): Low→Medium | +29 | +27 | +23 |
| Medium→High | +14 | +9 | +12 |
| High→Critical | +4 | +3 | +6 |
| Camera minus bulb, same attack (device awareness) | +10 | +15 | +5 |

## Decision: `balanced`

* `severity_centric` mislabels M2 (a light brute force on a smart bulb comes out High). It gives the device too little weight, so it barely separates a bulb from a camera (+5 points).
* `device_centric` separates devices best (+15) but its margins are the thinnest: Medium→High only +9, High→Critical +3, and C1 lands exactly on the Critical line (80). Small changes in input would flip levels.
* `balanced` matches every scenario, has the widest margins at Low→Medium and Medium→High, and still separates devices clearly (+10). It is the best compromise, so it is `active_weight_set`.

## Honest limits of this comparison

* **The scenarios were adjusted while the engine was being designed.** A few cases (L1, M1, M2, H1) were tuned so the stories stay plausible, so "10 / 10" is a calibration result, not independent proof. Re-run the comparison on those events with expected levels written *before* looking at the output.
* There are only 10 scenarios, so the numbers show the sets' *trade-offs*, not their accuracy.
* The High→Critical gap is small (+4) for every set. Scores near 80 are borderline by nature; the policy engine should also look at confidence (as the PDF's rule does) rather than at the level alone.
* The maximum score is 99, not 100, when the source is outside the network, because "external" counts as 90, not 100.

## Decisions worth knowing

* **Persistence uses a log scale**: 1 attempt ≈ 12, 10 ≈ 42, 100 ≈ 81, 300 or more = 100. A linear scale would score 10 failed logins as almost nothing.
* **Source trust can only nudge the score.** A source IP can be spoofed, so its weight is capped at 0.15 in the config validation. An attacker who fakes a trusted IP lowers the score by about 7 points at most (tested).
* **Missing or invalid data uses cautious defaults** (unknown attack = 60, missing device profile = treated as important, missing source IP = external) and is listed in `warnings`. A benign verdict scores 0.
* **Optional factors** (behavioral deviation, potential impact) are skipped when they cannot be computed, and the other weights are re-scaled. Deviation only looks at whether `dst_port` is in the device's `expected_ports`, because the profile's protocol names (RTSP, HTTPS) do not match an event's transport protocol (TCP).

## Score on the backend's scale

The levels above (30/60/80) are the internal ones. The backend uses 0/31/61/91, so `risk.to_backend_score()` translates a score before it is published, using `backend_scale` in `config/risk_weights.yaml`. Every internal level stays the same level on the backend. Decisions are made on the internal score. Why and what the alternative would cost: [calibration-report.md](calibration-report.md).
