# Rule-based detector

## What it does
`detect(event, device_profile=None)` takes one network event (a dict) and returns:

```python
{"label": "ATTACK", "attack_type": "Brute Force", "confidence": 0.98, "mitre_technique": "T1110"}
```

It uses threshold rules instead of ML. The input and output match the shared contract, so next week the ML model only needs to provide the same `detect(event)` function.

## How it works
1. Load thresholds from `rules.yaml`.
2. Run every enabled rule on the event (features + context fields).
3. Each rule that fires returns a confidence value.
4. The rule with the highest confidence wins (ties go to the more severe rule: DoS > Brute Force > Port Scan > Unexpected).
5. If no rule fires, return `BENIGN`.

Confidence is `base_confidence` when the value just reaches the threshold and rises linearly to `max_confidence` at 3x the threshold. A stronger attack gives a higher confidence.

## The rules

| Rule | Fires when | Fields used | MITRE |
|---|---|---|---|
| DoS | (`Rate` >= 2000 pkt/s OR `syn_count` >= 100) AND `connection_attempts` >= 500 | features + context | T1498 |
| Brute Force | target port is 22/23/554 (or SSH/Telnet flag) AND `failed_attempts` >= 50. Plain connections do not count | context + features | T1110 |
| Port Scan | `unique_dst_ports` >= 20 OR `unique_dst_ips` >= 10 | context | T1046 |
| Unexpected Protocol/Port | **inbound** traffic whose `dst_port` or `protocol` is not in the device profile (0.60 for one mismatch, 0.75 for both) | context + profile | T1571 |

## Direction

Every event carries `direction`: `inbound` (towards the device) or `outbound` (from the device). Only inbound traffic is checked against the profile's ports, so the camera's own DNS, NTP and MQTT (8883) calls are not "unexpected" and the profile does not have to list every port the device uses to call out. If `direction` is missing or invalid it is derived from the device IP in the profile (source = device -> outbound, destination = device -> inbound); if that is not possible the event is treated as inbound, the cautious choice. Outbound traffic is therefore not judged by the profile at all: a compromised device calling a command-and-control server on an odd port is a known gap (see below).

## Configuration is validated

`detector_rules.yaml` is checked when it is loaded. A missing key, a misspelled key (`min_failed_atempts`), an unknown rule, a negative threshold or a confidence outside 0..1 raises `DetectorConfigError`, and the pipeline stops with `error: configuration problem: ...`. Before this check a typo silently disabled the rule, and 300 failed logins were reported as "Unexpected port".

## Assumptions
- CICIoT2023 has no "unique ports/destinations" column, so the port scan rule reads two extra context fields: `unique_dst_ports` and `unique_dst_ips`. They are now columns of `data/sample_events.csv`.
- The unexpected-traffic rule needs the device profile from `config/devices.json`. The pipeline looks the profile up by `device_id` and passes it in.

## Robustness
Missing fields, empty strings, NaN, inf and non-dict input never crash `detect()`; they fall back to BENIGN.

## Known limitations (evasion tests document these)
- **Slow scan**: a few ports over a long time stays under 20 unique ports and is missed.
- **Low-rate brute force**: under 50 failed attempts is missed.
- **Low-rate DoS**: under 2000 pkt/s and 100 SYN is missed.
- **A flood with few connections** is missed: DoS needs `connection_attempts` >= 500 as well as a high rate, so a fast video upload (high rate, 1-3 connections) is not an alarm. A single-stream UDP flood counted as one "connection" is missed the same way (sample event EVT-012). The flow engine must count packets or sessions per source for the connection field to be meaningful on live traffic.
- **Outbound traffic is not checked** against the device profile (a compromised device calling out on an odd port).
- **Attack on an allowed port and protocol** with low volume looks normal.
- Rules look at one event at a time with no memory across events, so attacks spread over many events are missed.

The ML model (next week) should cover these.

## Run
```
pip install -e ".[dev]"
python -m pytest tests/test_detector.py
```

## Calibration notes
- DoS also needs `min_connection_attempts` (500; 100 until the flow engine of `services/ips_cyber` was added: on live traffic 150 normal viewer sessions or a port scan reached 100 and were reported as DoS, 500 removes both while the 14 sample events still give the same 7 alerts): a high rate alone is what a fast clip upload looks like (Rate up to 3000 packets/s, 1-3 connections in the generated normal traffic). With this condition the generated normal traffic raises no DoS alert (see [calibration-report.md](calibration-report.md)); the price is the missed low-connection flood above.
- `min_rate` is 2000 pkt/s, not 1000: the benign sample event "camera uploads a clip" has Rate 1040 and was flagged as DoS at 1000. The value was chosen with the 14 sample events in view, so it is a calibration, not an independent test.
- The unexpected-protocol rule does not compare the event's transport (`TCP`, `UDP`) with the profile's application protocols (`RTSP`, `HTTPS`, `DNS`); that comparison flagged every normal event once the pipeline passed the device profile. A transport name is compared only if the profile lists transport names.

- DoS confidence is the weaker of the flood ratio and the connection ratio, so a flood that barely reaches the connection floor is not reported with high confidence.
