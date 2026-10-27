# IPS integration (contract v1.2)

How the IoT-IPS (detector, risk engine, policy, pipeline, reports) plugs into SmartSecure Home without a new topic or a new service. Written before any code, so every owner builds against the same text. The rules themselves are in `docs/CONTRACT.md` (sections 3, 3.1, 4.4, 7.1, 11, 12); this file holds the decision, the mapping tables and the work list.

## 1. Data flow

```
IPS pipeline (CSV / live flows)
  detect -> assess -> decide -> actions -> report
        |
   IPS adapter  (runs with the cyber service identity)
        |  cyber.port_scan | cyber.brute_force | cyber.dos | cyber.unexpected_traffic
        |  cyber.block_applied | cyber.block_refused
        v
   security/alerts/cyber  ->  engine (points per type, incident, responses)  ->  security/incidents (+ details)
                          ->  api (stores events, incidents, details)  ->  dashboard
```

No new topic and no ACL change: the adapter publishes on `security/alerts/cyber` and every event keeps zone `network` (CONTRACT 12). The IPS keeps deciding its own actions in dry-run mode; real blocking later goes through the existing `system/block` channel.

## 2. Decision: one level scale

The backend uses `0/31/61/91`; the IPS uses `0/30/60/80`. **Decision: the published scale is the backend's `0/31/61/91`.** The IPS keeps its internal scale and converts at the boundary (section 5), so an IPS Critical stays Critical.

| Option | Effect | Verdict |
|---|---|---|
| Backend moves to 0/30/60/80 | `door.open`, `lock.login_failed` and `cyber.rogue_device` (30 points each) become Medium and open an incident every time; `gas.detected` (80) reaches Critical; engine tests and demo text (85 = High) change | rejected |
| IPS moves to 0/31/61/91 | the highest possible score for the camera is 94, so Critical (91+) is almost unreachable and `critical_certain` (isolation) rarely fires; the tests and weight analysis of the IPS modules change | rejected |
| One published scale + conversion | nothing in either system changes; level names always agree | **chosen** |

## 3. Event mapping (IPS to contract)

| IPS attack type | Contract event type | Points |
|---|---|---|
| Port Scan | `cyber.port_scan` (existing) | 25 |
| Brute Force | `cyber.brute_force` (existing) | 35 |
| DoS | `cyber.dos` (new) | 40 |
| Unexpected Protocol/Port | `cyber.unexpected_traffic` (new) | 30 |
| BENIGN | nothing is published | - |

The order of the points follows the IPS attack-severity order (port scan, unexpected traffic, brute force, DoS); the engine points are 25, 30, 35 and 40.

| IPS field | Contract field (`data`) | Conversion |
|---|---|---|
| `src_ip`, `dst_ip`, `dst_port`, `direction`, `confidence`, `mitre_technique`, `failed_attempts`, `connection_attempts` | same name | none |
| `protocol` | `protocol` | capitals (`TCP`, `UDP`, `ICMP`, `GRE`) |
| `device_id` | `device_id` | backend id (section 4) |
| `duration` (text such as "4 minutes") | `duration` | number of seconds; 0 when missing |
| `unique_dst_ports`, `unique_dst_ips` | `port_count`, `hosts_probed` | port scan only |
| IPS level | `severity_hint` | lowercase |
| technical and executive report | `details.reports.technical`, `details.reports.executive` | text, 12 KB each at most |

Extra fields of the reused types: `cyber.port_scan` sends `ports: []` (the IPS counts ports, it does not list them) and `port_count`, `hosts_probed`. `cyber.brute_force` sends `target` (22 is `ssh`, 23 `telnet`, 554 `rtsp`, any other port its number as text), `attempts` = `failed_attempts` and `window_s` = `duration`.

Block results: an action-log record with status `simulated` becomes `cyber.block_applied` with `dry_run: true`; status `skipped` or `refused` becomes `cyber.block_refused` with the log note as `reason` (for example `source_allow_listed`, `source_is_device`, `already_blocked`). The address goes in `ip`, so these events are never scored or re-blocked.

## 4. Device mapping

**Id rule:** lowercase the IPS id and replace `-` with `_`. The result matches `[a-z0-9_]+` and collides with no simulated device.

**Type rule** (`device_type` is the topic token `home/<zone>/<device_type>/<device_id>/event`):

| IPS `device_type` | Backend type | Note |
|---|---|---|
| surveillance_camera | `camera` | existing |
| temperature_sensor | `temperature` | existing |
| thermostat | `temperature` | the backend has no thermostat type |
| smart_bulb | `bulb` | existing |
| smart_plug | `plug` | new type, no commands |
| industrial_sensor | `industrial_sensor` | new type, no commands |

**Devices** (the file is `config/ips_devices.json`, copied from the IPS `devices.json`; the zones come from `config/zones.yaml`):

| IPS id | Backend id | Backend type | Zone | IP |
|---|---|---|---|---|
| CAM-001 | `cam_001` | camera | entrance | 192.168.1.50 |
| THERMO-001 | `thermo_001` | temperature | living_room | 192.168.1.51 |
| PLUG-001 | `plug_001` | plug | living_room | 192.168.1.52 |
| TEMP-001 | `temp_001` | temperature | kitchen | 192.168.1.70 |
| BULB-001 | `bulb_001` | bulb | bedroom | 192.168.1.60 |
| IND-001 | `ind_001` | industrial_sensor | garage | 192.168.1.80 |

The zone is where the device sits; the IPS events still use zone `network`. The API shows the device's zone through `device_id`. `plug` and `industrial_sensor` accept no commands, because `ALLOWED_ACTIONS` in the API lists only bulb, siren, lock and valve.

## 5. IPS score conversion

```python
BANDS = [(0, 29, 0, 30), (30, 59, 31, 60), (60, 79, 61, 90), (80, 100, 91, 100)]   # IPS band -> published band

def to_published(ips_score):
    s = max(0.0, min(100.0, float(ips_score)))
    for lo, hi, out_lo, out_hi in BANDS:
        if s <= hi or hi == 100:
            return int(round(out_lo + (min(s, hi) - lo) * (out_hi - out_lo) / (hi - lo)))
```

The function never decreases, and every IPS level lands in the published level of the same name (checked for all 101 scores). Examples:

| IPS score | Published `ips_score` | `ips_level` |
|---|---|---|
| 29 | 30 | low |
| 54 | 55 | medium |
| 67 | 72 | high |
| 77 | 87 | high |
| 81 | 91 | critical |
| 85 | 93 | critical |
| 86 | 94 | critical |

`incident.level` is still the zone's level from points (CONTRACT 11); `details.ips_level` is the IPS's judgement of the attack. The two can differ, for example one brute force alone is 35 points, which is Medium, while the IPS may rate it Critical.

## 6. Example

```json
{"id": "6f1c2d9a-52b1-4a0e-9c3e-0d6c5e7a11f2", "ts": "2026-10-21T09:05:15.000+00:00", "source": "cyber",
 "type": "cyber.brute_force", "zone": "network", "severity_hint": "critical",
 "data": {"src_ip": "203.0.113.45", "dst_ip": "192.168.1.50", "dst_port": 22, "protocol": "TCP",
          "direction": "inbound", "device_id": "cam_001", "confidence": 0.98, "mitre_technique": "T1110",
          "failed_attempts": 300, "connection_attempts": 300, "duration": 240,
          "target": "ssh", "attempts": 300, "window_s": 240,
          "details": {"mitre_technique": "T1110", "ips_score": 93, "ips_level": "critical", "ips_score_raw": 85,
                      "reports": {"technical": "# Security Incident Report ...", "executive": "# Security Incident Summary ..."}}}}
```

## 7. Work list by module

| Module | Change | Owner |
|---|---|---|
| Engine | `block_ip` skips events with `direction: outbound`; copy `data.details` into the incident; do not score `cyber.block_*` (no points, no `src_ip`). **Done** in `services/engine` (`eng/ips.py`, tests in `tests/test_ips.py`); an alert without details gets them from the IPS chain when `iot_ips` is installed | Person 6 (engine) |
| API | store `details` encrypted (nullable column), return it in `/incidents`, cap each report at 12 KB, keep `integrity_ok` behaviour | Person 2 (API) |
| Cyber | add the eleven fields to `cyber.port_scan` and `cyber.brute_force`; accept IPS events from the adapter; optionally add `cyber.dos` to `CYBER_AUTOBLOCK` | Person 5 (cyber) |
| Frontend | show `details` (MITRE tag, IPS level and score, the two reports as plain text, never HTML) | Person 7 (frontend) |
| IPS pipeline | adapter that builds the events of section 3; `load_devices` must keep `zone`, `backend_id` and `backend_type` (it now drops unknown keys) | IPS Person 6 |
| IPS reports | provide the technical and executive report as plain text for `details.reports` | IPS Person 7 |
| Simulators | none; `plug` and `industrial_sensor` have no simulator | - |
| Device registration | `scripts/ips/seed_ips_devices.py` reads `config/ips_devices.json` and registers the six devices through `POST /devices` (they then appear in the dashboard) | Person 7 |

## 8. Out of this change

- The engine's zone score ignores the IPS score. If the IPS judgement should lift the incident level (for example `max(points, ips_score)`), the engine owner decides that as a separate change.
- Real firewall enforcement from the IPS (today: dry run).

## 9. Sign-off

| Owner | Confirms | Signed |
|---|---|---|
| Person 1 (lead) | contract text, decision on the scale, this file | [ ] |
| Person 2 (API) | `details` storage and size limit | [ ] |
| Person 5 (cyber) | eleven fields, `cyber.dos` autoblock, adapter identity | [ ] |
| Person 6 (engine) | points 40 and 30, outbound rule, `details` copy | [ ] |
| Person 7 (frontend) | `details` display as text | [ ] |
| IPS owners (detector, risk, policy, pipeline, reports) | mapping tables, score conversion, `devices.json` fields | [ ] |
