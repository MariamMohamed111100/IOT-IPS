# Design document addendum: changes after the PDF

The PDF describes the first integrated release. This addendum lists what changed and the new results. Apply it to the PDF's contract, detector, results and testing sections.

## 1. Contract changes
| Item | Change |
|---|---|
| Event context | New optional field `direction`: `inbound` (to the device) or `outbound` (from the device). Missing or unknown counts as inbound. |
| Device profile | New optional list `expected_outbound_ports` (where the device may connect: DNS, NTP, its cloud). `expected_ports` keeps meaning "ports the device serves". |
| Detector call | `detect(event, device_profile)` (the pipeline now passes the profile). The ML model must accept both arguments. |
| Detection | `mitre_technique` is the single source of truth: the report prints the detector's tag. |
| Incident | The source label (external / unknown internal / trusted internal host) comes from the risk engine's `source_trust` factor. |

## 2. Detector rule changes
- **Brute force:** counts `failed_attempts` only (connections no longer count).
- **DoS:** high rate or SYN count, and (when the event has it) `connection_attempts` >= 1000. Configurable (`min_connection_attempts`, 0 turns it off).
- **Unexpected traffic:** inbound events are compared with `expected_ports`, outbound events with `expected_outbound_ports`. MITRE T1571 (Non-Standard Port).
- **Configuration:** `rules.yaml` is validated when loaded; typos raise an error.

## 3. Pipeline changes
`--dedup-window SECONDS` (group repeats; default off), `--placeholders`, `--require-real`, start-up validation of `rules.yaml`. Actions still run before the incident is stored, so containment does not depend on the database.

## 4. New results (`python evaluate.py`)
| Event | Scenario | Result |
|---|---|---|
| EVT-001 to 004 | benign traffic (stream viewing, cloud upload, DNS, one wrong password) | no incident |
| EVT-005 | port scan of 1,000 ports | High, port scan |
| EVT-006 | slow scan (8080) | Medium, unexpected port (wrong type, alert raised) |
| EVT-007 | vulnerability scan of the plug | missed (known limit) |
| EVT-008 | 300 failed SSH logins | Critical, brute force |
| EVT-009 | 6 SSH guesses | Medium, unexpected port (wrong type, alert raised) |
| EVT-010 | SYN flood | Critical, DoS |
| EVT-011 | UDP flood | Critical, DoS |
| EVT-012 | ARP spoofing | missed (needs ARP data) |
| EVT-013 | command injection | missed (needs payload inspection) |
| EVT-014 | infected camera floods an outside server | Critical, DoS (device isolated) |

7 incidents (2 Medium, 1 High, 4 Critical). 7 of 10 attacks raised an alert, 0 of 4 benign events did. Precision 1.00, recall 0.70, F1 0.82 on these 14 events (before: 6 of 10, 1 false alarm, 0.86 / 0.60 / 0.71). Two of the seven alerts carry the wrong attack type. Fourteen events with hand-written context only show that the chain works; they are not an accuracy measurement.

`expected_results.csv` was updated for EVT-006 and EVT-009 (they are now detected by the unexpected-port rule).

## 5. Tests
288 unit tests pass: database 23, pipeline 57, detector 35, risk 54, actions 38, policy 55, reports 26. Plus `evaluate.py` (14 of 14 events as expected) and the demo scripts, all run in CI.
