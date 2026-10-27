# Security Incident Report: INC-00004

**Classification:** MEDIUM (57/100) | **Status:** Open | **Source system:** IoT Intrusion Prevention System

| Field | Detail |
|---|---|
| Incident ID | INC-00004 |
| Detected (UTC) | 2026-10-21T09:06:00Z |
| Affected asset | CAM-001 (surveillance_camera), criticality high |
| Incident owner | IoT Security Lead (to be assigned) |
| Response target | 4 hours (proposed internal target) |
| Escalation | Handled by the security analyst on duty; the System Owner is informed. |

## 1. Executive summary
The IoT-IPS detected **unexpected traffic on a non-approved port** against **CAM-001** from **203.0.113.45** with 60% confidence. The event is rated **Medium** (57/100). Response taken: notification sent to the administrator. Current status: **open**.

## 2. Technical indicators
| Indicator | Value |
|---|---|
| Source IP | 203.0.113.45 (external, outside the network) |
| Destination | 192.168.1.50:22 / TCP |
| Attempts or events observed | 6 |

| Duration | - |
| Detection method | Rule-based detector (ML model planned) |

## 3. Threat analysis (MITRE ATT&CK)
| Item | Value |
|---|---|
| Tactic | Command and Control (TA0011) |
| Technique | T1571 Non-Standard Port |
| Reference | https://attack.mitre.org/techniques/T1571/ |
| Security property at risk | Integrity (unauthorised change or control) |

**Analyst assessment:** A connection reached the device on a port or protocol outside its approved profile. This can mean a service the device should not run, a probe for one, or command-and-control traffic.

## 4. Risk assessment
| Risk factor | Value | Weight | Contribution |
|---|---|---|---|
| Confidence | 60/100 | 0.20 | 12.0 |
| Attack Severity | 35/100 | 0.25 | 8.8 |
| Device Criticality | 75/100 | 0.20 | 15.0 |
| Persistence | 34/100 | 0.15 | 5.1 |
| Source Trust | 90/100 | 0.10 | 9.0 |
| Behavioral Deviation | 100/100 | 0.05 | 5.0 |
| Potential Impact | 35/100 | 0.05 | 1.8 |

- **Likelihood:** Medium (detection confidence and persistence of the activity).
- **Impact:** High (criticality of the affected device).
- **Overall rating:** Medium (57/100), calculated by the risk engine from the weighted factors above (weight set: balanced).
- **Risk statement:** there is a medium likelihood that this incident (unexpected traffic on a non-approved port against CAM-001) results in unauthorised change or control, with a high impact on the organisation.

## 5. Response and containment
**Action taken:** Notification sent to the administrator.

**Policy decision:** rule medium matched: level Medium, score 57, confidence 0.6, attack known.

| NIST SP 800-61 phase | State |
|---|---|
| Detection and analysis | Completed by the IPS (detection, risk scoring) |
| Containment | Monitoring only |
| Eradication and recovery | Not required at this level |
| Post-incident review | Required for High and Critical incidents |

## 6. Recommended actions
**Immediate (analyst, within the response target)**
1. Verify whether the source is a known system and whether the device should offer that service.
2. Review the device for signs of compromise (unknown processes, changed settings).

**Short term (corrective)**
1. Allow inbound traffic to the device only on its approved ports.
2. Reset the device to a known-good firmware if compromise is suspected.

**Long term (preventive)**
1. Maintain an approved-communications profile for every device type.
2. Subscribe to vendor security advisories.

## 7. Governance, risk and compliance
| Framework | Reference | Relevance |
|---|---|---|
| NIST CSF 2.0 | DE.AE | Adverse event analysis |
| NIST CSF 2.0 | RS.AN | Incident analysis |
| ISO/IEC 27001:2022 | A.8.16 | Monitoring activities |
| ISO/IEC 27001:2022 | A.8.22 | Segregation of networks |

- **Risk register:** record as *RISK-INC-00004*: Unexpected traffic on a non-approved port on CAM-001; inherent rating Medium; treatment *mitigate* (actions in section 6); owner IoT Security Lead; review after closure.
- **Reporting:** notify the system owner per the escalation line above; keep the incident record for the retention period set in the organisation's policy.
- **Lessons learned:** feed the result into the detection rules and device baseline (ISO/IEC 27001 A.5.27).

## 8. Evidence and integrity
Incident record SHA-256: `d90405caa8ec8cbdf958c709e69e26e1c6822a2d13a7a135f2cd00a5c89756a7`

## 9. Assumptions and limitations
Detection uses threshold rules and does not see encrypted payloads. Confidence and risk values are model outputs and need analyst validation before any decision beyond the simulated (dry-run) response. Compliance references are indicative mappings, not a certification statement.

*Generated automatically by the IoT-IPS reporting module.*
