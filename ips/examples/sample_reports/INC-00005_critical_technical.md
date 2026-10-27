# Security Incident Report: INC-00005

**Classification:** CRITICAL (86/100) | **Status:** Open | **Source system:** IoT Intrusion Prevention System

| Field | Detail |
|---|---|
| Incident ID | INC-00005 |
| Detected (UTC) | 2026-10-21T09:06:45Z |
| Affected asset | CAM-001 (surveillance_camera), criticality high |
| Incident owner | IoT Security Lead (to be assigned) |
| Response target | 15 minutes (proposed internal target) |
| Escalation | Immediate escalation to the IoT Security Lead and the System Owner; management informed. |

## 1. Executive summary
The IoT-IPS detected **network denial-of-service (syn flood)** against **CAM-001** from **203.0.113.45** with 99% confidence. The event is rated **Critical** (86/100). Response taken: block decided (dry-run, not executed); isolation decided (dry-run, not executed); notification sent to the administrator. Current status: **open**.

## 2. Technical indicators
| Indicator | Value |
|---|---|
| Source IP | 203.0.113.45 (external, outside the network) |
| Destination | 192.168.1.50:5000 / UDP |
| Attempts or events observed | 25000 |
| Repeated events in this incident | 2 (2026-10-21T09:06:45Z to 2026-10-21T09:07:30Z) |
| Duration | - |
| Detection method | Rule-based detector (ML model planned) |

## 3. Threat analysis (MITRE ATT&CK)
| Item | Value |
|---|---|
| Tactic | Impact (TA0040) |
| Technique | T1498 Network Denial of Service |
| Reference | https://attack.mitre.org/techniques/T1498/ |
| Security property at risk | Availability (loss of service) |

**Analyst assessment:** The source sent traffic at a rate far above the device's baseline, aiming to exhaust its network or processing capacity and make it unavailable.

## 4. Risk assessment
| Risk factor | Value | Weight | Contribution |
|---|---|---|---|
| Confidence | 99/100 | 0.20 | 19.8 |
| Attack Severity | 75/100 | 0.25 | 18.8 |
| Device Criticality | 75/100 | 0.20 | 15.0 |
| Persistence | 100/100 | 0.15 | 15.0 |
| Source Trust | 90/100 | 0.10 | 9.0 |
| Behavioral Deviation | 100/100 | 0.05 | 5.0 |
| Potential Impact | 70/100 | 0.05 | 3.5 |

- **Likelihood:** High (detection confidence and persistence of the activity).
- **Impact:** High (criticality of the affected device).
- **Overall rating:** Critical (86/100), calculated by the risk engine from the weighted factors above (weight set: balanced).
- **Risk statement:** there is a high likelihood that this incident (network denial-of-service (syn flood) against CAM-001) results in loss of service, with a high impact on the organisation.

## 5. Response and containment
**Action taken:** Block decided (dry-run, not executed); Isolation decided (dry-run, not executed); Notification sent to the administrator.

Dry-run commands (not executed):
```
iptables -I FORWARD -s 203.0.113.45 -m comment --comment iot-ips -j DROP
iptables -I FORWARD -s 192.168.1.50 -m comment --comment iot-ips -j DROP
iptables -I FORWARD -d 192.168.1.50 -m comment --comment iot-ips -j DROP
```

**Policy decision:** rule critical_certain matched: level Critical, score 86, confidence 0.99, attack known.

| NIST SP 800-61 phase | State |
|---|---|
| Detection and analysis | Completed by the IPS (detection, risk scoring) |
| Containment | Simulated (dry-run, nothing executed) |
| Eradication and recovery | Pending analyst verification |
| Post-incident review | Required for High and Critical incidents |

## 6. Recommended actions
**Immediate (analyst, within the response target)**
1. Block the source (the system only simulated the block) and confirm that the device responds normally.
2. Check upstream links for congestion.

**Short term (corrective)**
1. Apply rate limits for the device at the gateway.
2. Confirm the device firmware is current.

**Long term (preventive)**
1. Define a traffic baseline per device and alert on deviations.
2. Plan capacity and failover for critical devices.

## 7. Governance, risk and compliance
| Framework | Reference | Relevance |
|---|---|---|
| NIST CSF 2.0 | DE.CM | Continuous monitoring |
| NIST CSF 2.0 | RS.MI | Incident mitigation |
| ISO/IEC 27001:2022 | A.8.20 | Networks security |
| ISO/IEC 27001:2022 | A.5.26 | Response to information security incidents |

- **Risk register:** record as *RISK-INC-00005*: Network denial-of-service (SYN flood) on CAM-001; inherent rating Critical; treatment *mitigate* (actions in section 6); owner IoT Security Lead; review after closure.
- **Reporting:** notify the system owner per the escalation line above; keep the incident record for the retention period set in the organisation's policy.
- **Lessons learned:** feed the result into the detection rules and device baseline (ISO/IEC 27001 A.5.27).

## 8. Evidence and integrity
Incident record SHA-256: `3aa2790cb3d01c8ff2784d6004fe579dc3adeead889d01811939010a38df0b7c`

## 9. Assumptions and limitations
Detection uses threshold rules and does not see encrypted payloads. Confidence and risk values are model outputs and need analyst validation before any decision beyond the simulated (dry-run) response. Compliance references are indicative mappings, not a certification statement.

*Generated automatically by the IoT-IPS reporting module.*
