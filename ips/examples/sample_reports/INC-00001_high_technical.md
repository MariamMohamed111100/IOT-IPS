# Security Incident Report: INC-00001

**Classification:** HIGH (67/100) | **Status:** Open | **Source system:** IoT Intrusion Prevention System

| Field | Detail |
|---|---|
| Incident ID | INC-00001 |
| Detected (UTC) | 2026-10-21T09:03:00Z |
| Affected asset | CAM-001 (surveillance_camera), criticality high |
| Incident owner | IoT Security Lead (to be assigned) |
| Response target | 1 hour (proposed internal target) |
| Escalation | Escalate to the IoT Security Lead; the System Owner is informed. |

## 1. Executive summary
The IoT-IPS detected **network service discovery (port scan)** against **CAM-001** from **192.168.1.66** with 97% confidence. The event is rated **High** (67/100). Response taken: temporary block decided (dry-run, not executed); notification sent to the administrator. Current status: **open**.

## 2. Technical indicators
| Indicator | Value |
|---|---|
| Source IP | 192.168.1.66 (internal, not a known device) |
| Destination | 192.168.1.50:8000 / TCP |
| Attempts or events observed | 1000 |

| Duration | - |
| Detection method | Rule-based detector (ML model planned) |

## 3. Threat analysis (MITRE ATT&CK)
| Item | Value |
|---|---|
| Tactic | Discovery (TA0007) |
| Technique | T1046 Network Service Discovery |
| Reference | https://attack.mitre.org/techniques/T1046/ |
| Security property at risk | Confidentiality (exposure of data) |

**Analyst assessment:** The source probed multiple ports on the device to learn which services are exposed. This is typically the reconnaissance step before an intrusion attempt.

## 4. Risk assessment
| Risk factor | Value | Weight | Contribution |
|---|---|---|---|
| Confidence | 97/100 | 0.20 | 19.4 |
| Attack Severity | 25/100 | 0.25 | 6.2 |
| Device Criticality | 75/100 | 0.20 | 15.0 |
| Persistence | 100/100 | 0.15 | 15.0 |
| Source Trust | 60/100 | 0.10 | 6.0 |
| Behavioral Deviation | 100/100 | 0.05 | 5.0 |
| Potential Impact | 15/100 | 0.05 | 0.8 |

- **Likelihood:** High (detection confidence and persistence of the activity).
- **Impact:** High (criticality of the affected device).
- **Overall rating:** High (67/100), calculated by the risk engine from the weighted factors above (weight set: balanced).
- **Risk statement:** there is a high likelihood that this incident (network service discovery (port scan) against CAM-001) results in exposure of data, with a high impact on the organisation.

## 5. Response and containment
**Action taken:** Temporary block decided (dry-run, not executed); Notification sent to the administrator.

Dry-run commands (not executed):
```
iptables -I FORWARD -s 192.168.1.66 -m comment --comment iot-ips-temp -j DROP
```

**Policy decision:** rule high_probable matched: level High, score 67, confidence 0.97, attack known.

| NIST SP 800-61 phase | State |
|---|---|
| Detection and analysis | Completed by the IPS (detection, risk scoring) |
| Containment | Simulated (dry-run, nothing executed) |
| Eradication and recovery | Pending analyst verification |
| Post-incident review | Required for High and Critical incidents |

## 6. Recommended actions
**Immediate (analyst, within the response target)**
1. Confirm whether the source is an authorised scanner or asset.
2. Keep the source under monitoring and review its other connections.

**Short term (corrective)**
1. Disable every service the device does not need.
2. Restrict management ports to the admin network only.

**Long term (preventive)**
1. Segment IoT devices into their own VLAN.
2. Review firewall rules at least quarterly.

## 7. Governance, risk and compliance
| Framework | Reference | Relevance |
|---|---|---|
| NIST CSF 2.0 | DE.CM | Continuous monitoring |
| NIST CSF 2.0 | DE.AE | Adverse event analysis |
| ISO/IEC 27001:2022 | A.8.16 | Monitoring activities |
| ISO/IEC 27001:2022 | A.8.20 | Networks security |

- **Risk register:** record as *RISK-INC-00001*: Network service discovery (port scan) on CAM-001; inherent rating High; treatment *mitigate* (actions in section 6); owner IoT Security Lead; review after closure.
- **Reporting:** notify the system owner per the escalation line above; keep the incident record for the retention period set in the organisation's policy.
- **Lessons learned:** feed the result into the detection rules and device baseline (ISO/IEC 27001 A.5.27).

## 8. Evidence and integrity
Incident record SHA-256: `743078389ece4af22d58a01ed455e58f459b95d1a7c8215ff6c3e0f6eec1de57`

## 9. Assumptions and limitations
Detection uses threshold rules and does not see encrypted payloads. Confidence and risk values are model outputs and need analyst validation before any decision beyond the simulated (dry-run) response. Compliance references are indicative mappings, not a certification statement.

*Generated automatically by the IoT-IPS reporting module.*
