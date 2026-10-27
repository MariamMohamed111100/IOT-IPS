"""
report.py - incident reporting for the IoT-IPS.

make_report(incident) -> {"technical": str, "executive": str, "notification": str|None}
Templates only (no LLM). Every field is treated as untrusted text and sanitised first.
Sample reports: `python make_samples.py` (real pipeline output). Rebuild from a JSON file: `python report.py incidents.json`.
"""
import hashlib, json, math, re

# ---------------------------------------------------------------- sanitising
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
def clean(v, n=120):
    """Strip control chars and markup characters, cap the length."""
    s = _CTRL.sub(" ", str(v))
    s = s.replace("|", "/").replace("`", "'").replace("<", "(").replace(">", ")")
    s = s.replace("[", "(").replace("]", ")").replace("*", " ").replace("://", ":/ ")   # no markdown links, emphasis or autolinks
    return re.sub(r"\s+", " ", s).strip()[:n]

# ---------------------------------------------------------------- governance
LEVELS = ["Low", "Medium", "High", "Critical"]
# Proposed internal response targets - adjust to the organisation's policy.
SLA = {"Critical": "15 minutes", "High": "1 hour", "Medium": "4 hours", "Low": "24 hours"}
ESCALATION = {
    "Critical": "Immediate escalation to the IoT Security Lead and the System Owner; management informed.",
    "High": "Escalate to the IoT Security Lead; the System Owner is informed.",
    "Medium": "Handled by the security analyst on duty; the System Owner is informed.",
    "Low": "Logged and reviewed by the security analyst during routine monitoring.",
}
STATUS_PLAIN = {
    "Simulated containment": "The system decided how to contain the threat, but this is a simulation: nothing was actually blocked or isolated. The device is under close monitoring and still needs a person to check it.",
    "Monitoring": "No harm has been detected. The activity is being watched.",
    "Open": "The incident is being investigated and is not yet resolved.",
}
ACTION_TEXT = {
    "monitor": ("Continued monitoring of the device", "Increased monitoring"),
    "notify_admin": ("Notification sent to the administrator", "Administrator notified"),
    "temporary_block": ("Temporary block decided (dry-run, not executed)", "Temporary block decided (dry-run)"),
    "block_source": ("Block decided (dry-run, not executed)", "Block decided (dry-run)"),
    "isolate_device": ("Isolation decided (dry-run, not executed)", "Isolation decided (dry-run)"),
    "log": ("Event logged", "Event logged"),
    "create_incident": ("Incident record created", "Incident recorded"),
}
BOOKKEEPING = ("log", "create_incident")
NETWORK = ("temporary_block", "block_source", "isolate_device")
BUSINESS = {
    "surveillance_camera": "Loss of video coverage or exposure of live footage; physical security is weakened while the camera is affected.",
    "temperature_sensor": "Unreliable environmental readings, which may affect monitoring and automated decisions.",
    "industrial_sensor": "Wrong or missing process readings, which may disturb production or safety decisions that depend on them.",
    "smart_bulb": "Limited direct impact; the main concern is use of the device as a foothold on the network.",
}
CIA_RISK = {"Confidentiality": "exposure of data", "Integrity": "unauthorised change or control", "Availability": "loss of service"}

# ---------------------------------------------------------------- MITRE ATT&CK + GRC knowledge base
ATTACKS = {
    "port_scan": dict(
        title="Network service discovery (port scan)", tactic="Discovery", tactic_id="TA0007",
        tech_id="T1046", tech_name="Network Service Discovery", cia="Confidentiality",
        tech="The source probed multiple ports on the device to learn which services are exposed. This is typically the reconnaissance step before an intrusion attempt.",
        plain="Someone checked which doors (network services) the device has open. This is usually the first step before an attack.",
        imm=["Confirm whether the source is an authorised scanner or asset.", "Keep the source under monitoring and review its other connections."],
        short=["Disable every service the device does not need.", "Restrict management ports to the admin network only."],
        long=["Segment IoT devices into their own VLAN.", "Review firewall rules at least quarterly."],
        iso=[("A.8.16", "Monitoring activities"), ("A.8.20", "Networks security")],
        nist=[("DE.CM", "Continuous monitoring"), ("DE.AE", "Adverse event analysis")]),
    "brute_force": dict(
        title="Credential brute-force attempt", tactic="Credential Access", tactic_id="TA0006",
        tech_id="T1110", tech_name="Brute Force", cia="Confidentiality",
        tech="The source made a large number of failed authentication attempts against a device service (for example SSH, Telnet or RTSP) to guess valid credentials.",
        plain="Someone tried to guess the device's password many times in a row.",
        imm=["Block the source (the system only simulated the block) and verify that no login succeeded.", "Check the device for new accounts or configuration changes.", "Change the device credentials if there is any doubt."],
        short=["Replace default credentials with unique strong ones.", "Disable Telnet and any remote access that is not needed.", "Add lockout or rate limiting for failed logins."],
        long=["Use certificate or key based access where the device supports it.", "Include credential hygiene in the IoT onboarding checklist."],
        iso=[("A.8.5", "Secure authentication"), ("A.5.26", "Response to information security incidents")],
        nist=[("DE.AE", "Adverse event analysis"), ("RS.MI", "Incident mitigation")]),
    "dos": dict(
        title="Network denial-of-service (SYN flood)", tactic="Impact", tactic_id="TA0040",
        tech_id="T1498", tech_name="Network Denial of Service", cia="Availability",
        tech="The source sent traffic at a rate far above the device's baseline, aiming to exhaust its network or processing capacity and make it unavailable.",
        plain="Someone flooded the device with traffic to make it stop working.",
        imm=["Block the source (the system only simulated the block) and confirm that the device responds normally.", "Check upstream links for congestion."],
        short=["Apply rate limits for the device at the gateway.", "Confirm the device firmware is current."],
        long=["Define a traffic baseline per device and alert on deviations.", "Plan capacity and failover for critical devices."],
        iso=[("A.8.20", "Networks security"), ("A.5.26", "Response to information security incidents")],
        nist=[("DE.CM", "Continuous monitoring"), ("RS.MI", "Incident mitigation")]),
    "unexpected_protocol": dict(
        title="Unexpected traffic on a non-approved port", tactic="Command and Control", tactic_id="TA0011",
        tech_id="T1571", tech_name="Non-Standard Port", cia="Integrity",
        tech="A connection reached the device on a port or protocol outside its approved profile. This can mean a service the device should not run, a probe for one, or command-and-control traffic.",
        plain="Something contacted the device in a way it normally never is contacted.",
        imm=["Verify whether the source is a known system and whether the device should offer that service.", "Review the device for signs of compromise (unknown processes, changed settings)."],
        short=["Allow inbound traffic to the device only on its approved ports.", "Reset the device to a known-good firmware if compromise is suspected."],
        long=["Maintain an approved-communications profile for every device type.", "Subscribe to vendor security advisories."],
        iso=[("A.8.16", "Monitoring activities"), ("A.8.22", "Segregation of networks")],
        nist=[("DE.AE", "Adverse event analysis"), ("RS.AN", "Incident analysis")]),
    "arp_spoofing": dict(
        title="ARP cache poisoning", tactic="Credential Access", tactic_id="TA0006",
        tech_id="T1557.002", tech_name="Adversary-in-the-Middle: ARP Cache Poisoning", cia="Integrity",
        tech="Forged ARP replies were observed that try to place the source between the device and its gateway, allowing traffic to be intercepted or altered.",
        plain="Someone tried to trick the network into sending the device's traffic through their machine.",
        imm=["Identify the physical port or host behind the forged address.", "Flush ARP tables on the gateway and the device."],
        short=["Enable dynamic ARP inspection or static ARP entries for critical devices."],
        long=["Use port security and segmentation on the access network."],
        iso=[("A.8.20", "Networks security"), ("A.8.22", "Segregation of networks")],
        nist=[("DE.CM", "Continuous monitoring"), ("RS.MI", "Incident mitigation")]),
}
GENERIC = dict(title="Suspicious activity", tactic="Unmapped", tactic_id="-", tech_id="-", tech_name="Not mapped", cia="Integrity",
    tech="The activity deviates from the device baseline and could not be mapped to a known ATT&CK technique.",
    plain="The device behaved in an unusual way and the system flagged it.",
    imm=["Review the raw events for this device."], short=["Classify the activity and update the detection rules."], long=["Review the device baseline."],
    iso=[("A.5.25", "Assessment and decision on information security events")], nist=[("DE.AE", "Adverse event analysis")])

ATTACKS["spoofing"] = ATTACKS.pop("arp_spoofing")
ATTACKS["spoofing"].update(title="Spoofing / adversary-in-the-middle", tech_id="T1557", tech_name="Adversary-in-the-Middle",
    tech="Forged address-resolution or name-resolution replies (for example ARP or DNS) were observed that try to place the source between the device and its peers, allowing traffic to be intercepted or altered.")
ATTACKS["reconnaissance"] = dict(ATTACKS["port_scan"], title="Active reconnaissance", tactic="Reconnaissance", tactic_id="TA0043",
    tech_id="T1595", tech_name="Active Scanning",
    tech="The source actively probed the device and its network to gather information about hosts, services and weaknesses before a possible attack.")
ATTACKS["ddos"] = dict(ATTACKS["dos"], title="Distributed denial-of-service",
    tech="The device was hit by a high-rate flood from many sources at once, aiming to exhaust its capacity and make it unavailable.",
    plain="Many machines flooded the device with traffic at the same time to make it stop working.",
    long=["Define a traffic baseline per device and alert on deviations.", "Agree upstream filtering or rate limiting with the network provider."])
ATTACKS["web_based"] = dict(title="Web-based attack on the device interface", tactic="Initial Access", tactic_id="TA0001",
    tech_id="T1190", tech_name="Exploit Public-Facing Application", cia="Integrity",
    tech="Malicious requests were sent to the device's web or management interface, typically to exploit a vulnerability or inject commands.",
    plain="Someone sent harmful requests to the device's web page or control panel.",
    imm=["Review the device web logs for unusual requests.", "Check whether the device configuration or firmware changed."],
    short=["Apply the latest vendor firmware.", "Remove the device web interface from any internet-facing path."],
    long=["Place management interfaces on an admin-only network.", "Run periodic vulnerability scans on IoT devices."],
    iso=[("A.8.8", "Management of technical vulnerabilities"), ("A.8.20", "Networks security")],
    nist=[("DE.AE", "Adverse event analysis"), ("RS.MI", "Incident mitigation")])
ATTACKS["mirai"] = dict(title="Mirai-style botnet infection", tactic="Resource Development", tactic_id="TA0042",
    tech_id="T1584.005", tech_name="Compromise Infrastructure: Botnet", cia="Availability",
    tech="Traffic matches Mirai-style behaviour: default-credential guessing followed by enrolment of the device into a botnet used for large-scale attacks.",
    plain="The device shows signs of being recruited into a network of hacked devices used to attack others.",
    imm=["Isolate the device (the system only simulated it) and treat it as compromised.", "Do not reconnect it before it is reset."],
    short=["Factory-reset and update the firmware, then set a unique password.", "Check other devices of the same model."],
    long=["Ban default credentials in the IoT onboarding checklist.", "Block outbound traffic that the device does not need."],
    iso=[("A.8.7", "Protection against malware"), ("A.5.26", "Response to information security incidents")],
    nist=[("DE.AE", "Adverse event analysis"), ("RS.MI", "Incident mitigation")])
ATTACKS["device_takeover"] = dict(title="Device takeover", tactic="Initial Access", tactic_id="TA0001",
    tech_id="T1078", tech_name="Valid Accounts", cia="Integrity",
    tech="Activity indicates that an attacker gained working control of the device, for example through valid or default credentials.",
    plain="Someone appears to have taken control of the device.",
    imm=["Isolate the device and treat it as compromised.", "Preserve its logs and configuration as evidence."],
    short=["Reset the device, update the firmware and rotate every credential it used."],
    long=["Review how access was obtained and close that path.", "Add authentication-failure alerting for all IoT devices."],
    iso=[("A.8.5", "Secure authentication"), ("A.5.26", "Response to information security incidents")],
    nist=[("RS.AN", "Incident analysis"), ("RS.MI", "Incident mitigation")])

_ALIASES = {"portscan": "port_scan", "scan": "port_scan", "recon": "reconnaissance", "bruteforce": "brute_force",
            "dictionarybruteforce": "brute_force", "dictionary_bruteforce": "brute_force", "web": "web_based",
            "webbased": "web_based", "unexpected_port": "unexpected_protocol", "takeover": "device_takeover",
            "arp_spoofing": "spoofing", "dns_spoofing": "spoofing", "mitm": "spoofing"}
from .risk import canonical_attack_name as _p4_canon   # one list of attack names for the score, the policy and the reports
def canon(name):
    """Canonical attack key (same names as risk_weights.yaml), or None if unknown."""
    if _p4_canon:
        try:
            c = _p4_canon(name)
            if c: return c
        except Exception:
            pass
    k = re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")
    k = _ALIASES.get(k, k)
    return k if k in ATTACKS else None

def _lvl(n): return "Low" if n < 40 else "Medium" if n < 70 else "High"

def _num(v, default=0.0):
    """A finite number from v, or default. Never raises: a report must always be produced."""
    try:
        f = float(v)
    except (TypeError, ValueError):
        return default
    return f if math.isfinite(f) else default

def _norm(inc):
    def g(k, d="-"):
        v = inc.get(k)
        return d if v is None else clean(v)
    ckey = canon(inc.get("attack_type"))
    atk = ATTACKS.get(ckey, GENERIC)
    score = max(0, min(100, int(_num(inc.get("score"), 0.0))))
    level = clean(inc.get("level", "")).capitalize()
    if level not in LEVELS: level = "Low" if score < 30 else "Medium" if score < 60 else "High" if score < 80 else "Critical"
    status = clean(inc.get("status", "Open")).capitalize()
    if status == "Contained": status = "Simulated containment"   # old records
    status = status if status in STATUS_PLAIN else "Open"
    conf = max(0.0, min(1.0, _num(inc.get("confidence"), 0.0)))
    factors = {}
    for k, v in (inc.get("factors") if isinstance(inc.get("factors"), dict) else {}).items():           # accepts the risk engine's nested dicts or plain numbers
        d = v if isinstance(v, dict) else {"value": v}
        try: val = None if d.get("value") is None else max(0.0, min(100.0, float(d["value"])))
        except (TypeError, ValueError): val = None
        try: wt = None if d.get("weight") is None else float(d["weight"])
        except (TypeError, ValueError): wt = None
        try: ct = None if d.get("contribution") is None else float(d["contribution"])
        except (TypeError, ValueError): ct = None
        factors[clean(k, 40)] = (val, wt, ct)
    acts = [a for a in (inc.get("actions") or []) if a in ACTION_TEXT] or ["monitor"]
    vis = [a for a in acts if a not in BOOKKEEPING] or acts
    skipped = [clean(f"{x.get('action')} ({x.get('why')})" if isinstance(x, dict) else x, 100) for x in (inc.get("skipped") or [])][:10]
    applied = [a for a in acts if a in NETWORK]
    warns = [clean(x, 60) for x in (inc.get("warnings") or [])][:10]
    digest = hashlib.sha256(json.dumps(inc, sort_keys=True, default=str).encode()).hexdigest()
    return dict(g=g, atk=atk, score=score, level=level, status=status, conf=conf, factors=factors, acts=acts,
                digest=digest, vis=vis, skipped=skipped, applied=applied, warns=warns, rule=g("rule_id"), reason=g("reason", ""), wset=g("weight_set"), id=g("id"), ts=g("timestamp"), dev=g("device_id"), dtype=g("device_type"),
                crit=g("criticality"), dip=g("device_ip"), src=g("src_ip"), dst=g("dst_ip"), port=g("dst_port"),
                proto=g("protocol"), attempts=g("attempts"), duration=g("duration"), atype=g("attack_type"),
                src_kind=g("source_type", "unknown"), events=max(1, int(_num(inc.get("event_count"), 1.0))),
                first_seen=g("first_seen"), last_seen=g("last_seen"))

def _factor_table(f):
    def cell(v, fmt): return "not used" if v is None else fmt % v
    rows = "\n".join(f"| {k.replace('_', ' ').title()} | {cell(v, '%.0f/100')} | {cell(w, '%.2f')} | {cell(c, '%.1f')} |" for k, (v, w, c) in f.items())
    return "| Risk factor | Value | Weight | Contribution |\n|---|---|---|---|\n" + rows

def technical_report(inc):
    n = _norm(inc); a = n["atk"]
    url = "https://attack.mitre.org/techniques/" + a["tech_id"].replace(".", "/") + "/" if a["tech_id"] != "-" else "n/a"
    fv = lambda k, d: (n["factors"].get(k) or (None,))[0] if (n["factors"].get(k) or (None,))[0] is not None else d
    likelihood = _lvl((n["conf"] * 100 + fv("persistence", n["conf"] * 100)) / 2)
    impact = _lvl(fv("device_criticality", 50))
    actions_txt = "; ".join(ACTION_TEXT[x][0] for x in n["vis"])
    cmds = ""
    if inc.get("commands"):
        cmds = "\n\nDry-run commands (not executed):\n```\n" + "\n".join(clean(c, 200) for c in inc["commands"]) + "\n```"
    grouped_row = (f"| Repeated events in this incident | {n['events']} ({n['first_seen']} to {n['last_seen']}) |"
                   if n["events"] > 1 else "")
    iso = "\n".join(f"| ISO/IEC 27001:2022 | {c} | {t} |" for c, t in a["iso"])
    nist = "\n".join(f"| NIST CSF 2.0 | {c} | {t} |" for c, t in a["nist"])
    lst = lambda xs: "\n".join(f"{i}. {x}" for i, x in enumerate(xs, 1))
    return f"""# Security Incident Report: {n['id']}

**Classification:** {n['level'].upper()} ({n['score']}/100) | **Status:** {n['status']} | **Source system:** IoT Intrusion Prevention System

| Field | Detail |
|---|---|
| Incident ID | {n['id']} |
| Detected (UTC) | {n['ts']} |
| Affected asset | {n['dev']} ({n['dtype']}), criticality {n['crit']} |
| Incident owner | IoT Security Lead (to be assigned) |
| Response target | {SLA[n['level']]} (proposed internal target) |
| Escalation | {ESCALATION[n['level']]} |

## 1. Executive summary
The IoT-IPS detected **{a['title'].lower()}** against **{n['dev']}** from **{n['src']}** with {n['conf']:.0%} confidence. The event is rated **{n['level']}** ({n['score']}/100). Response taken: {actions_txt.lower()}. Current status: **{n['status'].lower()}**.

## 2. Technical indicators
| Indicator | Value |
|---|---|
| Source IP | {n['src']} ({n['src_kind']}) |
| Destination | {n['dst']}:{n['port']} / {n['proto']} |
| Attempts or events observed | {n['attempts']} |
{grouped_row}
| Duration | {n['duration']} |
| Detection method | Rule-based detector (ML model planned) |

## 3. Threat analysis (MITRE ATT&CK)
| Item | Value |
|---|---|
| Tactic | {a['tactic']} ({a['tactic_id']}) |
| Technique | {a['tech_id']} {a['tech_name']} |
| Reference | {url} |
| Security property at risk | {a['cia']} ({CIA_RISK[a['cia']]}) |

**Analyst assessment:** {a['tech']}

## 4. Risk assessment
{_factor_table(n['factors'])}

- **Likelihood:** {likelihood} (detection confidence and persistence of the activity).
- **Impact:** {impact} (criticality of the affected device).
- **Overall rating:** {n['level']} ({n['score']}/100), calculated by the risk engine from the weighted factors above{(' (weight set: ' + n['wset'] + ')') if n['wset'] != '-' else ''}.
- **Risk statement:** there is a {likelihood.lower()} likelihood that this incident ({a['title'].lower()} against {n['dev']}) results in {CIA_RISK[a['cia']]}, with a {impact.lower()} impact on the organisation.

## 5. Response and containment
**Action taken:** {actions_txt}.{cmds}
{('' if not n['rule'] or n['rule'] == '-' else chr(10) + '**Policy decision:** ' + (n['reason'] or 'rule ' + n['rule']) + '.')}{('' if not n['skipped'] else chr(10) + chr(10) + '**Not executed:** ' + '; '.join(n['skipped']) + ' (the reason is in brackets). An analyst should review this manually.')}{('' if not n['warns'] else chr(10) + chr(10) + '**Data-quality warnings:** ' + ', '.join(n['warns']) + '.')}

| NIST SP 800-61 phase | State |
|---|---|
| Detection and analysis | Completed by the IPS (detection, risk scoring) |
| Containment | {'Simulated (dry-run, nothing executed)' if n['applied'] else 'Monitoring only'} |
| Eradication and recovery | {'Pending analyst verification' if n['level'] in ('High','Critical') else 'Not required at this level'} |
| Post-incident review | Required for High and Critical incidents |

## 6. Recommended actions
**Immediate (analyst, within the response target)**
{lst(a['imm'])}

**Short term (corrective)**
{lst(a['short'])}

**Long term (preventive)**
{lst(a['long'])}

## 7. Governance, risk and compliance
| Framework | Reference | Relevance |
|---|---|---|
{nist}
{iso}

- **Risk register:** record as *RISK-{n['id']}*: {a['title']} on {n['dev']}; inherent rating {n['level']}; treatment *mitigate* (actions in section 6); owner IoT Security Lead; review after closure.
- **Reporting:** notify the system owner per the escalation line above; keep the incident record for the retention period set in the organisation's policy.
- **Lessons learned:** feed the result into the detection rules and device baseline (ISO/IEC 27001 A.5.27).

## 8. Evidence and integrity
Incident record SHA-256: `{n['digest']}`

## 9. Assumptions and limitations
Detection uses threshold rules and does not see encrypted payloads. Confidence and risk values are model outputs and need analyst validation before any decision beyond the simulated (dry-run) response. Compliance references are indicative mappings, not a certification statement.

*Generated automatically by the IoT-IPS reporting module.*
"""

def executive_report(inc):
    n = _norm(inc); a = n["atk"]
    banner = {"Critical": "CRITICAL: IMMEDIATE ATTENTION", "High": "HIGH: ATTENTION REQUIRED", "Medium": "MEDIUM: REVIEW SOON", "Low": "LOW: NO ACTION NEEDED"}[n["level"]]
    did = ". ".join(ACTION_TEXT[x][1] for x in n["vis"]) + "."
    safe = STATUS_PLAIN[n["status"]]
    decisions = {
        "Critical": ["Confirm that the device should be isolated until the security team verifies it (the system only simulated the isolation).", "Approve the corrective actions listed by the security team (for example new credentials)."],
        "High": ["Review the report and confirm the follow-up actions with the security team."],
        "Medium": ["No decision is needed now; the security team will report if the situation changes."],
        "Low": ["No decision is needed."],
    }[n["level"]]
    dec = "\n".join(f"- {d}" for d in decisions)
    return f"""# Security Incident Summary: {n['id']}

## Status: {banner}

**Device:** {n['dev']} ({n['dtype'].replace('_', ' ')})
**Risk rating:** {n['level']} ({n['score']} out of 100)
**Time detected:** {n['ts']}

### What happened?
{a['plain']} The system noticed this on {n['ts']} and rated it with {n['conf']:.0%} confidence.

### What did the system do?
{did}

### Is the device safe?
{safe}

### What could it have meant for the business?
{BUSINESS.get(n['dtype'], 'The device could have been misused or taken out of service.')}

### What is needed from management?
{dec}

### Governance note
This incident was recorded, rated and escalated according to the security response procedure. {ESCALATION[n['level']]} The full technical report and evidence are available to the security team.
"""

def notification(inc):
    n = _norm(inc)
    if n["level"] not in ("High", "Critical"): return None
    icon = "CRITICAL" if n["level"] == "Critical" else "HIGH-RISK"
    return f"""{icon} IoT SECURITY ALERT

Device: {n['dev']}
Problem: {n['atk']['title']} from {n['src']}
Risk: {n['score']}/100 ({n['level']})
MITRE ATT&CK: {n['atk']['tech_id']} {n['atk']['tech_name']}
Action: {'; '.join(ACTION_TEXT[x][1] for x in n['vis'])}
Status: {n['status']}
Respond within: {SLA[n['level']]}
Incident: {n['id']}
"""

SOURCE_KINDS = {"external": "external, outside the network", "internal_unknown": "internal, not a known device",
                "trusted_internal": "trusted internal device", "trusted": "trusted internal device"}


def source_kind(risk):
    """Plain-words label for the source, taken from the risk engine's source_trust factor (never from event text)."""
    factors = risk.get("factors") if isinstance(risk, dict) else None
    detail = (factors.get("source_trust") or {}).get("detail") if isinstance(factors, dict) and isinstance(factors.get("source_trust"), dict) else None
    return SOURCE_KINDS.get(detail, "unknown")


def build_incident(event, detection, risk, decision, device_profile=None, incident_id=None, status=None, timestamp=None):
    """Merge the outputs of the detector, risk engine and policy into the one incident record that make_report() reads.
    event/detection/risk/decision/device_profile are the dicts exactly as the modules produce them (not modified)."""
    from datetime import datetime, timezone
    ev, de, ri, dc, dp = (x if isinstance(x, dict) else {} for x in (event, detection, risk, decision, device_profile))
    acts = [a for a in (dc.get("action") or []) if a in ACTION_TEXT]
    tgt = dc.get("targets") if isinstance(dc.get("targets"), dict) else {}
    level = ri.get("level", "Low")
    if status is None:
        status = "Simulated containment" if any(a in NETWORK for a in acts) else ("Monitoring" if level in ("Low", "Medium") else "Open")
    attempts = max([v for v in (ev.get("failed_attempts"), ev.get("connection_attempts")) if isinstance(v, (int, float)) and not isinstance(v, bool)] or [0])
    return {
        "id": incident_id or "INC-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
        "timestamp": timestamp or ev.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "device_id": dp.get("device_id") or ev.get("device_id") or tgt.get("device_id"),
        "device_type": dp.get("device_type"), "criticality": dp.get("criticality"), "device_ip": dp.get("ip") or tgt.get("device_ip"),
        "src_ip": ev.get("src_ip"), "dst_ip": ev.get("dst_ip") or dp.get("ip"), "dst_port": ev.get("dst_port"), "protocol": ev.get("protocol"),
        "attempts": attempts, "duration": ev.get("duration"), "source_type": source_kind(ri),
        "event_count": ev.get("event_count") if isinstance(ev.get("event_count"), int) and not isinstance(ev.get("event_count"), bool) else 1,
        "first_seen": ev.get("first_seen"), "last_seen": ev.get("last_seen"),
        "attack_type": de.get("attack_type"), "confidence": de.get("confidence", 0),
        "score": ri.get("score", 0), "level": level, "factors": ri.get("factors"), "weight_set": ri.get("weight_set"),
        "actions": acts, "commands": dc.get("command"), "skipped": dc.get("skipped"), "rule_id": dc.get("rule_id"), "reason": dc.get("reason"),
        "warnings": list(ri.get("warnings") or []) + list(dc.get("warnings") or []), "status": status,
    }

def make_report(inc):
    return {"technical": technical_report(inc), "executive": executive_report(inc), "notification": notification(inc)}
