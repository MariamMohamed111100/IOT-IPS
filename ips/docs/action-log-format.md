# Decision and action log format

This file describes what `policy.decide()` returns and what `actions.ActionExecutor` writes to the action log. Everything is simulated: no real firewall rule is ever applied in this version.

## How the pieces fit

```
risk + detection + event + device profile
        |
   policy.decide()  ->  decision          (rules from policy.yaml)
        |
   ActionExecutor.run(decision)  ->  action log records (JSON Lines)
```

The pipeline (`pipeline.py`) calls both. The report module reads the decision (or the stored incident) to write the report.

```python
from iot_ips import actions, policy

pol = policy.load_policy()                                    # once, at start-up
executor = actions.ActionExecutor.from_policy(pol, log_path="actions.jsonl")

decision = policy.decide(risk_msg, detection_msg, event, device_profile)
records = executor.run(decision)
# if "create_incident" in decision["action"]: store the incident in the database
```

## Decision message

| Field | Type | Meaning |
|---|---|---|
| `action` | list of strings | Actions to carry out, in order. Every one comes from `config/policy.yaml`. Empty for a benign verdict. |
| `reason` | string | Which rule matched, with the level, score and confidence it used. |
| `command` | list of strings | The firewall commands that would run (dry run). Empty when nothing touches the network. |
| `dry_run` | bool | Always `true` in this version. |
| `rule_id` | string | Id of the rule that matched (`benign` for a benign verdict). |
| `level` | string or null | `Low`, `Medium`, `High`, `Critical`, or null if the risk message was unusable. |
| `targets` | object | `src_ip`, `device_ip`, `device_id`: validated values, or null. |
| `skipped` | list | Actions the rule asked for but safety checks removed: `{"action", "why"}`. |
| `warnings` | list of strings | Fixed codes for bad or missing input (see below). |

Example (Critical, certain):

```json
{
  "action": ["block_source", "isolate_device", "create_incident", "notify_admin"],
  "reason": "rule critical_certain matched: level Critical, score 81, confidence 0.94, attack known",
  "command": [
    "iptables -I FORWARD -s 192.168.1.77 -m comment --comment iot-ips -j DROP",
    "iptables -I FORWARD -s 192.168.1.50 -m comment --comment iot-ips -j DROP",
    "iptables -I FORWARD -d 192.168.1.50 -m comment --comment iot-ips -j DROP"
  ],
  "dry_run": true,
  "rule_id": "critical_certain",
  "level": "Critical",
  "targets": {"src_ip": "192.168.1.77", "device_ip": "192.168.1.50", "device_id": "CAM-001"},
  "skipped": [],
  "warnings": []
}
```

`skipped[].why` codes: `source_allow_listed`, `source_never_block`, `source_is_device`, `no_valid_source`, `no_valid_device_ip`, `device_ip_not_private`, `device_allow_listed`.

`warnings` codes: `invalid_risk`, `invalid_detection`, `label_missing_or_invalid`, `invalid_confidence`, `invalid_score`, `invalid_level`.

## The action catalog

| Action | Kind | What the simulation does |
|---|---|---|
| `monitor` | bookkeeping | Records that the device is being watched. |
| `log` | bookkeeping | Records the event. |
| `create_incident` | bookkeeping | Records that an incident must be stored. **The pipeline writes it to the database.** |
| `notify_admin` | bookkeeping | Records that the administrator must be told. **The report module builds the message.** |
| `temporary_block` | network | Would drop traffic from the source address for `temporary_block_seconds` (default 600). |
| `block_source` | network | Would drop traffic from the source address until someone removes the rule. |
| `isolate_device` | network | Would drop all traffic to and from the protected device. |

## Action log (`actions.jsonl`)

One JSON object per line, ASCII only, appended in order. The file is created with owner-only permissions and rotated to `actions.jsonl.1` when it reaches `max_log_bytes` (10 MB by default).

| Field | Type | Meaning |
|---|---|---|
| `ts` | string | UTC time the executor ran, `2026-10-20T14:03:22Z`. Taken from the executor's clock, never from the event. |
| `seq` | int | Counter that grows by one for every record. |
| `action` | string | An action from the catalog, or `none` when the entry was refused. |
| `status` | string | `simulated` (done in dry run), `skipped` (a safety check said no) or `refused` (invalid input or a limit was hit). |
| `note` | string | Fixed code explaining the status (list below). |
| `dry_run` | bool | Always `true`. |
| `device_id` | string | Device id, or `unknown-device` if it was not a clean identifier. |
| `rule_id` | string | Rule that produced the decision, or `unknown_rule`. |
| `level` | string or null | Risk level. |
| `target` | string or null | The blocked source address, or the isolated device address. |
| `commands` | list | The exact commands that would be run. |
| `undo` | list | The commands that would undo them. |
| `expires_in_s` | int or null | Lifetime of a temporary block. |

`note` codes: `ok`, `already_blocked`, `upgraded_to_permanent`, `expired`, `block_budget_exhausted`, `unknown_action`, `invalid_decision`, and every `skipped[].why` code above.

Example lines:

```json
{"ts":"2026-10-20T14:03:22Z","seq":1,"action":"block_source","status":"simulated","note":"ok","dry_run":true,"device_id":"CAM-001","rule_id":"critical_certain","level":"Critical","target":"192.168.1.77","commands":["iptables -I FORWARD -s 192.168.1.77 -m comment --comment iot-ips -j DROP"],"undo":["iptables -D FORWARD -s 192.168.1.77 -m comment --comment iot-ips -j DROP"],"expires_in_s":null}
{"ts":"2026-10-20T14:03:22Z","seq":2,"action":"block_source","status":"skipped","note":"source_allow_listed","dry_run":true,"device_id":"CAM-001","rule_id":"high_probable","level":"High","target":"192.168.1.20","commands":[],"undo":[],"expires_in_s":null}
```

## Safety rules, in short

* Blocking and isolation need a confident, known attack: `block_source` and `isolate_device` only for Critical, confidence 0.90 or more and a known attack type; `temporary_block` only for High or Critical with confidence 0.60 or more. `policy.yaml` refuses to load if a rule breaks this.
* "A known attack type" is the one the risk engine recognises (`risk.canonical_attack_name`, so aliases such as `bruteforce` count as `brute_force`). An attack the risk engine calls unknown is never blocked or isolated hard, so the policy and the score always agree.
* Never blocked: allow-listed addresses (router, the Pi, admin PCs), loopback, multicast, link-local, reserved and unspecified addresses, and the protected device itself. `isolate_device` only for a private, non-allow-listed device address, and never when the source is allow-listed or never-block (a spoofed gateway or admin IP cannot get a device isolated).
* The executor checks these again, so a tampered decision still cannot block the router.
* At most `max_active_blocks` (256) blocks and isolations are active at once; temporary blocks expire. This limits the damage if an attacker spoofs many source addresses.
* The policy can only choose actions written in `policy.yaml`. An AI model never picks an action.
* Commands are built as argument lists from validated `ipaddress` objects. A future real executor must pass the list to the operating system without a shell.
* `dry_run: false` is rejected on purpose. Turning on real blocking is a code change that needs review (run as root, remove expired rules, survive a restart).

## Known limitations (for the threat model)

* **Spoofed trusted source.** Faking an allow-listed or trusted address (for example the gateway) cannot get it blocked and cannot get the protected device isolated: both actions are skipped with the reason `source_allow_listed`. An incident is still recorded and the administrator is still notified, so a person decides. The attacker also lowers the risk score by up to about 7 points this way, which is a known limitation.
* **Spoofed victim.** An attacker can fake the address of a legitimate outside server that is not on the allow-list (a cloud service or DNS server the camera uses) to get it blocked. The block is temporary at High and the active-block cap limits a flood. Add the addresses the devices depend on to `allow_list`.
* **State is in memory.** Active blocks are forgotten when the program restarts. The log keeps the history.
* **Slow attacks** that stay under the detector's thresholds never reach the policy as attacks.
