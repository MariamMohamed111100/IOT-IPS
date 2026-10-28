# Engine (Person 6): risk, correlation, response

Listens to device events and the vision/cyber alerts, keeps a decaying risk score, opens an
incident, and reacts (lights, siren, IP block, notification). Rules live in
`config/risk_scores.yaml`; behaviour is described in `docs/CONTRACT.md` section 9.

    eng/policy.py    load + validate the YAML, strict attacker-IP checks
    eng/scoring.py   decaying score, repeat cap, correlation, main zone
    eng/registry.py  which devices exist (from retained `status` messages)
    eng/core.py      Engine: events in -> risk / incident / commands / block out (no MQTT inside)
    eng/ips.py       IPS details: validates the adapter's `details`, or builds them with iot_ips (optional)
    eng/notify.py    ntfy.sh / Telegram (optional, dry-run when unset)
    eng/service.py   MQTT glue: mTLS connect, re-subscribe on reconnect, 5 s tick, heartbeat

Run the tests: `pytest services/engine/tests -q` (no broker needed).
Try it: `make demo-incident` (the script stages vision + cyber; the engine decides).

Notifications (optional, free): set `NTFY_TOPIC` (install the ntfy app, subscribe to that topic)
or `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` in `.env`. Unset = messages are logged only.

Safety choices: Critical never locks anyone in; doors unlock only for fire/smoke/gas. The engine
cannot block loopback, multicast or link-local addresses, nor anything in `never_block`.

## IPS alerts (docs/IPS_INTEGRATION.md section 7)

- `cyber.dos`, `cyber.unexpected_traffic`, `cyber.port_scan`, `cyber.brute_force` score by points as any other event;
  the incident level always comes from the points.
- `data.details` (MITRE tag, IPS score and level, technical and executive report) is checked against
  `contract/incident_details.schema.json` and copied into the incident (the strongest alert wins). An alert
  with no details gets them from the IPS chain (risk engine, policy in dry-run, reports) when the `iot_ips`
  package is installed (`WITH_IPS=1` in the Docker build, set for `engine` in compose). Without it the engine
  works as before and the incident has no details. The chain never runs an action; only `block_ip` blocks.
- An alert with `direction: outbound` never puts its `src_ip` (our own device) on the block list.
- `cyber.block_applied` / `cyber.block_refused` have no points, so they are never scored or blocked. For an address the
  engine asked to block they add a note to the incident ("block confirmed" / "block refused"), which closes the loop.
- Not done here: storing IPS incidents in the IPS hash-chained database (the API already keeps the incident and
  its details), and using the IPS score to lift the incident level (section 8 of the integration file).
