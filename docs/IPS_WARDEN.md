# IoT-IPS in the dashboard: how to run and test the link

The design and the rules are in `docs/IPS_INTEGRATION.md` and `docs/CONTRACT.md` (section 3.1). In short: the IPS publishes only `cyber.*` events on `security/alerts/cyber` (zone `network`); the backend `engine` turns them into incidents; the dashboard shows the IPS details (MITRE tag, IPS score, technical and executive report) from the events of each incident.

## Try it (docker stack running: `make setup && make up`)
```bash
python scripts/ips/seed_ips_devices.py                        # registers the 6 IPS devices (config/ips_devices.json)
python scripts/ips/fake_ips_publisher.py --now                # 7 sample detections + dry-run block results
python scripts/ips/ips_e2e_check.py                           # PASS/FAIL checks through the API
python scripts/ips/test_ips.py                                # offline unit tests
cd services/frontend/test && npm install && npm test         # dashboard test (real API fixtures)
```
Open the dashboard (http://localhost:8080), then Incidents. The engine opens one incident per zone (all IPS events are in zone `network`) and adds points per event type (`config/risk_scores.yaml`).

- `fake_ips_publisher.py --list` shows the samples; `--only brute_force --repeat 3` sends one detection three times.
- Without a running engine use `--standalone` (and `ips_e2e_check.py --standalone`): it also publishes risk and incident messages so the dashboard has something to show. Do not use it next to the engine.
- Rebuild the dashboard after changing `index.html`: `docker compose up --build -d frontend`, then Ctrl+F5.

## What the engine does with our events (tested locally)
Brute force (35) and DoS (40) from the same source gave one incident in `network` with 75 points (High) and the engine's own `block_ip` response. The IPS dry-run results appear as `cyber.block_applied` / `cyber.block_refused` events and are not scored.

## Notifications
The engine sends them (ntfy or Telegram). Put the bot token and chat id in `.env` (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`).

## Still open (owners in `docs/IPS_INTEGRATION.md`, section 7)
API `details` column, engine copy of `details` into the incident and the outbound `block_ip` rule, the eleven extra fields in the `cyber` service, the real IPS pipeline adapter. The dashboard already reads `details` from the events, so it keeps working when the incident carries it.
The Devices page, the first Live Alerts entries, the Security Copilot answers and the top counters still show demo data.
