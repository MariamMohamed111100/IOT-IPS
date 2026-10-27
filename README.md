# IoT-IPS — Smart Home Intrusion Prevention System

Graduation project that combines the **SmartSecure Home** backend with our **IoT-IPS** detection,
risk-scoring and response engine, plus the **Warden** dashboard.

One repository, four parts:

| Part | Where | What it is |
|---|---|---|
| **Backend** | `services/`, `libs/`, `infra/`, `config/`, `contract/`, `docker-compose.yml`, `Makefile` | API (JWT, REST, WebSocket), MQTT broker with TLS + ACLs, device simulators, `cyber` (Suricata detection and blocking), `engine` (risk, correlation, incidents, automated responses) and `vision` (YOLO / face / fire detection). Backend notes: [`docs/BACKEND_README.md`](docs/BACKEND_README.md); message formats: [`docs/CONTRACT.md`](docs/CONTRACT.md). |
| **IoT-IPS** | `ips/` | Installable Python package `iot_ips` (`ips/src`): rule-based detector, risk engine, policy and simulated actions, pipeline and hash-chained incident database, MITRE/GRC reports, calibration and evaluation tools. Start with [`ips/README.md`](ips/README.md); design document in `ips/docs/design/`. |
| **Warden dashboard** | `services/frontend/index.html` | Floor-plan digital twin, network graph, live incident list and incident detail (MITRE, risk factors, reports, timeline). Tested with `services/frontend/test`. The backend team's original dashboard is kept for reference in `services/frontend/reference/`. |
| **Link between them** | `services/ips_cyber/`, `scripts/ips/`, `docs/IPS_INTEGRATION.md` | `ips_cyber` turns PCAP/CSV/live flows into scored `cyber.*` alerts on `security/alerts/cyber`; the engine enriches them with MITRE technique + technical/executive reports. Adapter, device seeding, fake publisher and end-to-end checker live in `scripts/ips/`. |

## Architecture

```text
 simulators / real devices            PCAP / CSV / live flows
            Ã¢"â€š                                  Ã¢"â€š
            Ã¢"â€š MQTT over TLS (8883)             Ã¢"â€š
            Ã¢-Â¼                                  Ã¢-Â¼
      Ã¢"Å’Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"Â                  Ã¢"Å’Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"Â
      Ã¢"â€š Mosquitto Ã¢"â€š                  Ã¢"â€š services/ips_cyber Ã¢"â€š
      Ã¢"â€š  + ACLs   Ã¢"â€š                  Ã¢"â€š iot_ips: detector  Ã¢"â€š
      Ã¢""Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"Â¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"Ëœ                  Ã¢"â€š Ã¢â€ ' risk Ã¢â€ ' policy    Ã¢"â€š
            Ã¢"â€š                        Ã¢""Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"Â¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"Ëœ
            Ã¢"â€š home/Ã¢â‚¬Â¦/event                     Ã¢"â€š security/alerts/cyber
            Ã¢-Â¼                                  Ã¢-Â¼
      Ã¢"Å’Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"Â   security/risk      Ã¢"Å’Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"Â
      Ã¢"â€š  engine   Ã¢"â€šÃ¢-â€žÃ¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â€š   API     Ã¢"â€šÃ¢"â‚¬Ã¢"â‚¬Ã¢-Âº PostgreSQL
      Ã¢"â€š risk +    Ã¢"â€š   security/incidents Ã¢"â€š REST + WS Ã¢"â€š
      Ã¢"â€š incidents Ã¢"â€šÃ¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢-ÂºÃ¢"â€š           Ã¢"â€šÃ¢"â‚¬Ã¢"â‚¬Ã¢-Âº dashboard (8080)
      Ã¢"â€š actions   Ã¢"â€š   home/Ã¢â‚¬Â¦/cmd         Ã¢""Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"Ëœ
      Ã¢""Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"Â¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"â‚¬Ã¢"Ëœ
            Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬Ã¢-Âº cyber (block IP)
            Ã¢""Ã¢"â‚¬Ã¢"â‚¬Ã¢-Âº vision (security/alerts/vision)
```

## Repository structure

```text
.
Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ .github/workflows/          # CI (lint, tests, secret scan, Docker smoke), CodeQL, IPS tests
Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ config/                     # risk_scores.yaml, zones.yaml, ips_devices.json
Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ contract/                   # contract v1.2 JSON schemas
Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ docker/                     # shared Python service Dockerfile
Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ docs/                       # backend, contract, demo, integration and handover docs
Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ infra/                      # generated certs (ignored), Mosquitto, ntfy
Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ ips/                        # IoT-IPS Python package
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ config/                 # devices, detector rules, risk weights, policy
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ data/                   # CICIoT2023 subset + samples + expected results
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ docs/                   # design document, calibration and rule docs
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ examples/demo/          # hash-chained demo DB and action log
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ scripts/                # evaluate, calibrate, compare, make_samples, demo_chain
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ src/iot_ips/            # detector, risk, policy, actions, pipeline, db, report
Ã¢"â€š   Ã¢""Ã¢"â‚¬Ã¢"â‚¬ tests/                  # unit + integration tests
Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ libs/common/                # shared MQTT/TLS, events, crypto, topics, runtime helpers
Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ scripts/
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ ips/                    # IPS Ã¢â€ ' backend adapter, seeding, fake publisher, e2e check
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ demo_incident.py        # proposal garage-intruder incident, end to end
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ setup.sh                # secrets Ã¢â€ ' certs Ã¢â€ ' MQTT users (safe to re-run)
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ smoke-test.sh           # live verification of the whole stack
Ã¢"â€š   Ã¢""Ã¢"â‚¬Ã¢"â‚¬ validate_contract.py    # contract + config consistency checks
Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ services/
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ api/                    # FastAPI: REST, WebSocket, audit, storage
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ cyber/                  # Suricata consumer + blocklist/iptables
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ engine/                 # risk, correlation, incidents, response actions
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ frontend/               # Warden dashboard (static page + nginx proxy)
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ ips_cyber/              # IoT-IPS network sensor service (PCAP/CSV/live)
Ã¢"â€š   Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ simulators/             # virtual home devices + scenario runner
Ã¢"â€š   Ã¢""Ã¢"â‚¬Ã¢"â‚¬ vision/                 # YOLO, face recognition, fire/smoke detection
Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ docker-compose.yml
Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ Makefile
Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ ruff.toml
Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ .env.example
Ã¢"Å“Ã¢"â‚¬Ã¢"â‚¬ .gitignore
Ã¢""Ã¢"â‚¬Ã¢"â‚¬ README.md
```

## Requirements

- Docker Desktop (Linux containers) with Compose v2
- Python 3.11 or newer
- `make` and a POSIX shell (Git Bash on Windows) for the convenience targets
- Optional: `openssl` (used by `scripts/setup.sh`)

## Quick start

```bash
make setup       # generate .env with random secrets, TLS certs and MQTT users
make up          # build and start the stack
make smoke       # verify MQTT/mTLS/ACL/JWT/API/WebSocket end to end
```

| Service | URL |
|---|---|
| Warden dashboard | <http://localhost:8080> |
| API + Swagger (dev) | <https://localhost:8443/docs> |
| MQTT over TLS | `localhost:8883` |
| RTSP demo camera (demo profile) | `rtsp://localhost:8554/camera` |
| ntfy (demo profile) | <http://localhost:8090> |

The dashboard proxies `/api` and `/ws` to the HTTPS API through nginx, so there is no CORS and
WebSockets work from one origin. Login credentials are generated into `.env`
(`API_USERS=admin:<random>`); read them with:

```bash
grep '^API_USERS=' .env
```

Vision models are not committed (they are large). Download them once, then restart vision:

```bash
make vision-models
docker compose restart vision
```

## IoT-IPS package

```bash
cd ips
pip install -e ".[dev]"
python -m pytest                 # unit + integration tests
python run_demo.py               # 6 incidents, 7 attacks, verify the hash chain
python scripts/evaluate.py       # precision / recall / F1 on the labelled sample
python scripts/calibrate.py      # threshold calibration
```

## Tests

```bash
make test                                        # backend unit tests (no Docker needed)
make lint                                        # ruff

cd ips && python -m pytest                       # IoT-IPS package
python -m pytest services/ips_cyber              # IPS network sensor
python -m pytest services/engine                 # engine (risk, incidents, IPS enrichment)
cd services/frontend/test && npm test            # dashboard checks
```

The suite is expected to finish with **0 failed and 0 skipped**. The real-model vision tests need
`make vision-models` first (otherwise they are marked as skipped by design).

## Demos and scenarios

```bash
make demo-up                                     # stack + attacker / smartlock / Suricata / ntfy
make demo-scan                                   # nmap scan Ã¢â€ ' cyber.port_scan Ã¢â€ ' block
make demo-incident                               # garage intruder: risk 85/High, lights, siren, block
```

If the engine still holds risk from a previous run, restart it before the scripted incident so the
score is exactly 85:

```bash
docker compose restart engine
python scripts/demo_incident.py
```

Simulator scenarios:

```bash
docker compose exec simulators python scenario_runner.py --list
docker compose exec simulators python scenario_runner.py night_intruder
docker compose exec simulators python scenario_runner.py kitchen_fire
docker compose exec simulators python scenario_runner.py smart_lock_attack
docker compose exec simulators python scenario_runner.py water_leak
```

IPS Ã¢â€ ' Warden end-to-end:

```bash
python scripts/ips/seed_ips_devices.py --devices ips/config/devices.json
python scripts/ips/fake_ips_publisher.py --now
python scripts/ips/ips_e2e_check.py --expect 7
```

## Security notes

- `.env`, `infra/certs/*`, `infra/ca/`, MQTT passwords and private keys are **never committed**;
  `make setup` generates them.
- Vision models (`*.onnx`, `*.pt`), demo videos and face photos are ignored. `make vision-models`
  downloads the public models.
- The demo hash-chained database (`ips/examples/demo/`) and the IPS dataset
  (`ips/data/train.csv`, `ips/data/test.csv`) are committed on purpose so demos and data checks are
  reproducible.
- API docs (`/docs`) are enabled for development only; disable them with `API_DOCS_ENABLED=false`.

## Documentation

- [`docs/BACKEND_README.md`](docs/BACKEND_README.md) Ã¢â‚¬" backend details and message flow
- [`docs/CONTRACT.md`](docs/CONTRACT.md) Ã¢â‚¬" event/command/risk/incident contract
- [`docs/IPS_INTEGRATION.md`](docs/IPS_INTEGRATION.md) Ã¢â‚¬" IPS Ã¢â€ ' engine integration and scoring bands
- [`docs/IPS_WARDEN.md`](docs/IPS_WARDEN.md) Ã¢â‚¬" dashboard behaviour for IPS alerts
- [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) Ã¢â‚¬" presentation script
- [`ips/README.md`](ips/README.md) Ã¢â‚¬" IoT-IPS package usage

## Status

- Backend, IoT-IPS and the dashboard are implemented and tested together.
- `services/ips_cyber` publishes scored `cyber.*` alerts; the engine enriches them with MITRE
  technique, IPS score and technical/executive reports before opening an incident.
- All local suites (backend, IPS, IPS sensor, engine, dashboard) pass with no failures or skips.
