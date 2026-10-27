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
            │                                  │
            │ MQTT over TLS (8883)             │
            ▼                                  ▼
      ┌───────────┐                  ┌────────────────────┐
      │ Mosquitto │                  │ services/ips_cyber │
      │  + ACLs   │                  │ iot_ips: detector  │
      └─────┬─────┘                  │ → risk → policy    │
            │                        └─────────┬──────────┘
            │ home/.../event                   │ security/alerts/cyber
            ▼                                  ▼
      ┌───────────┐   security/risk      ┌───────────┐
      │  engine   │◄─────────────────────│   API     │──► PostgreSQL
      │ risk +    │   security/incidents │ REST + WS │
      │ incidents │─────────────────────►│           │──► dashboard (8080)
      │ actions   │   home/.../cmd       └───────────┘
      └─────┬─────┘
            ├──► cyber (block IP)
            └──► vision (security/alerts/vision)
```

## Repository structure

```text
.
├── .github/workflows/          # CI (lint, tests, secret scan, Docker smoke), CodeQL, IPS tests
├── config/                     # risk_scores.yaml, zones.yaml, ips_devices.json
├── contract/                   # contract v1.2 JSON schemas
├── docker/                     # shared Python service Dockerfile
├── docs/                       # backend, contract, demo, integration and handover docs
├── infra/                      # generated certs (ignored), Mosquitto, ntfy
├── ips/                        # IoT-IPS Python package
│   ├── config/                 # devices, detector rules, risk weights, policy
│   ├── data/                   # CICIoT2023 subset + samples + expected results
│   ├── docs/                   # design document, calibration and rule docs
│   ├── examples/demo/          # hash-chained demo DB and action log
│   ├── scripts/                # evaluate, calibrate, compare, make_samples, demo_chain
│   ├── src/iot_ips/            # detector, risk, policy, actions, pipeline, db, report
│   └── tests/                  # unit + integration tests
├── libs/common/                # shared MQTT/TLS, events, crypto, topics, runtime helpers
├── scripts/
│   ├── ips/                    # IPS → backend adapter, seeding, fake publisher, e2e check
│   ├── demo_incident.py        # proposal garage-intruder incident, end to end
│   ├── setup.sh                # secrets → certs → MQTT users (safe to re-run)
│   ├── smoke-test.sh           # live verification of the whole stack
│   └── validate_contract.py    # contract + config consistency checks
├── services/
│   ├── api/                    # FastAPI: REST, WebSocket, audit, storage
│   ├── cyber/                  # Suricata consumer + blocklist/iptables
│   ├── engine/                 # risk, correlation, incidents, response actions
│   ├── frontend/               # Warden dashboard (static page + nginx proxy)
│   ├── ips_cyber/              # IoT-IPS network sensor service (PCAP/CSV/live)
│   ├── simulators/             # virtual home devices + scenario runner
│   └── vision/                 # YOLO, face recognition, fire/smoke detection
├── docker-compose.yml
├── Makefile
├── ruff.toml
├── .env.example
├── .gitignore
└── README.md
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
make demo-scan                                   # nmap scan → cyber.port_scan → block
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

IPS → Warden end-to-end:

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

- [`docs/BACKEND_README.md`](docs/BACKEND_README.md) — backend details and message flow
- [`docs/CONTRACT.md`](docs/CONTRACT.md) — event/command/risk/incident contract
- [`docs/IPS_INTEGRATION.md`](docs/IPS_INTEGRATION.md) — IPS → engine integration and scoring bands
- [`docs/IPS_WARDEN.md`](docs/IPS_WARDEN.md) — dashboard behaviour for IPS alerts
- [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) — presentation script
- [`ips/README.md`](ips/README.md) — IoT-IPS package usage

## Status

- Backend, IoT-IPS and the dashboard are implemented and tested together.
- `services/ips_cyber` publishes scored `cyber.*` alerts; the engine enriches them with MITRE
  technique, IPS score and technical/executive reports before opening an incident.
- All local suites (backend, IPS, IPS sensor, engine, dashboard) pass with no failures or skips.
