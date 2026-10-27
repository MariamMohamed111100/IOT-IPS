# IoT-IPS — Smart Home Intrusion Prevention System

A graduation project that unifies the **SmartSecure Home** backend with a custom **IoT-IPS** detection, risk-scoring, and automated response engine, alongside the **Warden** real-time dashboard.

The system detects, correlates, enriches, and responds to network, physical, and vision-based threats inside a smart home environment with full traceability and auditability.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Repository Structure](#repository-structure)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [IoT-IPS Python Package](#iot-ips-python-package)
- [Testing](#testing)
- [Demos & Scenarios](#demos--scenarios)
- [IPS → Warden End-to-End](#ips--warden-end-to-end)
- [Security Notes](#security-notes)
- [Documentation](#documentation)
- [Status](#status)
- [License](#license)

## Overview

This repository combines four tightly integrated components into one monorepo:

| Component | Location | Description |
|---|---|---|
| **SmartSecure Backend** | `services/`, `libs/`, `infra/`, `config/`, `contract/`, `docker-compose.yml`, `Makefile` | Core backend providing REST, WebSocket, JWT auth, audit logging, MQTT broker with mTLS & ACLs, device simulators, Suricata-based cyber defense, correlation engine, and vision inference. |
| **IoT-IPS Engine (Package)** | `ips/` | A standalone, installable Python package (`iot_ips`) responsible for rule-based network detection, dynamic risk scoring, policy enforcement, simulated response actions, a hash-chained incident database, MITRE ATT&CK mapping, and GRC-ready reports. |
| **Warden Dashboard** | `services/frontend/` | An interactive web dashboard acting as a digital twin for the smart home. It visualizes the floor plan, live network graph, active incidents, MITRE techniques, risk factors, timelines, and detailed incident reports. |
| **IPS–Backend Integration Layer** | `services/ips_cyber/`, `scripts/ips/`, `docs/IPS_INTEGRATION.md` | Bridges raw network traffic (PCAP/CSV/live) to the backend. `ips_cyber` normalizes and scores traffic using `iot_ips`, publishes `cyber.*` alerts to MQTT, and the Engine enriches them with MITRE mapping, technical/executive reports, and incident creation. |

## Key Features

- **Multi-Layer Threat Detection** – Covers network-based attacks, physical intrusion, smart-lock abuse, fire/smoke, and suspicious vision events.
- **Real-Time Risk Scoring** – Context-aware scoring based on device criticality, zone, severity, and correlated events.
- **MITRE ATT&CK Mapping** – Every cyber incident is mapped to relevant MITRE techniques for better traceability.
- **Automated Response** – Dynamic actions such as IP blocking via Suricata/iptables, alerting via `ntfy`, triggering lights/siren, and logging response history.
- **Hash-Chained Incident Ledger** – Tamper-evident incident storage with cryptographic chaining to ensure integrity.
- **Secure Communication** – End-to-end secured with MQTT over TLS (8883), ACLs, JWT authentication for API/WebSocket, and mTLS where applicable.
- **Warden Digital Twin** – Live visualization of devices, topology, zones, and active threats in a single UI.
- **Vision Intelligence** – On-device/served inference for person detection, face recognition, and fire/smoke detection using YOLO and OpenCV.
- **GRC & Reporting** – Automated generation of technical and executive reports with full incident context.
- **Reproducible Demos** – Pre-committed datasets, hash-chained demo DB, and ready-to-run attack scenarios.

## System Architecture

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

**Flow Summary:**

1. **Ingress**: Simulated/real devices publish events over MQTT over TLS, or network traffic is captured as PCAP/CSV/live.
2. **Detection**: `ips_cyber` uses the `iot_ips` package to detect, classify, and score cyber events.
3. **Enrichment & Correlation**: The `engine` correlates alerts, applies zone/criticality rules, maps to MITRE, and computes final risk.
4. **Response**: Automated actions are triggered (blocking, notifications, smart-home commands) via the `cyber` service and engine actions.
5. **Visualization**: The Warden dashboard consumes REST/WebSocket streams from the API to display live threats and incidents.

## Repository Structure

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

## Tech Stack

| Layer | Technologies |
|---|---|
| **Orchestration** | Docker, Docker Compose v2 |
| **Backend/API** | FastAPI, Uvicorn, Pydantic, WebSocket |
| **Messaging** | Eclipse Mosquitto (MQTT over TLS 1.2/1.3), custom ACLs |
| **Database** | PostgreSQL |
| **Network Security** | Suricata, iptables/blocklist integration |
| **IPS Core** | Python 3.11, Scapy, Pandas, NumPy, PyYAML, JSONSchema |
| **Vision** | Ultralytics YOLO, OpenCV, face-recognition, PyTorch/ONNX Runtime |
| **Frontend/Dashboard** | Vanilla HTML/CSS/JS, Nginx (reverse proxy for `/api` & `/ws`) |
| **Tooling/QA** | PyTest, Ruff, GitHub Actions, CodeQL |

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) with **Linux containers** and **Compose v2**
- [Python 3.11+](https://www.python.org/downloads/)
- [`make`](https://www.gnu.org/software/make/) and a POSIX shell (Git Bash recommended on Windows)
- [OpenSSL](https://www.openssl.org/) (used by `scripts/setup.sh` to generate certs/keys)

## Quick Start

### 1) Clone the repository

```bash
git clone https://github.com/MariamMohamed111100/IOT-IPS.git
cd IOT-IPS
```

### 2) Generate secrets, certificates & MQTT users

```bash
make setup
```

This will create `.env`, TLS certificates under `infra/`, and MQTT credentials securely.

### 3) Build and start the full stack

```bash
make up
```

### 4) Run end-to-end smoke tests

```bash
make smoke
```

### 5) Access the services

| Service | URL/Address | Notes |
|---|---|---|
| **Warden Dashboard** | [http://localhost:8080](http://localhost:8080) | Main UI with live incidents & digital twin |
| **API + Swagger UI (Dev)** | [https://localhost:8443/docs](https://localhost:8443/docs) | REST & schema reference (disable in prod via `API_DOCS_ENABLED=false`) |
| **MQTT over TLS** | `localhost:8883` | Secured broker for all services/devices |
| **RTSP Demo Camera (demo profile)** | `rtsp://localhost:8554/camera` | Used by vision demos |
| **ntfy (demo profile)** | [http://localhost:8090](http://localhost:8090) | Real-time push notifications |

> The dashboard proxies `/api` and `/ws` to the HTTPS API through Nginx, so no CORS issues and WebSockets work from the same origin.

**Get login credentials:**

```bash
grep '^API_USERS=' .env
```

### 6) Download vision models (required for real vision inference)

Vision models are **not** committed due to size. Download them once and restart the vision service:

```bash
make vision-models
docker compose restart vision
```

## IoT-IPS Python Package

The `ips/` directory is a fully self-contained package. You can use it independently for research, evaluation, or integration.

```bash
cd ips
pip install -e ".[dev]"

# Run unit + integration tests
python -m pytest

# Run the interactive demo (6 incidents / 7 attacks + hash-chain verification)
python run_demo.py

# Evaluate against the labeled sample
python scripts/evaluate.py

# Calibrate detection thresholds
python scripts/calibrate.py
```

Key modules under `ips/src/iot_ips/` include: `detector`, `risk`, `policy`, `actions`, `pipeline`, `db` (hash-chained), `report`, and `utils`.

## Testing

Run all test suites locally with the following commands:

```bash
# Backend unit tests (no Docker required)
make test

# Linting
make lint

# IoT-IPS package tests
cd ips && python -m pytest

# IPS network sensor service
python -m pytest services/ips_cyber

# Engine tests (risk, correlation, incidents, IPS enrichment)
python -m pytest services/engine

# Warden dashboard tests
cd services/frontend/test && npm test
```

**Expectation:** All suites must complete with **0 failed** and **0 skipped**.  
Vision tests that rely on real model weights will be **skipped by design** unless `make vision-models` has been run.

## Demos & Scenarios

### Quick attack demos

```bash
make demo-up                                     # stack + attacker / smartlock / Suricata / ntfy
make demo-scan                                   # nmap scan → cyber.port_scan → block
make demo-incident                               # garage intruder: risk 85/High, lights, siren, block
```

> If the engine retains previous risk state, restart it before running the scripted incident to guarantee a clean **Risk: 85 / High** result:

```bash
docker compose restart engine
python scripts/demo_incident.py
```

### Smart-home scenario runner

```bash
# List available scenarios
docker compose exec simulators python scenario_runner.py --list

# Run specific scenarios
docker compose exec simulators python scenario_runner.py night_intruder
docker compose exec simulators python scenario_runner.py kitchen_fire
docker compose exec simulators python scenario_runner.py smart_lock_attack
docker compose exec simulators python scenario_runner.py water_leak
```

IPS → Warden end-to-end:

```bash
# Seed IPS devices into the backend
python scripts/ips/seed_ips_devices.py --devices ips/config/devices.json

# Publish synthetic IPS alerts now
python scripts/ips/fake_ips_publisher.py --now

# Verify end-to-end delivery and count
python scripts/ips/ips_e2e_check.py --expect 7
```

Successful execution confirms that `ips_cyber` publishes scored `cyber.*` alerts, the engine enriches them with MITRE techniques, IPS scores, and technical/executive reports, and incidents appear correctly in the Warden dashboard.

## Security Notes

- **Secrets**: `.env`, `infra/certs/*`, `infra/ca/`, MQTT passwords, and private keys are **never committed**. `make setup` generates all of them locally.
- **Models & Media**: Vision weights (`*.onnx`, `*.pt`), demo videos, and face photos are ignored by Git. Use `make vision-models` to fetch public models.
- **Reproducible Artifacts**: The hash-chained demo DB (`ips/examples/demo/`) and the IPS datasets (`ips/data/train.csv`, `ips/data/test.csv`) are intentionally committed to guarantee consistent demos and evaluation.
- **API Exposure**: Swagger/OpenAPI docs at `/docs` are enabled for development only. In production, set `API_DOCS_ENABLED=false`.
- **Network Hardening**: MQTT runs with TLS + per-user ACLs. Suricata is integrated for network inspection with IP blocking capabilities.
- **Integrity**: Incidents are written to a hash-chained store to detect tampering.

## Documentation

- [`docs/BACKEND_README.md`](docs/BACKEND_README.md) — backend details and message flow
- [`docs/CONTRACT.md`](docs/CONTRACT.md) — event/command/risk/incident contract
- [`docs/IPS_INTEGRATION.md`](docs/IPS_INTEGRATION.md) — IPS → engine integration and scoring bands
- [`docs/IPS_WARDEN.md`](docs/IPS_WARDEN.md) — dashboard behaviour for IPS alerts
- [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) — presentation script
- [`ips/README.md`](ips/README.md) — IoT-IPS package usage

## Status

- **Integration**: Backend, IoT-IPS, IPS-Cyber, Engine, Vision, and Warden Dashboard are fully implemented and integrated.
- **Enrichment Pipeline**: `services/ips_cyber` publishes scored `cyber.*` alerts; the Engine enriches them with MITRE techniques, IPS scores, and technical/executive reports before creating incidents.
- **Testing**: All local test suites (Backend, IoT-IPS, IPS Sensor, Engine, and Dashboard) pass with **no failures** and **no skips**.
- **CI/CD**: GitHub Actions, CodeQL, and security workflows are configured and passing.
- **Ready for Demo & Evaluation**: Fully reproducible with committed datasets and demo assets.

## License

This project was developed as a **Graduation Project** for academic purposes. All rights reserved by the project team unless otherwise stated.
