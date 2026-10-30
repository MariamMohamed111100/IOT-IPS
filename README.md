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
2. **Detection**: `ips_cyber` uses the `iot_ips` package to detect, classify, and score cyber events, and puts the MITRE tag, the IPS score and both reports in the alert's `data.details` (Warden reads them from the stored event).
3. **Enrichment & Correlation**: The `engine` correlates alerts, applies zone/criticality rules, maps to MITRE, and computes final risk.
4. **Response**: Automated actions are triggered (blocking, notifications, smart-home commands) via the `cyber` service and engine actions.
5. **Visualization**: The Warden dashboard consumes REST/WebSocket streams from the API to display live threats and incidents.

## Repository Structure

```text
.
├── .github/workflows/          # CI (lint, tests, secret scan, Docker smoke), CodeQL, IPS tests
├── config/                     # risk_scores.yaml, zones.yaml, ips_devices.json
├── contract/                   # Contract v1.2 JSON schemas for events/commands/incidents/risk
├── docker/                     # Shared Python service Dockerfile
├── docs/                       # Backend, contract, demo, integration, IPS-Warden and handover docs
├── infra/                      # Mosquitto config, ntfy, generated certs/CA (git-ignored)
├── ips/                        # IoT-IPS Python package (core detection, risk, policy, DB, reports)
│   ├── config/                 # Devices, detector rules, risk weights, and policy files
│   ├── data/                   # CICIoT2023 subset, samples, and expected evaluation results
│   ├── docs/                   # Design, calibration, and rule documentation
│   ├── examples/demo/          # Hash-chained demo DB and action log (committed for reproducibility)
│   ├── scripts/                # evaluate, calibrate, compare, make_samples, demo_chain
│   ├── src/iot_ips/            # detector, risk, policy, actions, pipeline, db, report modules
│   └── tests/                  # Unit and integration tests for the IPS package
├── libs/common/                # Shared MQTT/TLS, events, crypto, topics, logging & runtime helpers
├── scripts/
│   ├── ips/                    # IPS→backend adapter, device seeding, fake publisher, E2E checker
│   ├── demo_incident.py        # End-to-end garage-intruder demonstration
│   ├── setup.sh                # Generate secrets → TLS certs → MQTT users (idempotent)
│   ├── smoke-test.sh           # Full-stack live verification
│   └── validate_contract.py    # Contract & configuration consistency checks
├── services/
│   ├── api/                    # FastAPI service (REST, WebSocket, auth, audit, storage)
│   ├── cyber/                  # Suricata consumer with blocklist/IP blocking logic
│   ├── engine/                 # Risk engine, correlation, incidents, enrichment & response actions
│   ├── frontend/               # Warden dashboard (static assets + Nginx reverse proxy)
│   ├── ips_cyber/              # IoT-IPS network sensor (PCAP/CSV/live ingestion)
│   ├── simulators/             # Virtual smart-home devices & scenario runner
│   ├── ml/                     # Machine-learning detector (CICIoT2023 features, rules + model)
│   └── vision/                 # YOLO, face recognition, fire/smoke detection service
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
| **API + Swagger UI (optional)** | [https://localhost:8443/docs](https://localhost:8443/docs) | REST & schema reference — enable with `API_DOCS_ENABLED=true` |
| **MQTT over TLS** | `localhost:8883` | Secured broker for all services/devices |
| **RTSP Demo Camera (demo profile)** | `rtsp://localhost:8554/camera` | Used by vision demos |
| **ntfy (demo profile)** | [http://localhost:8090](http://localhost:8090) | Real-time push notifications |

> The dashboard proxies `/api` and `/ws` to the HTTPS API through Nginx, so no CORS issues and WebSockets work from the same origin.

**Get login credentials:**

```bash
grep '^API_ADMIN_PASSWORD=' .env   # dashboard login; API_USERS holds scrypt hashes
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
pip install -e ".[dev]"        # or: pip install -r ../requirements/ips-dev-3.12.txt --require-hashes

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
# Spin up stack + attacker/smartlock/Suricata/ntfy
make demo-up

# Port scan demo -> cyber.port_scan -> automatic block
make demo-scan

# Garage intruder demo -> High risk (85), lights, siren, block
make demo-incident
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

## IPS → Warden End-to-End

Validate the full IPS integration pipeline from ingestion to dashboard visibility:

```bash
# Seed IPS devices into the backend
python scripts/ips/seed_ips_devices.py --devices ips/config/devices.json

# Publish synthetic IPS alerts now
python scripts/ips/fake_ips_publisher.py --now

# Verify end-to-end delivery and count
python scripts/ips/ips_e2e_check.py --expect 7
```

This checks the adapter format (`fake_ips_publisher.py` builds `details` itself). The **real** path is the `ips_cyber` service that `make up` starts: it replays `ips/data/sample_events.csv` through the detector and publishes the alerts with their `details`. To check that path alone, run the e2e check without the fake publisher:

```bash
make up
python scripts/ips/ips_e2e_check.py --expect 7 --sensor-only
```

Without Docker, `pytest services/engine/tests/test_live_path.py` runs the same chain (sensor -> engine) and checks that every stored alert carries what Warden reads.

## Security Notes

- **Secrets**: `.env`, `infra/certs/*`, `infra/ca/`, MQTT passwords, and private keys are **never committed**. `make setup` generates all of them locally.
- **Models & Media**: Vision weights (`*.onnx`, `*.pt`), demo videos, and face photos are ignored by Git. Use `make vision-models` to fetch public models.
- **Reproducible Artifacts**: The hash-chained demo DB (`ips/examples/demo/`) and the IPS datasets (`ips/data/train.csv`, `ips/data/test.csv`) are intentionally committed to guarantee consistent demos and evaluation.
- **API Exposure**: Swagger/OpenAPI at `/docs` is **off** by default; set `API_DOCS_ENABLED=true` only while developing, and never on a gateway (the API port is reachable).
- **Network Hardening**: MQTT runs with TLS + per-user ACLs. Suricata is integrated for network inspection with IP blocking capabilities.
- **Integrity**: Incidents are written to a hash-chained store to detect tampering.
- **Supply chain**: every GitHub Action is pinned to a commit SHA, every Docker image is pinned to a digest — the base image of each image this repo builds (`docker/python-service.Dockerfile`, the frontend/cyber demo Dockerfiles) and every third-party service in `docker-compose.yml` (`image: name:tag@sha256:…`, kept with its readable tag) — and every `pip install` runs from a hash-pinned lock (`requirements/*.txt`, `docker/locks/*.txt`) with `--require-hashes`. Regenerate the locks with `scripts/lock-requirements.sh`; move the Compose pins forward with `scripts/pin_compose_images.py` (it verifies each digest against the registry, and `--check` reports anything unpinned).
- **Vulnerability reporting**: see [`SECURITY.md`](SECURITY.md).

## Documentation

| Document | Purpose |
|---|---|
| [`docs/BACKEND_README.md`](docs/BACKEND_README.md) | Deep dive into backend services, topics, flows, and internals |
| [`docs/CONTRACT.md`](docs/CONTRACT.md) | Full specification of the event/command/risk/incident contract (v1.2) |
| [`docs/IPS_INTEGRATION.md`](docs/IPS_INTEGRATION.md) | IPS → Engine integration details, mapping, and scoring bands |
| [`docs/IPS_WARDEN.md`](docs/IPS_WARDEN.md) | Warden dashboard behavior for IPS-generated alerts and incidents |
| [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) | Step-by-step presentation script for live demos |
| [`ips/README.md`](ips/README.md) | Usage guide for the standalone `iot_ips` package |

## Status

The project is verified in a **simulated environment**: unit and integration tests, replayed datasets, and a Docker lab with a fake camera and a fake attacker. It has **not** been tried on real IoT devices, a real camera, or real home traffic.

**What is done and checked**

- **Integration**: Backend, IoT-IPS, IPS-Cyber, Engine, Vision, and Warden Dashboard are implemented and connected.
- **Enrichment**: `services/ips_cyber` publishes scored `cyber.*` alerts with `data.details` (MITRE technique, IPS score and level, technical and executive report). The Engine passes them into the incident (and builds them only for an alert that has none), the API stores the incident `details` encrypted, and Warden reads them.
- **ML model**: `services/ml` is trained and tested. `ips_cyber --detector combined` uses it next to the rules on CSV events. On PCAP and live traffic it needs `--ml-windows`: packets are cut into 10-packet windows per device and remote address, and an alert needs 3 flagged windows within 30 s (then one alert, then 30 s quiet). The `detector` field on each alert (`rules` or `ml`) shows which one raised it.
- **Device isolation**: opt-in through `ENGINE_ISOLATION=off` (default) | `shadow` (only writes "would isolate" in the incident summary) | `on` (at Critical, for a known device that sends an attack outbound, the Engine asks `cyber` to isolate it with `direction: both`). It was tried only inside the lab; try `shadow` before `on`.
- **Docker lab**: `docker-compose.lab.yml`, `scripts/ips/ips_e2e.py` and [docs/LAB.md](docs/LAB.md) run an attack against a fake camera and check the alert, the incident and the block end to end. It was run once on Windows with Docker Desktop, and all checks passed.
- **Tests and CI**: all suites pass (Backend, IoT-IPS, IPS Sensor, ML, Engine, Dashboard, Simulators). The 12 GitHub Actions checks pass, including CodeQL and the privileged nftables job. `-m dataset` (needs the 27 MB PCAP) and the lab job `lab-e2e` (run by hand from Actions) are not part of a normal run.

**Not done / known limits**

- **No real hardware**: the false-alarm rate on real home traffic is unknown. The only measurement is zero false alarms in 30 minutes of synthetic traffic.
- **ML on real traffic**: it flagged some normal windows in synthetic traffic, which is why the 3-window rule exists. How much it adds over the rules on a long run is not measured.
- **Thresholds and risk weights** were calibrated on synthetic traffic and need a capture from a real network.
- **Missed attacks**: slow brute force or scans and low-rate outbound floods (`ips/docs/known-limitations.md`).
- **Email alerts** are not implemented. Alerts go through the dashboard and ntfy.
- **Warden screenshots** in `docs/screenshots/` come from recorded demo data.

## License

Released under the [MIT License](LICENSE). This project was developed as a **Graduation Project** for academic purposes.
