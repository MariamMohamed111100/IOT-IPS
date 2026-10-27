# IoT-IPS

A simulated **intrusion prevention system for IoT devices**, built as a graduation project. It sits (conceptually) between a device such as a camera and the network, reads network events, decides whether they are attacks, scores the risk, chooses a response, stores an incident and writes a report.

This version works on a CSV of events and **simulates** every response: no real firewall command ever runs, and blocks and isolations are written to an action log as dry runs. The Raspberry Pi deployment, live blocking and dashboard are future work.

```
CSV event ─> detector ─> risk engine ─> policy ─> incident database (saved first) ─> actions ─> reports
```

## Quick start

Python 3.10 or newer.

```bash
git clone <repository-url> && cd IoT-IPS-SmartHomes-commercials--main/ips
pip install -e ".[dev]"          # or: pip install -r requirements.txt

python run_demo.py        # events -> incidents -> summary -> integrity check
python -m pytest          # all unit tests
```

Look at the stored incidents:

```bash
iot-ips show                           # table plus count by level
iot-ips show --level Critical
iot-ips show --full INC-00003          # one incident with its three reports
iot-ips verify                         # detects edited or deleted incidents
```

`make test` and `make demo` do the same. Details of every command: [docs/pipeline.md](docs/pipeline.md).

## Who owns what

| Person | Area | Files |
|---|---|---|
| 1 | Architecture, contract, device profiles, policy table, threat model | `docs/`, `config/devices.json` |
| 2 | Data and sample events | `data/`, `scripts/data/` |
| 3 | Rule-based detector (validated rules file, inbound/outbound direction) | `src/iot_ips/detector.py`, `config/detector_rules.yaml`, `tests/test_detector.py` |
| 4 | Risk engine, weight comparison, calibration on normal traffic | `src/iot_ips/risk.py`, `config/risk_weights.yaml`, `src/iot_ips/baseline.py`, `scripts/calibrate.py`, `docs/risk-weights.md`, `docs/calibration-report.md` |
| 5 | Policy and simulated actions | `src/iot_ips/policy.py`, `src/iot_ips/actions.py`, `config/policy.yaml` |
| 6 | Pipeline, incident database (save first, then act; grouping), CI | `src/iot_ips/pipeline.py`, `src/iot_ips/db.py`, `run_demo.py`, `.github/workflows/ips-tests.yml` (repository root) |
| 7 | Reports and notifications | `src/iot_ips/report.py`, `examples/sample_reports/` |

What changed after the deep review, and what is still open: [docs/review-fixes.md](docs/review-fixes.md).

## What it does

| Stage | Module | Configuration |
|---|---|---|
| Detect attacks with threshold rules (DoS, brute force, port scan, unexpected port/protocol) and MITRE ATT&CK tags | `detector.py` | `config/detector_rules.yaml` |
| Score the risk 0-100 from confidence, attack severity, device criticality, persistence and source trust | `risk.py` | `config/risk_weights.yaml` |
| Choose actions with ordered rules, an allow-list and safety checks | `policy.py` | `config/policy.yaml` |
| Carry out the actions as a simulation: iptables commands in dry-run mode, written to an action log | `actions.py` | `config/policy.yaml` |
| Store incidents in SQLite with a tamper-evident hash chain | `db.py` | - |
| Write a technical report, an executive summary and an alert for High and Critical incidents | `report.py` | - |

Device profiles (type, address, criticality, expected ports and protocols) are in `config/devices.json`.

## Repository layout

```
src/iot_ips/     the package: one module per stage, plus pipeline.py (the iot-ips command)
config/          detector rules, risk weights, policy rules, device profiles
tests/           unit and integration tests (pytest)
data/            CICIoT2023 training and test data, sample_events.csv (the demo input)
scripts/         weight comparison, sample-report builder, chain demo, dataset build and checks
docs/            architecture, pipeline, rules, weights, action log format, known limitations
examples/        reference outputs: sample reports and a demo incident database
run_demo.py      one-command demo
```

## Results on the sample events

The 14 sample events contain 4 benign events and 10 attacks. The rule-based detector raises no false alarm on the benign events, and 7 of the 10 attacks are detected and, because repeated events from one source are grouped, become 6 incidents (2 Medium, 1 High, 3 Critical). Two missed attacks are web attacks hidden in normal-looking traffic and one is a fast upload with few connections; two slow attacks are caught only because their port is unexpected. The thresholds were tuned while looking at these events, so this shows that the chain works, not how accurate it is. See [docs/known-limitations.md](docs/known-limitations.md).

## Documentation

[docs/](docs/README.md) - architecture, pipeline and incident database, detector rules, risk weights, action log format, known limitations. The dataset is described in [data/README.md](data/README.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Team

| Name | Area |
|---|---|
| | Architecture and documentation |
| | Data (CICIoT2023) |
| | Rule-based detector |
| | Risk engine |
| | Policy engine and actions |
| | Pipeline and incident database |
| | Reporting and notifications |
