# Contributing

## Set up

```bash
pip install -e ".[dev]"
python -m pytest
```

## Workflow

1. Work on a branch, not on `main`: `git switch -c area/short-description` (for example `risk/weights-update`).
2. Run `python -m pytest` and `python run_demo.py` before you push. The same checks run on GitHub for every push and pull request (`.github/workflows/ips-tests.yml` at the repository root; run the commands from the `ips/` folder).
3. Open a pull request. Say what changed and why; the template has a short checklist.
4. Keep commits small, with messages that say what changed ("Raise DoS rate threshold to 2000").

## Where things live

| You change | Look at |
|---|---|
| A threshold or MITRE tag of a detection rule | `config/detector_rules.yaml`, `docs/detector-rules.md` |
| Risk weights, attack severities, trusted addresses | `config/risk_weights.yaml`, `docs/risk-weights.md` |
| Response rules, the allow-list | `config/policy.yaml`, `docs/action-log-format.md` |
| A device profile | `config/devices.json` (add the device id used by the sample events too) |
| What a sample event looks like | `data/sample_events.csv`, then `python scripts/data/check_data.py` |
| The reports | `src/iot_ips/report.py`, then `python scripts/make_samples.py` and commit `examples/sample_reports/` |

## Rules for the code

* **Keep the shared messages stable.** The event, detection, risk, decision and incident dicts are described in [docs/architecture.md](docs/architecture.md). Renaming a field breaks the stages after it; change the docs and the tests in the same pull request.
* **Treat every input as untrusted** (CSV fields, device files, configuration). Validate, limit the length, never copy free text into an output.
* **Simulation only.** Do not add code that runs a firewall command, a subprocess or a network call. `dry_run: false` is rejected on purpose; turning real blocking on needs a separate, reviewed change.
* **Write a test with every change**, and a test that fails if the change is reverted.
* **Never commit** secrets, keys, `__pycache__` or generated files from `output/`. The incident database key (`IOTIPS_DB_KEY`) is an environment variable only.
