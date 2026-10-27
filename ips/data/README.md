# Data (CICIoT2023)

## What is inside

| File | What it is |
|---|---|
| `train.csv` | 160,000 rows: 18 features + `label` (BENIGN/ATTACK) + `attack_group` + `original_label` |
| `test.csv` | 40,000 rows, same columns, no row shared with train |
| `features.txt` | the 18 features, what each means, why it was chosen, and what was dropped |
| `data_summary.md` | sources, what was removed, class balance, missing context fields |
| `sample_events.csv` | 14 events (4 benign, 10 attacks incl. 2 evasion cases): real test rows with all 39 features + context fields; the input of the demo |

Scripts in `scripts/data/`: `check_data.py` (33 checks of the files above), and `prepare_data.py`, `make_sample_events.py`, `write_docs.py` which built them.

`sample_events.csv` columns: `event_id, device_id, timestamp, src_ip, dst_ip, dst_port, protocol,
failed_attempts, connection_attempts, unique_dst_ports, unique_dst_ips`, then the 39 CICIoT2023
features, then `expected_label, expected_attack_type, original_label, story`. The `expected_*`
columns are the answers for checking results; the detector must not read them. Device ids
CAM-001, THERMO-001, PLUG-001 = 192.168.1.50 / .51 / .52 (see `config/devices.json`).

## Check the files

Needs Python 3.11 or newer and the `data` extra (`pip install -e ".[data]"`, or `pip install pandas numpy`).

```
python scripts/data/check_data.py
```

It must end with `33/33 checks passed`.

## Use the data in your own code

```python
import pandas as pd
train = pd.read_csv("data/train.csv")
events = pd.read_csv("data/sample_events.csv")
features = [c for c in train.columns if c not in ("label", "attack_group", "original_label")]
```

## Rebuilding from the raw dataset

`scripts/data/prepare_data.py`, `make_sample_events.py` and `write_docs.py` rebuild everything from the
raw CICIoT2023 CSV files (about 600 MB, not included; put them in `data/raw/`, with the partial
file `Merged01_partial.csv` and an `extra/` folder). They also need scikit-learn
(`pip install -e ".[data]" scikit-learn`). Intermediate files go to `data/interim/`. Both folders
are ignored by git. Fixed random seeds give byte-identical files.
