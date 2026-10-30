# ml (Person 2, Task 6): an ML model on features we can really compute

`ids_ml` turns packets into the 39 CICIoT2023 features (`extractor.py`, which follows the dataset authors' own
converter rule by rule) and judges a 10-packet window with a Random Forest on 16 of them (`detector.py`,
same `detect(event, profile)` interface as the rule-based detector). `combined.py` puts the rules and the model
together for the pipeline.

| Step of the task | Status |
|---|---|
| 1. List the features the extractor can produce; train only on those | Done: 39 features; the model uses 16 (`features.py`) |
| 2. Check the extractor against the dataset on CICIoT2023 PCAPs | Done on one capture: on `CommandInjection.pcap` (54,083 packets) all 39 features equal the dataset's CSV (`evidence/extractor_check.csv`). One capture, one attack type |
| 3. Train and evaluate the binary model | Done (`evidence/results.md`), with the caveats below |
| 4. Expose `detect(event, profile)` | Done (`ids_ml.detector.detect`, `ids_ml.combined.make_detect`) |
| Pitfall: test beyond the random split | Partly: unseen-attack test done; the **lab-traffic test is still open** (Task 8) |

## Run it

```bash
pip install -e ips && pip install -e services/ml      # Python 3.11+; scikit-learn is pinned to 1.9.1
cd services/ml && python -m pytest                    # 28 tests (1 needs the dataset's big PCAP and is skipped without it)
python scripts/try_samples.py                         # the 14 demo events -> evidence/samples_result.md
python scripts/train_model.py                         # retrain (needs ips/data/train.csv and test.csv), rewrites MODELS.sha256
python scripts/compare_pcap.py pcap/CommandInjection.pcap pcap/CommandInjection.pcap.csv   # step 2 (the PCAP is 27 MB, not in git)
```

In the IPS service: `python services/ips_cyber/main.py --source csv --file ips/data/sample_events.csv --devices ips/config/devices.json --detector combined`.

## How it is used: rules first, the model as a second opinion

| Rules say | Model says | Result |
|---|---|---|
| ATTACK | anything | the rules' answer; a note says whether the model agrees |
| BENIGN | ATTACK with confidence >= 0.90 | ATTACK from the model (`detector: "ml"`) |
| BENIGN | anything else | BENIGN |

Why not the model alone: on the 20,000 normal windows of the test part it flags **5.7%** as attacks. In a real
home that is a false alarm every few minutes. At confidence 0.90 it is **0.1%**, and it still catches 68% of the
attacks. On the 14 demo events the rules alone get 11 labels right (they miss EVT-007, 012, 013), the combination
gets 13, and no normal event is flagged (the model alone flags EVT-001 and EVT-002). That is 14 events, not
a measurement: it is why the lab test matters.

The model's attack groups are mapped onto the four event types of the contract (`ips_cyber/envelope.py`):
Recon -> `cyber.port_scan`, BruteForce -> `cyber.brute_force`, DDoS, DoS, Mirai -> `cyber.dos`,
Spoofing and Web -> `cyber.unexpected_traffic`. The risk engine already knows all seven names.

**On PCAP and live traffic** (`ips_cyber --detector combined --ml-windows`): `ids_ml/live.py` cuts the packets into
windows of 10, computes the same features as `extractor.py`, and ties each window to the device it talks to and to the
other end (who spoke first decides inbound or outbound). The service then gates the alerts of windows: **3 flagged
windows** of the same (device, source, attack type) within 30 s raise ONE alert, then that key is quiet for 30 s.
Why: on a synthetic capture with ordinary request/response traffic the model flagged 3 of 8 normal windows at 0.90
(Spoofing, Recon), while a SYN flood gave 30 of 30 DoS windows; one window is not evidence. This is a synthetic test, not
a measurement: the real false-alarm rate on home traffic is still unknown and needs the lab capture (`docs/LAB.md`).
The flow events keep running next to the windows, so the rules still see failed logins, ports and connections.

## Results, honestly

Test part: 40,000 rows never used for training (`evidence/results.md`).

| | At 0.50 (as trained) | At 0.90 (as used) |
|---|---|---|
| False alarms on normal windows | 5.7% | 0.1% |
| Attacks caught | 83.5% | 68.1% |

- **The test part is not fully unseen.** 14% of the test rows have exactly the same 16 feature values as a training
  row (66% of DDoS, 52% of DoS, 41% of Mirai rows, a few % of the rest). On the rows the model has never seen,
  F1 is **0.839**, not 0.883 (recall 0.778, precision 0.910). Floods are caught almost perfectly either way.
- **The test part is half attacks.** A home is almost all normal traffic, so precision in real use is far lower than
  the 0.936 in the table; this is the main reason for the 0.90 rule above.
- **Quiet attacks are hard** (Recon 50%, BruteForce 67%, Web 70% at 0.5). Hidden from training, Recon is flagged
  30% of the time, BruteForce 40%: a new kind of quiet attack is often missed by the model alone.
- **A window-size shortcut was found and removed.** The dataset used 100-packet windows for floods and 10 for the
  rest, so `Number = 100` meant "flood" and the model used it. `Number` and `Tot sum` are not features any more.
- `IAT` depends on how busy the whole network is; the lab test must show that it carries over (without it F1 0.875).
- The dataset's PCAP check covers one attack type; the extractor's `Rate` and `IAT` agree on 98.5% of rows when the
  capture is read as one stream (live), 100% when cut in 10 MB pieces as the dataset did.

## Safety

`.joblib` files are pickles: loading one runs its code. `models/MODELS.sha256` holds the hash of each model and
`detector.py` checks it **before** loading; a changed file raises `ModelIntegrityError`. Retraining rewrites the
hash file, so review a change to it like a code change. The models are 38 MB; if the repository gets heavy, move
them to Git LFS or a release asset (the hash check stays the same).

## Files

`ids_ml/` the package (`detector.py`, `extractor.py`, `features.py`, `combined.py`, `models/`),
`scripts/` (train, try on samples, compare with a PCAP, check formulas on the raw dataset: Person 2 only),
`evidence/` (results, extractor check, definitions check, the 14 sample results), `tests/`.
The data (`train.csv`, `test.csv`, `sample_events.csv`) is the IPS data in `ips/data/`, not a copy.
