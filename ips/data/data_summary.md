# Data summary

Dataset: **CICIoT2023** (Canadian Institute for Cybersecurity), the provided CSV feature files, not the PCAPs. Each row is one window of packets described by 39 numeric features; labels are the 34 detailed CICIoT2023 classes, grouped into benign + 7 attack groups.

## Source files

- Merged01.csv (first part of the download): 143,502 rows, all classes mixed
- BenignTraffic_partial.csv: 173,654 rows of BENIGN
- CommandInjection.pcap.csv: 5,409 rows of COMMANDINJECTION
- DictionaryBruteForce.pcap.csv: 13,064 rows of DICTIONARYBRUTEFORCE
- MITM-ArpSpoofing_partial.csv: 193,404 rows of MITM-ARPSPOOFING
- Recon-PortScan.pcap.csv: 82,284 rows of RECON-PORTSCAN
- VulnerabilityScan_partial.csv: 124,065 rows of VULNERABILITYSCAN

Because the download server was very slow, only the first part of `Merged01.csv` and part of three per-attack files were downloaded. Every attack group is still present.

## Cleaning (what was removed)

| Step | Rows left |
|---|---|
| Loaded | 735,382 |
| Removed 30 rows with NaN or infinity | 735,352 |
| Removed 33,608 exact duplicate rows | 701,744 |
| Removed 656 rows whose identical values had both a benign and an attack label | 701,088 |
| Removed 3,774 rows repeating the same values under a different attack label | 697,314 |
| After choosing the features: removed 460 sampled rows whose selected-feature values also appear with the other label | (sample stays 200,000) |
| After choosing the features: removed 2,825 sampled rows that repeat another row on the selected features (inside a split or across train/test) | (sample stays 200,000) |
| Refilled 3,285 rows from unused cleaned rows of the same group (sizes and balance unchanged) | (sample stays 200,000) |

## Balanced sample: 200,000 rows

100,000 benign + 100,000 attack. The attack half is shared over the 7 groups: groups smaller than an equal share (Web, Mirai, BruteForce) are taken whole, the other four share the rest equally. Random seed 42.

| Group | Available after cleaning | In sample | Train | Test |
|---|---|---|---|---|
| Benign | 175,472 | 100,000 | 80,000 | 20,000 |
| DDoS | 89,392 | 18,421 | 14,732 | 3,689 |
| DoS | 22,193 | 18,420 | 14,731 | 3,689 |
| Mirai | 8,011 | 7,965 | 6,381 | 1,584 |
| Recon | 205,150 | 18,419 | 14,730 | 3,689 |
| Spoofing | 178,605 | 18,419 | 14,730 | 3,689 |
| BruteForce | 13,051 | 13,046 | 10,437 | 2,609 |
| Web | 5,440 | 5,310 | 4,259 | 1,051 |
| **Total** | 697,314 | 200,000 | 160,000 | 40,000 |

Binary balance: train 80,000 BENIGN / 80,000 ATTACK; test 20,000 BENIGN / 20,000 ATTACK.

## Train / test split

80 / 20, stratified by attack group. Duplicates were removed twice: on all 39 columns before splitting, and again on the 18 selected columns after the features were chosen (rows that differed only in dropped columns become identical once those columns are gone). Train rows were kept first, repeats and contradictory rows (same 18 values with both labels) were removed, and each split was refilled with unused cleaned rows of the same group. Where a small group had no unused rows left, a large attack group filled the gap, so the group counts above are the final ones. A check confirms that **0 rows** with the same selected-feature values appear in both train and test.

## Files

| File | Contents |
|---|---|
| `train.csv` | 160,000 rows: the 18 features + `label` (BENIGN/ATTACK) + `attack_group` + `original_label` |
| `test.csv` | 40,000 rows, same columns |
| `features.txt` | the selected features, how and why they were chosen |
| `sample_events.csv` | 14 demo events: real test rows (all 39 features) + context |

## Context fields the dataset does not have

The rule-based detector and the risk engine also need these fields. CICIoT2023 does not contain them, so in `sample_events.csv` they were added by hand to match each row's story:

- **device_id**: rows are not linked to a device; the dataset does not say which IoT device sent or received the traffic.
- **timestamp**: there is no capture time per row (the CSV files are shuffled windows).
- **src_ip, dst_ip**: addresses were removed when the PCAPs were turned into CSV features.
- **dst_port**: only protocol indicators exist (HTTP, HTTPS, SSH, DNS, ...), no port number.
- **protocol (as a name)**: only 'Protocol Type' (a number, e.g. 6 = TCP, 17 = UDP, 47 = GRE) and per-protocol shares.
- **failed_attempts**: no count of failed logins or refused connections.
- **connection_attempts**: no count of connection attempts per source.
- **unique_dst_ports, unique_dst_ips**: no count of distinct ports or hosts a source touched; the detector's port-scan rule reads these two. In the sample events they are 1 and 1, except `EVT-005` (1,000 ports) and the slow scan `EVT-006` (15 ports, under the rule's threshold of 20).

## Sample events

14 events, each a real row from the **test** part (never used for training) plus hand-written context. 4 benign, 10 attacks covering all 7 groups, including 2 evasion cases for the rule-based detector (a slow port scan, a low-rate SSH brute force). The row for each story was chosen so its real values fit: e.g. the SSH brute force uses rows with SSH traffic, the UDP flood a ~100% UDP row, Mirai a GRE (protocol 47) row. `expected_label` / `expected_attack_type` are for checking; the detector must not read them. Device ids CAM-001, THERMO-001 and PLUG-001 (IPs 192.168.1.50-52) should match the team's devices.json.

## Notes

- `Rate` was dropped from the model features as a near-copy of `IAT` (packet rate is the inverse of the time between packets). It is still in `sample_events.csv` for rules.
- `IAT` is suspected in some studies of leaking capture timing. Checked here: alone it is not among the 10 strongest single features, so it was kept.
- Feature check (Random Forest, test part): 18 features F1 0.8837 vs all 39 F1 0.8852.
- Rebuild everything with `python scripts/data/prepare_data.py`, `python scripts/data/make_sample_events.py`, `python scripts/data/write_docs.py`, then check with `python scripts/data/check_data.py`.
