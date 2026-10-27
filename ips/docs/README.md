# Documentation

| Document | What it covers |
|---|---|
| [architecture.md](architecture.md) | Stages, messages between them, design rules, module list |
| [pipeline.md](pipeline.md) | Commands, incident table, input format, safety, results on the sample events |
| [detector-rules.md](detector-rules.md) | The four detection rules, thresholds, evasion limits |
| [review-fixes.md](review-fixes.md) | What changed after the deep review, and what is still open |
| [risk-weights.md](risk-weights.md) | The weight sets that were compared and why `balanced` was chosen |
| [calibration-report.md](calibration-report.md) | False alarms on normal traffic, threshold headroom, why nothing else was tuned, risk scale for the backend |
| [action-log-format.md](action-log-format.md) | Decision message and action log format, safety rules |
| [known-limitations.md](known-limitations.md) | What the system does not do |
| [../data/README.md](../data/README.md) | The dataset files and how they were built |
| [design/IoT_IPS_Design_Document.pdf](design/IoT_IPS_Design_Document.pdf) | The original design document (not yet regenerated, apply the addendum) |
| [design/Design_Document_Addendum.md](design/Design_Document_Addendum.md) | Changes to apply to the design document |
| [design/Integration_Checklist.md](design/Integration_Checklist.md) | Integration status and open decisions (written for the earlier folder layout) |
| [../data/expected_results.csv](../data/expected_results.csv) | Ground truth for the 14 sample events, used by `scripts/evaluate.py` |
