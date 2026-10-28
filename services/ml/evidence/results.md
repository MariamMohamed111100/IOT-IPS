# Binary model results (Person 2, task 6)

Features (16, all computed by our extractor like the dataset): `Max`, `Variance`, `AVG`, `HTTPS`, `Time_To_Live`, `IAT`, `ack_flag_number`, `Header_Length`, `Min`, `psh_flag_number`, `TCP`, `UDP`, `DNS`, `syn_flag_number`, `HTTP`, `SSH`.

`Number` and `Tot sum` are left out on purpose: the dataset used 100-packet windows for floods and 10 for the rest, so they reveal the window size, not the traffic. Live windows are always 10 packets.

## Model comparison (test part, 40,000 rows)

| Model | Precision | Recall | F1 | False positives | Missed attacks | Train time |
|---|---|---|---|---|---|---|
| Random Forest (chosen) | 0.9361 | 0.8348 | 0.8825 | 5.70% | 16.52% | 12.5 s |
| Gradient Boosting | 0.9353 | 0.8351 | 0.8823 | 5.78% | 16.49% | 22.9 s |

## Confusion matrix (chosen model)

| | Predicted BENIGN | Predicted ATTACK |
|---|---|---|
| **Actual BENIGN** | 18,860 | 1,140 |
| **Actual ATTACK** | 3,304 | 16,696 |

False-positive rate 5.70%, false-negative rate 16.52%.

## What the timing feature IAT adds

With IAT (16 features) F1 0.8825; without it F1 0.8753. IAT is the time between packets of the whole network, so it also depends on how busy the network is: the lab test will show whether it carries over to our network.

## Per attack group (test part)

| Group | Correct |
|---|---|
| Benign | 94.3% |
| BruteForce | 66.8% |
| DDoS | 99.8% |
| DoS | 99.9% |
| Mirai | 99.9% |
| Recon | 50.1% |
| Spoofing | 92.6% |
| Web | 70.3% |

## Harder test: attack group never seen in training

The random split is optimistic: windows from the same capture are similar, so test rows resemble training rows. Here each attack group is removed from training and the model must still call its test rows attacks.

| Group hidden from training | Still flagged as attack |
|---|---|
| BruteForce | 40.4% |
| DDoS | 99.7% |
| DoS | 99.7% |
| Mirai | 99.9% |
| Recon | 29.7% |
| Spoofing | 58.1% |
| Web | 53.6% |

Attack-type model (for `attack_type`): accuracy 79.5%, macro F1 0.790 on the test part's attack rows.

Not yet done: testing on our own lab traffic (no lab capture exists yet).
