# detect() on the 14 demo events

Each event is a real test row (never seen in training). `Right` = label and attack type both match.

| Event | Story | Expected | Got | Confidence | MITRE | Right |
|---|---|---|---|---|---|---|
| EVT-001 | The owner's phone watches the camera's live video over RTSP. | BENIGN (Benign) | ATTACK (Web) | 0.81 | T1190 | NO |
| EVT-002 | The camera uploads a recorded clip to its cloud service over HTTPS. | BENIGN (Benign) | ATTACK (Spoofing) | 0.60 | T1557.002 | NO |
| EVT-003 | The thermostat looks up its update server's address (DNS). | BENIGN (Benign) | BENIGN | 0.65 | - | yes |
| EVT-004 | The owner mistypes the smart plug's password once, then logs in. | BENIGN (Benign) | BENIGN | 0.92 | - | yes |
| EVT-005 | An unknown laptop on the Wi-Fi probes 1,000 ports of the camera in 40 s. (dst_port is the last port probed; the 985 failed attempts are refused connections to closed ports.) | ATTACK (Recon) | BENIGN | 0.73 | - | NO |
| EVT-006 | Slow scan (evasion test): 15 ports probed over 30 minutes, under any rate threshold. | ATTACK (Recon) | ATTACK (Recon) | 0.55 | T1046 | yes |
| EVT-007 | A vulnerability scanner requests 450 known-weak URLs on the plug's web page. | ATTACK (Recon) | ATTACK (Recon) | 0.97 | T1046 | yes |
| EVT-008 | 300 failed SSH logins on the camera from an external address in 4 minutes. | ATTACK (BruteForce) | ATTACK (BruteForce) | 0.92 | T1110.001 | yes |
| EVT-009 | Low-rate brute force (evasion test): 6 SSH password guesses spread over an hour. | ATTACK (BruteForce) | ATTACK (BruteForce) | 0.80 | T1110.001 | yes |
| EVT-010 | Many machines send 25,000 half-open TCP connections to the camera's video port. | ATTACK (DDoS) | ATTACK (DDoS) | 1.00 | T1498.001 | yes |
| EVT-011 | One machine floods the camera with 18,000 UDP packets per second. | ATTACK (DoS) | ATTACK (DoS) | 1.00 | T1498.001 | yes |
| EVT-012 | A rogue device poses as the router (ARP spoofing); the camera's cloud upload now passes through it. | ATTACK (Spoofing) | ATTACK (Spoofing) | 1.00 | T1557.002 | yes |
| EVT-013 | Malicious requests try to run system commands through the plug's web form. | ATTACK (Web) | ATTACK (Web) | 0.79 | T1190 | yes |
| EVT-014 | The camera is infected with Mirai and floods an outside server with GRE packets. | ATTACK (Mirai) | ATTACK (Mirai) | 1.00 | T1498 | yes |

**11 of 14 fully right.**
