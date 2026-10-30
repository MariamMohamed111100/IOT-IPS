# Simulated IPS lab (Task 8)

A Docker lab that replaces the Raspberry Pi and the camera, and an end-to-end test that proves the whole chain.

```
 lab_attacker 10.77.0.66 --nmap / hydra / hping3-->  lab_camera 10.77.0.10  (ports 554, 443)
 lab_client   10.77.0.20 --normal requests------->        |  same network namespace
                                                    lab_gateway = ips_cyber, live capture
                                                          |  MQTT security/alerts/cyber
                                         engine -> incident -> API -> WebSocket / Warden
```

* The `lab` network is `internal: true`: no route to anything outside. `attack` also refuses a target outside `10.77.0.0/24`.
* `lab_gateway` shares the camera's network namespace, so it sees every packet. On the real Pi it becomes the container on the home network.
* In the lab the engine reads `lab/ips_devices.json` (the camera is `10.77.0.10`) and runs with `ENGINE_ISOLATION=shadow`; the CSV replay of `ips_cyber` is off.

## Run

```bash
./scripts/setup.sh                                  # once
make lab-up                                         # stack + lab (first build downloads images)
pip install websockets                              # for the WebSocket check
make lab-e2e                                        # attack, then check API and WebSocket
make lab-down
```

`scripts/ips/ips_e2e.py` runs `nmap` (port scan), `hydra` (300 wrong RTSP passwords) and `hping3` (10 s SYN flood), then checks through the REST API (after logging in):
1. alerts `cyber.port_scan`, `cyber.brute_force`, `cyber.dos` from the attacker, each with MITRE, IPS score and both reports;
2. the normal client raised no alert;
3. one incident in zone `network`, High or Critical, holds those events, and its timeline lists them;
4. the WebSocket pushed that incident.

Device isolation: the lab runs `ENGINE_ISOLATION=shadow` (the incident says "would isolate"). To see a real isolation inside the lab, add
`-f lab/isolation-on.yml` to the compose command; it sets `ENGINE_ISOLATION=on` (verified: cyber logs `ISOLATED 10.77.0.10`, `cyber.block_applied`
with `dry_run=false`). Never use it on a real home network.

CI: `.github/workflows/lab-e2e.yml` (manual, and on pull requests that touch the lab).

## Status: written, not yet run

The lab files and the e2e script were written where Docker images cannot be downloaded, so **the lab has not been started yet**.
What was checked: `docker compose config` accepts the files, the e2e logic is tested against a fake API
(`ips/tests/test_lab_e2e_logic.py`: passes on a good run, fails on each kind of bad run), and `attack` refuses targets outside the lab.
Expect to tune on the first real run:
* attack sizes against the thresholds in `ips/config/detector_rules.yaml` (DoS needs 2000 pkt/s and 500 connections; brute force 50 failed attempts on port 554);
* whether `hydra`'s `rtsp` module reaches the fake camera's 401 answers;
* the wait times in `ips_e2e.py` (`--wait`, the 10 s capture window).
