# ips_cyber - network flows to IPS alerts (Task 3)

Turns network traffic into the alerts the backend understands. Two sources, one path:

    PCAP file  -> flow_engine (flows, 60 s sliding window per direction/device/source) -> event
    CSV events ------------------------------------------------------------------------> event
    event -> iot_ips.detector.detect() -> envelope.build_alert() -> MQTT security/alerts/cyber

The detector is the one in `ips/` (rules in `ips/config/detector_rules.yaml`), so the
service, the evaluation script and the demo always agree. An ML model can replace it through
the `detect_fn` argument of `IpsCyberService`.

## ML windows (`--ml-windows`)

With `--detector combined --ml-windows` on a `pcap` or `live` source, the packets also feed `ids_ml.live` (10-packet windows with a device and a source address). Window alerts need 3 flagged windows within 30 s and are limited to one per 30 s per (device, source, type); see `services/ml/README.md`. Needs `pip install -e services/ml`; the lab gateway image has it (`lab/gateway/Dockerfile`).

## Run

    pip install -e ips && pip install -r services/ips_cyber/requirements.txt
    cd services/ips_cyber
    D=../../ips/config/devices.json
    python main.py --source pcap --file capture.pcap --devices $D --publisher file --out out.jsonl   # no broker
    python main.py --source csv --file ../../ips/data/sample_events.csv --devices $D --publisher file --out out.jsonl   # 7 alerts
    python -m pytest tests

With MQTT, set the broker variables (see `ips_cyber/publisher.py`) and use `--publisher mqtt`.
Exit code 2 means a bad config or input file.

## Decisions

- **Contract first.** Every alert is checked against `contract/ips_event_data.schema.json`
  (11 data fields). `duration` defaults to 0; a protocol outside TCP/UDP/ICMP/GRE is refused
  and counted, never sent.
- **DoS floor 500 connections** (was 100). The flow engine counts TCP initiating SYN attempts
  (or one non-TCP attempt per flow), so a flood that reuses one source port is still visible;
  150 normal viewers or one port scan did not reach 500. At 500 the sample evaluation is unchanged.
  DoS confidence is the weaker of the flood and connection ratios.
- **Spread-out floods.** Per-source grouping misses a flood from thousands of spoofed
  addresses, so `tick()` also emits one aggregate inbound event per device (`src_ip` 0.0.0.0)
  when at least `aggregate_min_sources` (20) different sources hit it. The policy never blocks
  0.0.0.0 (it is "unspecified"); the alert still reaches the admin. Tested.
- **Capture limits** (`max_packets` 5 000 000, `max_flows` 500 000) stop a huge capture from using all memory.

## Known limits

Low-rate outbound floods, slow brute force and slow scans (a few events an hour) are missed.
ESP and SCTP traffic is seen but cannot be published (contract enum). `syn_count` and TCP
`connection_attempts` count initiating SYNs, which differs from the dataset's meaning; thresholds
must still be calibrated on representative lab traffic.

## Relation to other services

`services/cyber` (Person 5) is the Suricata/iptables service and publishes `cyber.ip_blocked`;
this one only detects. Compose runs it as `ips_cyber` with the **cyber** MQTT identity
(`security/alerts/cyber`). Default command replays `ips/data/sample_events.csv` once, then
`--idle` so the container does not loop. Live capture is `IPS_CYBER_SOURCE=live`.
