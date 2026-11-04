# Changelog

All notable changes are listed here, newest first. Versions follow
[Semantic Versioning](https://semver.org/). Each release is a git tag
(`vMAJOR.MINOR.PATCH`) with a matching entry on the GitHub Releases page.

## [0.1.0] - 2026-11-04

First tagged release. A graduation prototype, verified in a simulated
environment only (tests, replayed datasets, and a Docker lab with a fake
camera and a fake attacker). It has not been tried on real IoT devices.

### What it does

- Smart-home security platform: simulated devices and traffic feed a detector
  (rules plus an ML model), a risk engine, a response policy, and a hash-chained
  incident database, shown on a live dashboard (Warden). Services talk over
  mTLS MQTT in Docker containers.
- `services/ips_cyber` reads CSV, PCAP or live traffic and publishes scored
  `cyber.*` alerts with MITRE technique, IPS score and a technical and
  executive report.
- The engine groups alerts into incidents, calculates risk, and can block an
  address. Device isolation is opt-in (`ENGINE_ISOLATION=off|shadow|on`,
  default `off`).
- The API stores incident details encrypted; Warden reads them.
- ML windows for PCAP and live traffic (`--ml-windows`): an alert needs
  3 flagged windows of the same source within 30 s. Each alert carries a
  `detector` field (`rules` or `ml`).
- Docker lab (`docker-compose.lab.yml`, `make lab-up`, `make lab-e2e`) that
  runs an attack against a fake camera end to end.

### Upgrade notes

- This is the first release, so there is nothing to migrate from.
- Event contract is v1.2 (`docs/CONTRACT.md`, `contract/`).
- The API adds a `details_encrypted` column to `incidents` on startup.

### Known limits

- Thresholds and risk weights were calibrated on synthetic traffic; the false
  alarm rate on real home traffic is unknown.
- Slow brute force or scans and low-rate outbound floods are missed
  (`ips/docs/known-limitations.md`).
- Email alerts are not implemented.

### Security

- No publicly known vulnerability with a CVE in this project's own code was
  fixed in this release. Report problems through `SECURITY.md`.
