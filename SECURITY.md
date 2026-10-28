# Security Policy

## Supported Versions

This project is a graduation prototype; only the `main` branch is actively maintained.

| Branch | Supported |
| --- | --- |
| `main` | :white_check_mark: |
| any other branch or fork | :x: |

## Reporting a Vulnerability

If you discover a security issue, please report it **privately** through GitHub's
[private vulnerability reporting form](https://github.com/MariamMohamed111100/IOT-IPS/security/advisories/new)
(repository **Security** tab → **Advisories** → **Report a vulnerability**), or by
emailing the maintainers. Do **not** open a public issue with exploit details.

Please include:

- the affected component (service, script or image) and the version/commit,
- a description of the vulnerability and its impact,
- step-by-step reproduction instructions or a proof of concept,
- any suggested remediation.

## Disclosure Policy

We aim to acknowledge a vulnerability report within 72 hours and to coordinate the
fix and the public disclosure with the reporter. We will keep you informed of the
progress and credit you in the advisory unless you prefer to stay anonymous.

## Scope

**In scope:** the code in this repository (API, engine, vision, cyber, IoT-IPS and
the dashboard) and the Docker images built from it.

**Out of scope:** third-party images and services referenced by
[`docker-compose.yml`](docker-compose.yml) (Mosquitto, PostgreSQL, Suricata, ntfy)
and any deployment of this prototype on a public network.
