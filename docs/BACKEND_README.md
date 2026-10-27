# SmartSecure Home

AI-powered smart home security: AI vision + cybersecurity + IoT automation + digital twin,
correlated into one risk score with automated response. Developed fully simulated first,
then moved to Raspberry Pi hardware (milestone M4).

## Quick start (any laptop with Docker and openssl)

```bash
make setup     # REQUIRED on a fresh clone: random secrets -> .env, local CA + TLS certs, MQTT users
make up        # build and start everything
make smoke     # proves mTLS + ACLs, API auth, and simulators -> broker -> API -> database -> REST
make test      # unit tests, no Docker needed (libs, simulators, API)
make lint      # ruff
```

**Windows:** run everything from **Git Bash** (not PowerShell/cmd) — the scripts are bash and
already disable MSYS path conversion themselves. **Port 8080 taken?** set `DASHBOARD_PORT` in
`.env` (setup writes it, compose reads it).

| Thing | URL |
|---|---|
| Dashboard + same-origin `/api` proxy (reverse proxy → HTTPS API, no CORS) | http://localhost:8080 |
| API docs (HTTPS, self-signed CA in `infra/certs/ca.crt`) | https://localhost:8443/docs |
| MQTT broker (TLS only) | `localhost:8883` |
| Demo rig (`docker compose --profile demo up`): RTSP | `rtsp://localhost:8554` |
| Demo rig: ntfy push notifications | http://localhost:8090 |

Debug a topic live:
```bash
docker compose exec mosquitto mosquitto_sub -h localhost -p 8883 --cafile /mosquitto/config/certs/ca.crt \
  --cert /mosquitto/config/certs/admin.crt --key /mosquitto/config/certs/admin.key \
  -u admin -P "$(grep MQTT_PASSWORD_ADMIN .env | cut -d= -f2)" -t 'security/#' -v
```

## Try it in 2 minutes

```bash
make up && make smoke                       # stack up and verified
make watch                                  # terminal 2: live device events (MQTT)
make ws                                     # terminal 3: what the dashboard receives (WebSocket)
make sim S=night_intruder                   # terminal 1: something happens in the house
make demo-incident                          # the proposal's full garage-intruder incident, checked end to end
```

Use the API (replace the password with the one in your `.env`, `API_USERS=admin:<password>`):

```bash
PW=$(grep '^API_USERS=' .env | cut -d= -f2 | cut -d, -f1 | cut -d: -f2)
TOKEN=$(curl -s --cacert infra/certs/ca.crt https://localhost:8443/auth/login \
  -H 'Content-Type: application/json' -d "{\"username\":\"admin\",\"password\":\"$PW\"}" \
  | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -s --cacert infra/certs/ca.crt -H "Authorization: Bearer $TOKEN" \
  'https://localhost:8443/events?limit=5'                       # the events your scenario created
curl -s --cacert infra/certs/ca.crt -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"action":"on","reason":"manual test"}' \
  https://localhost:8443/devices/siren_main/command             # sound the (simulated) siren
curl -s --cacert infra/certs/ca.crt -H "Authorization: Bearer $TOKEN" \
  https://localhost:8443/audit                                  # ...and see who did it
```

Swagger is at https://localhost:8443/docs while `API_DOCS_ENABLED=true`. The full endpoint list
is in `docs/CONTRACT.md` section 5.

## How the data flows

```
simulators (20 devices) --mTLS MQTT--> Mosquitto --> API --> PostgreSQL (encrypted at rest)
vision / cyber / engine --mTLS MQTT--> (alerts, risk, incidents)    |
                                                                    +--> REST + WebSocket --> dashboard
dashboard / API  --- POST /devices/{id}/command ---> .../cmd ---> simulators or real hardware
```

- The API **persists** device events, retained device status, `security/alerts/+`, risk snapshots
  and incidents. Everything arriving over MQTT is validated first; a malformed message is logged
  and dropped, never stored.
- Events and incidents are **read-only over REST** (they cannot be forged by a logged-in user).
- Every stored record has an `integrity_ok` flag; every login and device command is in `/audit`.
- After a broker restart the API re-subscribes by itself. If you change `acl.conf`, recreate the
  broker: `docker compose up -d --force-recreate mosquitto`.

## Testing

| Command | What it covers | Needs Docker |
|---|---|---|
| `make test` | `libs/common` (crypto, topics, events), simulators (HAL, scenarios, contract), API (auth, ingestion, integrity, commands, WebSocket) | no |
| `make lint` | ruff over the whole repo | no |
| `make smoke` | the real stack: mTLS and ACL checks, API auth, simulators to REST pipeline | yes |

CI runs all of them plus `gitleaks`, `pip-audit` and CodeQL on every PR. The API and simulator
suites also act as a contract test between those two modules (the API is fed real simulator traffic).

## Security model
- **Mutual TLS MQTT** (`localhost:8883`, TLS 1.3 only): the broker requires a client
  certificate signed by the local CA; the CN is the MQTT username.
  **Every container mounts only its own client cert + CA certificate**, and private keys are
  served as Docker secrets (`/run/secrets/`) — never through a bind mount. On Linux those are
  root-only (mode 0400), so `docker/entrypoint.sh` copies each secret to a world-readable
  `/run/app-secrets/` (chowned to the `app` user) before exec'ing the service as that user. The
  CA private key (`infra/ca/ca.key`) stays on the host, so a compromised service **cannot
  mint certificates** or impersonate another service, and per-service ACLs
  (`infra/mosquitto/acl.conf`) stop it reading/writing outside its lane. The smoke test
  asserts both directions: cert-less clients are refused *and* a service cannot read an
  engine-only topic.
- **JWT-protected API** (via the dashboard's `/api` reverse proxy, TLS verified against the local CA):
  `POST /auth/login` issues a token; everything but `/health` requires
  `Authorization: Bearer <token>`. Login attempts are rate-limited (5 failures/minute),
  passwords compare constant-time, and Swagger serves only with `API_DOCS_ENABLED=true`.
- **At-rest encryption (API, Person 2)**: persisted records are sealed with AES-256-GCM
  (`libs/common/smartsecure_common/crypto.py`, key `STORAGE_KEY`), bound to their record id so a
  ciphertext copied onto another row does not open. Tampering fails closed: the record is
  returned with `integrity_ok: false`, its content withheld, and an ERROR is logged.
- **Input validation + audit (API)**: every MQTT message is validated (event envelope, topic and
  zone must match, size limits, strict types) before it is stored. Events and incidents cannot be
  written over REST. Logins and device commands are recorded in an encrypted audit trail.
- **WebSocket**: authenticates with `?token=<JWT>`; the reverse proxy does not access-log `/ws/`,
  so the token never lands in a log file.
- **Fire safety policy**: `block_ip` fires from level **High** (so the demo pans out), and at
  **Critical** doors are *unlocked*, never locked (`config/risk_scores.yaml`).
- **Secrets never in git**: `.env`, certificates and MQTT passwords are git-ignored and
  excluded from Docker build contexts (`.dockerignore`). All files use LF line endings
  (`.gitattributes`). CI runs `gitleaks`, `pip-audit` and CodeQL so a leak or CVE fails a PR.
- **Dev CA caveat**: certificates are self-signed dev artifacts with finite lifetimes
  (CA 5y, leaves 397d). Rotate by deleting `infra/certs/*` (and `infra/ca/`, to re-key the
  CA) and re-running `./scripts/setup.sh`. Do not ship these to a real deployment.

## Repo layout

```
services/<module>/    one folder per module (own requirements.txt, main.py and tests/)
  api/                FastAPI: routes, mqtt_handler (ingestion), storage (encryption), audit
  simulators/         sim/ (HAL, catalog, runtime), devices.yaml, scenarios/, README.md
libs/common/          shared topics, event model, crypto, TLS MQTT helper (use it!)
contract/ config/     event schema, risk scores, zones
infra/                Mosquitto config + ACL, generated certs and CA (git-ignored)
docker/               shared Python Dockerfile + entrypoint
scripts/              setup, smoke test, watch.sh, ws_listen.py, GitHub bootstrap
docs/                 CONTRACT, BRANCHING, STANDUP, DEMO_SCRIPT
```

## Module owners (Milestone 1)

Owner-side setup (one-time, manual): enable the `main` branch-protection rule and replace the
placeholder handles in `.github/CODEOWNERS` — see `docs/BRANCHING.md`.

| # | Module | Folder | Status |
|---|---|---|---|
| 1 | Lead / DevOps / Security foundations | `infra/ docker/ scripts/ contract/` | done: mTLS broker, CI, smoke test |
| 2 | Backend API | `services/api` | done: REST, WebSocket, validated ingestion, audit |
| 3 | IoT simulation + scenarios | `services/simulators` | done: 20 devices, 4 scenarios, HAL |
| 4 | AI surveillance | `services/vision` | YOLOv8n + face recognition + motion, see `services/vision/README.md` |
| 5 | Cybersecurity | `services/cyber` | done: Suricata rules, scan/brute-force/rogue detection, IPS blocks, demo rig (see its README) |
| 6 | Risk, correlation, response | `services/engine` | done: scoring, correlation, incidents, responses (see its README) |
| 7 | Frontend / digital twin | `services/frontend` | placeholder page + reverse proxy |

Modules 4-7 plug in through the contract only: publish events to `security/alerts/<source>` (they
are stored automatically), publish `security/risk` / `security/incidents`, read state from the API.

## Configuration (`.env`, generated by `make setup`, never committed)

| Variable | Used by | Meaning |
|---|---|---|
| `POSTGRES_USER` / `POSTGRES_DB` / `POSTGRES_PASSWORD` | postgres, api | database credentials |
| `JWT_SECRET`, `JWT_ALGORITHM`, `JWT_EXPIRE_MINUTES` | api | token signing and lifetime |
| `API_USERS` | api | `name:password,name:password` login users |
| `API_DOCS_ENABLED` | api | Swagger on/off (**off in production**) |
| `STORAGE_KEY` | api | key material for at-rest encryption. **Losing it makes stored records unreadable** (they show `integrity_ok: false`) |
| `MQTT_PASSWORD_<SERVICE>` | each service | MQTT credentials (with the client certificate) |
| `DASHBOARD_PORT` | frontend | host port of the dashboard (default 8080) |
| `HAL_DRIVER`, `SIM_ALLOW_INJECT` | simulators | `sim` or `gpio`; **`SIM_ALLOW_INJECT=false` on real hardware** |

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `make smoke` fails on a service heartbeat | container crashed | `docker compose logs <service>` |
| Scenario runs but nothing appears | broker still has the old ACL | `docker compose up -d --force-recreate mosquitto` |
| `/events` is empty after a scenario | API not subscribed or event rejected | `docker compose logs api` (rejections are logged with the reason) |
| Records show `integrity_ok: false` | `STORAGE_KEY` changed, or the row was tampered with | restore the key, or `make clean` in dev (deletes all data) |
| `/zones` is empty | `config/` not mounted into the api container | check the `./config:/config:ro` volume in `docker-compose.yml` |
| Existing database lacks new indexes or tables | tables were created by an older version | the API adds missing tables and indexes on startup; `make clean` for a fresh start |
| `Permission denied` / `bad interpreter` running scripts (Windows) | line endings or lost exec bit | use Git Bash; `chmod +x scripts/*.sh`; the repo enforces LF via `.gitattributes` |
| Port 8080 or 8443 already in use | another program | set `DASHBOARD_PORT` in `.env`; stop the other program for 8443 |
| Dashboard shows "WebSocket 403" | bad/expired token, or `/ws/` not proxying the original path | reconnect (auto-reconnect is on Person 7); check `docker compose exec frontend nginx -T \| grep proxy_pass` shows `https://$api:8443;` (no trailing `/ws/`) in `location /ws/` |

## Known limitations (be honest in the demo)

- Single user tier: every logged-in user can send any device command (no roles yet, planned for M3).
- The login rate limit is in memory and keyed by `ip:username` (behind the proxy `ip` is the proxy).
  It also lets an attacker temporarily lock out a user by failing logins for that name.
- Database schema is created with `create_all` (no migrations yet): fine for development, add
  Alembic before any real data matters.
- Certificates are self-signed dev artifacts; GPIO drivers are only tested with mock pins.

## How to add dependencies or a new service
1. Add packages to your `services/<module>/requirements.txt`.
2. New MQTT user? Add it to `scripts/setup.sh`, `scripts/gen-mqtt-passwd.sh` and `infra/mosquitto/acl.conf`.
3. Read `docs/CONTRACT.md` before inventing topic names.

## Timeline (Milestone 1: 7 days)
D1 contract + skeleton | D2 modules in isolation | D3 events on MQTT | **D4 first integration** |
D5 correlation + response + timeline | D6 hardening + feature freeze | D7 demo.

## Raspberry Pi readiness
Everything is configured via environment variables and talks only through MQTT/REST, so the Pi
phase swaps simulator drivers for real ones behind the hardware abstraction layer. All base images
used here (`python:3.12-slim`, `eclipse-mosquitto`, `postgres`, `nginx`) publish ARM64 variants.
