# Shared Contract (v1.2)

**Breaking this contract breaks someone else's module.** Change it only through a PR to this file,
approved by Person 1 and the owners of the affected modules. Code lives in
`libs/common/smartsecure_common`; use it instead of hand-writing topic strings.

## 1. MQTT topics

| Purpose | Topic | Publisher | Subscribers | QoS | Retain |
|---|---|---|---|---|---|
| Sensor/device event | `home/<zone>/<device_type>/<device_id>/event` | simulators / real devices | engine, api | 1 | no |
| Command to device | `home/<zone>/<device_type>/<device_id>/cmd` | engine, api | simulators, device | 1 | no |
| Device state/online | `home/<zone>/<device_type>/<device_id>/status` | device (LWT = `offline`) | api, engine | 1 | **yes** |
| Vision alert | `security/alerts/vision` | vision | engine, api | 1 | no |
| Cyber alert | `security/alerts/cyber` | cyber | engine, api | 1 | no |
| Engine alert | `security/alerts/engine` | engine | api | 1 | no |
| Risk state | `security/risk` | engine | api | 1 | yes |
| Incident | `security/incidents` | engine | api | 1 | no |
| IP block command | `system/block` | engine | cyber | 1 | no |
| Simulation inject | `system/sim/inject` | scenario runner | simulators | 1 | no |
| Service heartbeat | `system/heartbeat/<service>` | every service (5 s) | admin | 0 | no |

Topic tokens are lowercase `a-z 0-9 _` only. Zones are listed in `config/zones.yaml`
(`outdoor_zones` marks outdoor areas, which emit `motion.outdoor` instead of `motion.night`).
Per-service permissions are enforced by `infra/mosquitto/acl.conf`, so a compromised service
cannot publish outside its lane. **New topic = update the ACL and this table in the same PR.**

`system/sim/inject` (simulation only, disabled on real hardware with `SIM_ALLOW_INJECT=false`):
`{"device": "pir_garage", "event": "motion", "data": {}}`. Sensors never receive `.../cmd`;
scenarios only describe what happens in the house, the engine decides how to respond.

Normal temperature readings are **not** events: they arrive as retained `.../status` updates
(`state.temperature_c`, about every 10 s). Only crossing `threshold_c` emits `temperature.abnormal`,
once per crossing. Devices are marked `online:false` on a clean shutdown; after a crash the missing
`system/heartbeat/simulators` is the signal (the simulators share one MQTT connection, so a
per-device LWT is not possible).

`system/block` payload (engine→cyber, one-way command channel):

```json
{"id": "uuid", "ts": "2026-10-06T10:30:26.120+00:00",
 "ip": "203.0.113.9", "reason": "cyber.port_scan", "window_seconds": 3600}
```

`action` is optional (`"block"` by default; `"unblock"` lifts a block early, used by admin tooling,
never sent by the engine). Cyber confirms every change on `security/alerts/cyber` as
`cyber.ip_blocked` / `cyber.ip_unblocked` (not scored, section 3).

## 2. Event envelope (`contract/event.schema.json`)

```json
{
  "id": "uuid",
  "ts": "2026-10-06T10:30:26.120+00:00",
  "source": "vision",
  "type": "face.unknown",
  "zone": "garage",
  "severity_hint": "high",
  "data": {"confidence": 0.93, "snapshot": "snapshots/abc.jpg"}
}
```

Rules: `ts` is UTC ISO-8601 (never local time). `type` is `<domain>.<name>`, lowercase.
`severity_hint` is advisory; **only the engine decides the final score.**
`data` is free-form per type, but fields in the registry below are required.
Snapshots referenced in `data.snapshot` are relative to the shared `data` volume (section 9).

## 3. Event type registry

| type | Producer | Required `data` | Score (config/risk_scores.yaml) |
|---|---|---|---|
| `face.unknown` | vision | `confidence`, `snapshot` | 40 |
| `fire.detected` | vision | `confidence`, `snapshot` | 100 |
| `person.detected` | vision | `confidence` | not scored |
| `vehicle.detected` | vision | `confidence` | not scored |
| `package.detected` | vision | `confidence` | not scored |
| `motion.night` | simulators (indoor) | `sensor_id` | 20 |
| `motion.outdoor` | simulators/vision (outdoor zones) | `sensor_id` | 20 |
| `door.open` | simulators | `door_id` | 30 |
| `temperature.abnormal` | simulators | `sensor_id`, `value_c`, `threshold_c` | 20 |
| `valve.closed` | simulators | `valve_id` | 15 |
| `lock.login_failed` | simulators | `lock_id`, `attempts` | 30 |
| `camera.disconnected` | simulators/vision | `camera_id` | 35 |
| `window.open` | simulators | `window_id` | not scored |
| `smoke.detected` | simulators/vision | `sensor_id` | 100 |
| `gas.detected` | simulators | `sensor_id`, `ppm` | 80 |
| `water.leak` | simulators | `sensor_id` | 35 |
| `cyber.port_scan` | cyber | `src_ip`, `dst_ip`, `ports`, plus the IPS fields (3.1) | 25 |
| `cyber.brute_force` | cyber | `src_ip`, `target`, plus the IPS fields (3.1) | 35 |
| `cyber.rogue_device` | cyber | `mac`, `ip` | 30 |
| `cyber.ip_blocked` | cyber | `ip`, `reason`, `expires_at` | not scored |
| `cyber.ip_unblocked` | cyber | `ip` | not scored |
| `cyber.dos` | cyber (IPS) | the IPS fields (3.1) | 40 |
| `cyber.unexpected_traffic` | cyber (IPS) | the IPS fields (3.1) | 30 |
| `cyber.block_applied` | cyber (IPS) | `ip`, `action`, `device_id`, `reason`, `dry_run` | not scored |
| `cyber.block_refused` | cyber (IPS) | `ip`, `action`, `device_id`, `reason`, `dry_run` | not scored |

Vision events also carry `camera_id` and `latency_ms` (capture to publish) in `data`;
`person.detected` adds `name` when a known face matched; `face.unknown`/`fire.detected` always carry
`snapshot` unless the volume was not writable (then the alert is still sent, without it). Vision
sends `motion.outdoor` only for zones listed under `outdoor_zones`.

Adding a type: add a row here, then (if scored) a line in `config/risk_scores.yaml`.

### 3.1 IPS detection data (`contract/ips_event_data.schema.json`)

`cyber.port_scan`, `cyber.brute_force`, `cyber.dos` and `cyber.unexpected_traffic` carry these fields in
`data`. All eleven are **required**. The fields each type already had (`ports`, `target`, ...) stay.
Events still sent by the Suricata path without the new fields are valid until Person 5 adds them (see
`docs/IPS_INTEGRATION.md`, section 7).

| Field | Type | Rule |
|---|---|---|
| `src_ip` | string | IPv4 or IPv6 address that sent the traffic. The engine copies it into `system/block` **only when `direction` is `inbound`** |
| `dst_ip` | string | IPv4 or IPv6 address that received it |
| `dst_port` | integer 0-65535 | destination port; 0 when the protocol has no ports (ICMP, GRE) |
| `protocol` | string | transport protocol in capitals: `TCP`, `UDP`, `ICMP`, `GRE` |
| `direction` | `inbound` or `outbound` | `inbound`: someone talks to the device; `outbound`: the device talks to someone |
| `device_id` | string `[a-z0-9_]+` | backend device id, for example `cam_001` (mapping in `docs/IPS_INTEGRATION.md`) |
| `confidence` | number 0-1 | how sure the detector is |
| `mitre_technique` | string | MITRE ATT&CK id, for example `T1110` or `T1557.002` |
| `failed_attempts` | integer >= 0 | failed logins seen from the source in the window |
| `connection_attempts` | integer >= 0 | connection attempts seen from the source in the window |
| `duration` | number >= 0 | seconds covered by the window |

Optional: `details` (same object as in 4.4). `severity_hint` follows the IPS level (`low` to `critical`).

`cyber.block_applied` and `cyber.block_refused` report what the IPS did with a block decision. They use
`ip` (never `src_ip`), so, like `cyber.ip_blocked`, they are never scored and never re-blocked.
`action` is `block_source`, `temporary_block` or `isolate_device`; `reason` is the policy rule id
(`block_applied`) or the refusal code such as `source_allow_listed` (`block_refused`); `dry_run` is a
boolean. Optional: `expires_at`.

## 4. Payloads

### 4.1 Commands (`.../cmd`)

```json
{"id": "uuid", "ts": "...", "action": "on|off|lock|unlock|close|open", "reason": "incident-42",
 "requested_by": "admin"}
```

`requested_by` is optional: the API sets it to the logged-in user (also written to the audit
trail); the engine may omit it or use `"engine"`. Devices ignore keys they do not know.

Devices must be idempotent and publish their new state to `.../status`.

### 4.2 Status (`.../status`, retained)

```json
{"id": "uuid", "ts": "...", "state": {"power": "on", "lock": "locked", "open": false},
 "online": true}
```

`online:false` is the LWT payload. After every command the device re-publishes the full state.

### 4.3 Risk state (`security/risk`, retained, whole-state snapshots)

```json
{"ts": "...", "zone": "garage", "level": "high", "score": 85,
 "factors": [{"type": "cyber.port_scan", "weight": 25}, {"type": "motion.night", "weight": 20}],
 "actions": ["log", "notify", "lights_on", "siren", "block_ip"]}
```

`ts` only changes the payload; the topic is the versioned risk feed for the dashboard widget.

### 4.4 Incident (`security/incidents`, append-only)

```json
{"id": "incident-42", "ts": "...", "zone": "garage", "level": "high", "score": 85,
 "trigger": "cyber.port_scan", "events": ["uuid-of-event", "..."],
 "actions": ["block_ip"], "summary": "Port scan detected from 203.0.113.9 in garage"}
```

The dashboard/API persists incidents and the timeline. Engine re-sends the same `id` to update
(actions/summary) instead of creating duplicates.

Optional `details` object (`contract/incident_details.schema.json`), added by the engine when one of the
incident's events carries `data.details` (the highest-scoring one wins):

```json
{"details": {"mitre_technique": "T1110", "ips_score": 93, "ips_level": "critical", "ips_score_raw": 85,
             "reports": {"technical": "# Security Incident Report ...", "executive": "# Security Incident Summary ..."}}}
```

`ips_score` is on the scale of section 7.1; `ips_score_raw` (the IPS's own 0-100) is optional. `reports` are
plain text or Markdown of at most 12 KB each, written from untrusted event data: the dashboard must show
them as text and never as HTML. API and dashboard ignore `details` when it is absent.

## 5. REST / WebSocket

Owned by Person 2 via OpenAPI in `services/api`. The browser talks to **one origin**:
`http://localhost:8080` (dashboard). An nginx reverse proxy in front of the API relays
`/api/*` to `https://api:8443/` and `/ws/*` to the API's WebSocket (WSS), verifying the API
certificate against the local CA. No CORS configuration is needed, and WebSocket upgrades work
through the same origin.

| Browser URL | Upstream |
|---|---|
| `http://localhost:8080/` | static dashboard |
| `http://localhost:8080/api/**` | `https://api:8443/**` |
| `http://localhost:8080/ws/**` | `https://api:8443/ws/**` |
| `http://localhost:8080/snapshots/**` | shared `data` volume |

Auth: JWT bearer. Login with `POST /api/auth/login {"username","password"}` (users come from
`API_USERS`) to get a token, then send `Authorization: Bearer <token>`. Use the `require_token`
dependency in `services/api/security.py`; `/api/health` stays public. Swagger stays on the direct
API (`https://localhost:8443/docs`) and only while `API_DOCS_ENABLED=true`.

### 5.1 Endpoints (all need a JWT except `/health` and `/auth/login`)

| Method and path | Purpose |
|---|---|
| `POST /auth/login`, `GET /auth/me` | token (5 failures/min limit), current user |
| `GET /health` | `{status, mqtt_connected, db}` (public) |
| `GET /zones` | zones seeded from `config/zones.yaml` (`is_outdoor`) |
| `GET /devices?zone=` | devices with their latest state (filled from retained `.../status`) |
| `POST /devices/{id}/command` | `{action, reason}`: validated against the device type, published to `.../cmd`, audited |
| `GET /events` | newest first. Filters: `zone`, `type`, `source`, `since`, `until`, `ids=a,b,c`. Paging: `limit` (1-500, default 100), `offset` |
| `GET /events/{id}` | one event |
| `GET /incidents?zone=`, `GET /incidents/{id}` | incidents published by the engine |
| `GET /incidents/{id}/events` | the incident's events in chronological order (timeline replay) |
| `GET /risk` | latest risk snapshot per zone |
| `GET /audit` | who logged in / sent which command (`limit`, `offset`) |
| `WS /ws/events?token=<JWT>` | live push, every frame is `{"kind": "event"/"device_status"/"risk"/"incident", "data": {...}}` (uniform envelope) |

Every WebSocket frame uses the **same envelope** `{kind, data}`: the `kind` is a discriminant and the
payload sits in `data`. `event` frames carry the event envelope in `data` (`id`, `ts`, `source`,
`type`, `zone`, `severity_hint`, `data`); `device_status` frames carry `data` with `{device_id,
device_type, zone, online, state, status_id, ts}`. Dashboards must switch on `kind` only and read the
payload from `data`.

Example — event frame (`frame.data` is the event envelope, and `frame.data.data` is the per-type payload):

```json
{"kind": "event", "data": {"id": "...", "ts": "...", "source": "...", "type": "door.open",
                           "zone": "garage", "severity_hint": "low", "data": {"door_id": "door_garage"}}}
```

WebSocket close codes the dashboard must handle:

| Code | Meaning | What the client does |
|---|---|---|
| `1008` | missing/invalid token, **or the JWT expired while connected** | log in again, then reconnect with the NEW token |
| `1013` | server is full (`WS_MAX_CLIENTS`, default 100) | wait with backoff, retry |
| `1011` | the client could not keep up and was dropped | reconnect and reload state from REST |

Tokens must carry `exp` and `sub`. Each send to a client has a 2 s timeout, so one stalled client
never delays the others. See `docs/FRONTEND_HANDOVER.md` for exact frame examples.

The token is checked at connect time **and** for its lifetime: when the JWT `exp` passes, the API
closes the socket with close code **1008** and the dashboard must re-login and reconnect (do not
reconnect with the old token).

Events and incidents are **read-only over REST on purpose**: they only enter through MQTT, where
every message is validated first (event envelope, topic/zone match, size limits). A malformed
message is logged and dropped, never stored.

What the API persists from MQTT: `home/+/+/+/event`, `home/+/+/+/status`, **`security/alerts/+`**
(vision, cyber and engine alerts use the event envelope and land in the same events table),
`security/risk`, `security/incidents`.

Every record carries `integrity_ok`. `false` means it failed its tamper check: content is
withheld (`data: {}`) and an ERROR is logged. The WebSocket token is a query parameter, so the
reverse proxy does not access-log `/ws/`.

## 6. Environment variables (all services)

`MQTT_HOST`, `MQTT_PORT`, `MQTT_USER`, `MQTT_PASSWORD`, `MQTT_CA_FILE`,
`MQTT_CLIENT_CERT`, `MQTT_CLIENT_KEY`. Nothing hardcoded.

The broker requires mutual TLS: every client cert's CN is its username. Each service gets **only
its own** client cert (bind mount) and key (Docker secret) — see `docker-compose.yml`. The CA
private key (`infra/ca/ca.key`) never enters any container, so a compromised service cannot
mint certificates to bypass the ACLs.

## 7. Risk & responses (`config/risk_scores.yaml`, owned by Person 6)

`block_ip` fires from level **High** upward, so the demo's 85-point incident drops the attacker.
At **Critical**, `unlock_doors` fires — a fire is the classic Critical scenario and locked doors
would trap people. Device-specific locking remains available via a `home/.../cmd` `lock` action.

### 7.1 One level scale and the IPS score

The only published scale is `levels` in `config/risk_scores.yaml`: **low 0, medium 31, high 61, critical 91**.
The IPS works internally on 0/30/60/80 and converts its score once, at the boundary, so that its level
name never changes:

| IPS band | Level | Published band |
|---|---|---|
| 0-29 | low | 0-30 |
| 30-59 | medium | 31-60 |
| 60-79 | high | 61-90 |
| 80-100 | critical | 91-100 |

Inside a band the score is stretched linearly and rounded (an IPS 81 is published as 91, an IPS 85 as 93).
The engine's zone score still comes only from the points in `config/risk_scores.yaml`; `details.ips_score`
is shown next to it and never changes it. Reference code and examples: `docs/IPS_INTEGRATION.md`, section 5.

## 8. At-rest encryption (owned by Person 2 / API)

The API encrypts persisted records (audit trail, incidents, alert archives) with AES-256-GCM from
`libs/common/smartsecure_common/crypto.py`, keyed by `STORAGE_KEY` (generated by `scripts/setup.sh`,
never committed). Use `encrypt()`/`decrypt()` with an AAD bound to the record id (a ciphertext
copied onto another row does not open). Tampering fails closed: the API never returns garbage;
it flags the record `integrity_ok: false`, withholds the content and logs an ERROR (`api/storage.py`).
The audit trail records every login and device command with the acting user.

## 9. Shared snapshot volume

`data` named volume mounted at `/data` in `vision` (writes `snapshots/<event-id>.jpg`), `api`
(reads, exports), and `frontend` (serves under `/snapshots/`). Paths in event payloads are
relative to `/data`, e.g. `snapshots/abc.jpg`.

## 10. Deployment / demo topology

```text
browser ── :8080 nginx (dashboard + /api + /ws proxy)
                                      │
                 ┌────────────────────┼────────────────────┐
            :8443 api ──[TLS :8883]── mosquitto ──[TLS]── simulators
                 │                     │                    │
postgres            engine ─ system/block ─ cyber
                                    │  │                     │
                              security/risk               suricata (sniff)
                                    │                        │
                                 ntfy (notify)           rtsp ─ camera feeds
```

- Default `docker compose up`: api, postgres, mosquitto, simulators, vision, cyber, engine, frontend.
- `docker compose --profile demo up`: additionally starts `rtsp`, `attacker`, `suricata`, `ntfy`
  (P4/P5 demo rig). Suricata runs inline in the attacker's network namespace and sniffs its traffic.
- Networks: `default` (all services) and future `sniff` (Suricata inline plane) are declared in
  `docker-compose.yml`. Final Suricata/attacker layout is owned by Person 5; RTSP by Person 4.
- Fresh clone: **run `make setup` first** — it generates `.env`, certs and the MQTT password file.
  `docker compose up` alone intentionally refuses to hardcode dev secrets.

## 11. Engine behaviour (Person 6, `services/engine`)

Everything is configured in `config/risk_scores.yaml`; code only enforces it.

- **Input:** `home/+/+/+/event`, `home/+/+/+/status`, `security/alerts/vision`, `security/alerts/cyber`
  (never its own output). An event whose `zone` differs from its topic zone is dropped; bad JSON,
  oversized (>64 KB) or invalid envelopes are dropped and logged. Duplicate event `id`s count once.
- **Score (per zone):** a zone counts its own live events plus the house-wide `network` ones (a port scan); other zones never add to it. Sum of live event points (an event counts for `decay_minutes`; one type counts at most
  `repeat_cap` times), plus a `correlations` bonus once while all its inputs are alive, capped at
  `max_score`. Level from `levels`. The demo (20 + 40 + 25) is 85 = High with no bonus.
- **Incident:** opened at Medium or above, same `id` re-sent as it grows (`events` in order),
  closed (published once more) when the score decays to 0. One incident and one risk row per zone. Risk (`security/risk`, retained) is
  published only when score, level, zone or actions change.
- **Responses** are cumulative per level and run once per incident:
  `lights_on` = bulbs in the incident zone; `siren` = all sirens (switched off again on close);
  `block_ip` = `system/block` for each valid `data.src_ip` (never loopback/multicast/link-local/
  reserved or `never_block`); `notify` = ntfy/Telegram when configured, log otherwise;
  `unlock_doors` only when a `life_safety_events` event (fire/smoke/gas) is part of the incident,
  otherwise doors are left alone. `event_actions` (e.g. `water.leak` -> `close_valve`) run per event.
- Commands use section 4.2 with `requested_by: "engine"` and `reason: <incident id>`.
- **IPS events (v1.2):** `block_ip` skips an event whose `data.direction` is `outbound` (its `src_ip` is the
  device itself). The incident copies `data.details` from its highest-scoring event (section 4.4).
  `cyber.block_applied` and `cyber.block_refused` are not scored.

## 12. Cyber behaviour (Person 5, `services/cyber`)

All cyber events use zone `network`. Details and settings: `services/cyber/README.md`.

- **Detection:** Suricata (`services/cyber/suricata/smartsecure.rules`) writes `eve.json`; the service
  turns it into **one event per attack**, never one per packet (the engine counts every event):
  - `cyber.port_scan` `{src_ip, dst_ip, ports, port_count, hosts_probed, window_s}`: at least
    `PORTSCAN_MIN_TARGETS` distinct host:port pairs from one source inside `PORTSCAN_WINDOW_S`,
    then quiet for `PORTSCAN_COOLDOWN_S`.
  - `cyber.brute_force` `{src_ip, dst_ip, target, protocol, attempts, window_s}`: at least
    `BRUTE_MIN_ATTEMPTS` login attempts (HTTP `POST /login`, or SSH connections) against one service
    inside `BRUTE_WINDOW_S`.
  - `cyber.rogue_device` `{mac, ip, seen_via, hostname?, src_ip?}`: a MAC that asks for a DHCP lease
    (or appears in the ARP table, `ROGUE_ARP=true`) and is not in `services/cyber/known_devices.yaml`.
    `ip` is `"0.0.0.0"` until the device has a lease; `src_ip` is only present once it has one, so
    the engine can block it. Detection stays OFF while the allowlist is empty.
- **`data.src_ip` is the attacker.** The engine copies it into `system/block`. Only events that name
  an attacker carry it; `cyber.ip_blocked` uses `ip`, so confirmations are never scored or re-blocked.
- **IPS:** cyber executes `system/block` (strict IP parsing; never loopback, multicast, link-local,
  reserved or `CYBER_NEVER_BLOCK`; window clamped to `BLOCK_MIN_S`..`BLOCK_MAX_S`; at most `MAX_BLOCKS`
  at once; duplicate command ids ignored) and also blocks a confirmed scan or brute force itself
  (`CYBER_AUTOBLOCK`, default both, for `CYBER_AUTOBLOCK_S`) so the attacker is cut off before the
  risk score is even computed. Backends: `blocklist` (state file read by the demo victim; default) and
  `iptables` (real drops; needs root + NET_ADMIN, see the service README). Active blocks survive a
  restart (`/data/blocklist.json`) and expire on their own.
- **Limits:** at most `CYBER_MAX_EVENTS_PER_MIN` events per minute leave the service, and every
  piece of detector state is bounded, so a spoofed-source flood cannot exhaust memory or the
  firewall (it can only cause blocks of spoofed addresses up to `MAX_BLOCKS`, for a short time).
- **Demo rig** (`docker compose --profile demo up`): `attacker` (nmap, hydra, raw DHCP) ->
  `smartlock` (victim; also refuses blocked sources), sniffed by `suricata` in the attacker's network
  namespace. Run it with `make demo-scan | demo-brute | demo-rogue | demo-attack`.
- **IPS adapter (v1.2):** the IPS pipeline publishes its detections as `cyber.*` events (section 3.1) on
  `security/alerts/cyber` with the cyber service's identity, zone `network`. No new topic and no ACL change.
  Details: `docs/IPS_INTEGRATION.md`.
