# Frontend handover (Person 7)

Everything the dashboard needs. The frames below were captured from the real API while
`make demo-incident` ran, so the shapes are exact. Full endpoint list: `docs/CONTRACT.md` section 5.

## 1. Talk only to the API, through the proxy
- REST: `/api/...` on the dashboard origin (nginx forwards to the API). Example: `/api/health`.
- Live feed: `ws(s)://<dashboard host>/ws/events?token=<JWT>`.
- Never talk to MQTT from the browser.

## 2. Login and token lifetime
```js
const r = await fetch('/api/auth/login', {method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({username, password})});            // 200 -> {access_token, token_type}
// 401 = wrong credentials, 429 = too many failures (wait 60 s)
```
Send `Authorization: Bearer <token>` on every REST call. A 401 means: log in again.
The token lives `JWT_EXPIRE_MINUTES` (default 60). Keep it in memory, not in localStorage.

## 3. The WebSocket: one switch on `kind`
Every frame is `{"kind": ..., "data": {...}}`. Only four kinds exist.

```json
{"kind":"event","data":{"id":"ac91...","ts":"2026-10-08T21:55:57.341+00:00","source":"sim.pir","type":"motion.night","zone":"garage","severity_hint":"medium","data":{"sensor_id":"pir_garage"}}}
{"kind":"device_status","data":{"device_id":"siren_main","device_type":"siren","zone":"living_room","online":true,"state":{"power":"on"},"status_id":"0989...","ts":"2026-10-08T21:55:57.383+00:00"}}
{"kind":"risk","data":{"ts":"2026-10-08T21:56:04.341+00:00","zone":"garage","level":"high","score":85,"factors":[{"type":"motion.night","weight":20},{"type":"face.unknown","weight":40},{"type":"cyber.port_scan","weight":25}],"actions":["log","notify","lights_on","siren"]}}
{"kind":"incident","data":{"id":"incident-demo-af0cdc","ts":"2026-10-08T21:56:04.341+00:00","zone":"garage","level":"high","score":85,"trigger":"face.unknown","events":["ac91...","561f...","675f..."],"actions":["log","notify","lights_on","siren"],"summary":"Garage intruder: night motion + unknown face + port scan from 192.168.1.15"}}
```
Watch out: for `event`, `frame.data` is the whole envelope and `frame.data.data` is the
type-specific payload (`sensor_id`, `door_id`, ...).

What to do with each kind:
| kind | Update |
|---|---|
| `event` | alert list / timeline; flash the zone `data.zone` |
| `device_status` | device icon by `device_id` (`state` keys: `power`, `lock`, `open`, `motion`, `temperature_c`, `stream`...) |
| `risk` | the gauge for `data.zone`; `level` is low/medium/high/critical, `score` can exceed 100 |
| `incident` | incident card; the same `id` arrives again when updated, replace it |

## 4. Initial state and reconnecting
The feed only pushes changes, so on page load and after every reconnect read the current state first:
`GET /api/zones`, `/api/devices`, `/api/risk`, `/api/incidents?limit=20`, `/api/events?limit=50`.
Then connect the WebSocket. Frames can repeat something you already loaded: dedupe by `id`.

Close codes:
| Code | Meaning | Do |
|---|---|---|
| `1008` | missing/invalid token, or the JWT expired | log in again, reconnect with the NEW token |
| `1013` | server full | retry with backoff |
| `1011` | you could not keep up and were dropped | reload state from REST, reconnect |
| anything else | network | exponential backoff 1, 2, 4... up to 30 s, then reload state |

## 5. Incident timeline
`GET /api/incidents/{id}/events` returns the incident's events in chronological order
(each has `ts`, `type`, `source`, `zone`, `data`, `integrity_ok`). Draw them as a vertical list and
replay by revealing one per `ts` delta. If `integrity_ok` is `false` show "record failed integrity
check" instead of the content.

## 6. Sending commands
`POST /api/devices/{device_id}/command` with `{"action": "on", "reason": "..."}`.
Valid actions: bulb/siren `on|off`, lock `lock|unlock`, valve `open|close`. The new state comes back
as a `device_status` frame, so update the UI from that, not optimistically.

## 7. Develop without the rest of the team
```bash
make up && make demo-incident     # fills the system with a full incident (30 s)
make ws                           # prints every frame in the terminal
```
