# Demo script (Day 7, about 6 minutes, rehearse twice, record a backup video)

**Before:** fresh clone on the demo laptop, `make setup && make up`, `make smoke` is all green,
dashboard open at http://localhost:8080, ntfy/Telegram on a phone visible to the audience.

| Min | Who | Action | What the audience sees |
|---|---|---|---|
| 0:00 | P1 | 30 s pitch: cyber + physical correlation, all simulated, Pi next | Digital twin, all devices green, score Low |
| 0:30 | P3 | Run scenario `night_intruder` | Garage PIR triggers, light turns on in the twin |
| 1:15 | P4 | Video clip shows a stranger | "Unknown face" alert with snapshot |
| 2:00 | P5 | `make demo-scan` (nmap from the attacker container; `make demo-brute` for hydra) | `cyber.port_scan` alert, attacker IP auto-blocked, smart lock refuses it |
| 3:00 | P6 | Point at the risk gauge | Score climbs to 85 (High), siren + notification fire |
| 4:00 | P7 | Open incident timeline | Chronological events, replay of the incident |
| 4:45 | P2 | Show Swagger + DB rows | Every event persisted, JWT-protected API |
| 5:15 | P1 | Show TLS-only broker and ACLs | Plain MQTT refused; a service can't publish outside its topics |
| 5:45 | P1 | Roadmap: Pi bring-up in M4 | HAL slide |

**Fallbacks:** if a live module fails, run its scenario from the recorded video; never debug on stage.
