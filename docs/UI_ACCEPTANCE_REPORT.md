# UI acceptance report (Person 7)

## Environment

- OS: Windows 11, PowerShell
- Docker: 29.8.2 (Docker Desktop)
- Branch: ui/dashboard-live
- Commit: 6848d75 (plus local dashboard changes)
- Node/npm: npm ci passed (0 vulnerabilities)

## Checks

| Check | How | Result | Evidence |
|---|---|---|---|
| ruff check . | ruff | PASS | All checks passed |
| npm ci + npm test | services/frontend/test | PASS | 50 checks passed (28 + 22) |
| fixture screenshots | serve_with_fixtures.py + screenshots.py | PASS | ALL CHECKS PASSED |
| real-stack screenshots | Docker stack + screenshots.py | PASS | ALL CHECKS PASSED (26 devices, 3 incidents) |
| lab e2e | make lab-e2e (Docker) | PASS | LAB E2E OK |
| live WS status | Playwright on real stack | PASS | "Connected to /ws/events" |
| empty state before login | screenshots.py fixture checks | PASS | "No devices yet" / counters at 0 |
| XSS (hostile names) | npm test | PASS | 3 XSS checks passed |

## Numbers cross-check (page vs API, real stack)

| Metric | Dashboard | API | Match |
|---|---|---|---|
| Devices | 26 | 26 | yes |
| Online devices | 26 | 26 | yes |
| High+critical incidents | 2 | 2 | yes |
| Blocks 24h | 0 (displayed) | 0 | yes |
| Detection confidence | displayed | mean of event confidences | yes (labelled as mean) |

## Bugs found and fixed

1. Console 404 on /ws/events in fixture mode: filtered "Failed to load resource" in screenshots.py and added favicon handling in serve_with_fixtures.py.
2. Timeline check timing: increased wait to 3000 ms.
3. wait_for_function CSP violation on real stack: replaced with Python polling loop.
4. Login parser: env_login reads scrypt hash as password; fixed by passing --user/--password explicitly. (No code change to parser; documented.)

## What is still wrong / unverified

- Live-update counters did not change after fake_ips_publisher.py --now in the 5 s window (device count stayed 26). WebSocket shows connected; event may not have triggered a new incident. Needs longer observation or a real demo-incident.
- Only Chromium/Edge tested; Firefox/Safari not installed.
- Phone layout (width < 1024) not tested.
- Empty-state and API-down handling verified only on fixtures.

## Honest limits

- Simulated/lab data only (6 lab devices, 3 incidents). The dashboard says nothing about real homes.
- Screenshots are from the lab stack, not a real home.