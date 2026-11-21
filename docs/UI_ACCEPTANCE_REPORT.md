# UI acceptance report (Person 7)

## Environment

- OS: Windows 11, PowerShell
- Docker: 29.8.2 (Docker Desktop)
- Branch: ui/dashboard-live
- Commit: a0ac08921a4cfd60d99e47e69c8a3ad086c896dd
- Node/npm: npm ci passed (0 vulnerabilities)

## Checks

| Check | How | Result | Evidence |
|---|---|---|---|
| ruff check . | ruff | PASS | All checks passed (after fixes) |
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

## Checklist evidence (added)

- Wrong password: tested; login shows "Invalid username or password." (clear error). PASS.
- API-down message: TESTED. Stopping the API container made login fail with "Login failed (502)." (clear error).
- 1024/1440 widths: TESTED. Playwright viewport 1024 and 1440 both had no horizontal overflow (scrollWidth <= clientWidth).
- Confidence value in cross-check: mean of event confidences (displayed as 86.9% in fixtures).

## What is still wrong / unverified

- Live-update check: PASS without reload. Before: threats '6', alerts '50 received', first feed 'Motion Outdoor … Entrance 01:53:41', incidents 6. After: threats '6', alerts '55 received', first feed 'Motion Outdoor … Entrance 01:54:11', incidents 6. Only alert count and feed changed; threats/incidents counts stayed the same.
- Only Chromium/Edge tested; Firefox/Safari not installed.
- Phone layout (width < 1024): no horizontal overflow at 375/414/768 (tested), but full visual usability not verified.
- Live new-incident appearance: VERIFIED. Before: incidents 8, threats 8, alerts 52 received. After demo-incident: incidents 10, threats 10, alerts 234 received. New incident appeared in the list without reload. PASS.
- Phone layout: no horizontal overflow at 375/414/768 (tested). 10-11 tap targets below 40x40px on every page (icons/buttons) - known issue, not fixed.
- demo-incident: fixed (API_ADMIN_PASSWORD in .env was a hash, not plaintext; ws_listen.default_credentials now strips quotes/CR and exits with a clear message if the value is a scrypt hash). Tested on Windows only; the `.env` fix is local (`.env` is not committed), so a stale `.env` with a hash needs the plaintext password (re-run `./scripts/setup.sh` or edit it).
- Empty-state and API-down handling verified only on fixtures.

## Honest limits

- Simulated/lab data only (6 lab devices, 3 incidents). The dashboard says nothing about real homes.
- Screenshots are from the lab stack, not a real home.
