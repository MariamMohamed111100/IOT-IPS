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

## Live behaviour (real stack, no page reload)

- Alerts and feed update live: Live Alerts 50 -> 55 received and the first feed item changed after the fake publisher ran. Threats and incident counts did not change in that run (no new incident was created).
- A new incident appears live: before incidents 8, threats 8, alerts 52 received; after `make demo-incident` incidents 10, threats 10, alerts 234 received. PASS.

## What is still wrong / unverified

- Tap targets: fixed for HTML controls (PR #74): before 10-11 below 40x40 px per page, after 0 at 375 px. The SVG node labels in the network/twin views remain small (not safely fixable with CSS). Not checked on a real phone.
- Phone layout (375/414/768): no horizontal overflow, but full visual usability was not verified by a person on a real phone.
- Browsers: only Chromium/Edge tested. Firefox and Safari were not tested (not installed).
- `demo-incident` was fixed and tested on Windows only. `ws_listen.default_credentials` strips quotes/CR and exits with a clear message if `API_ADMIN_PASSWORD` is a scrypt hash. `.env` is not committed, so a stale `.env` with a hash needs the plaintext password (re-run `./scripts/setup.sh` or edit it).
- Empty state is verified on fixtures only. API-down (502 login error) and wrong password were verified on the real stack.

## Honest limits

- Simulated/lab data only (lab devices and lab incidents). The dashboard says nothing about real homes.
- Screenshots are from the lab stack, not a real home.
