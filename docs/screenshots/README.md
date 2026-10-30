# Warden screenshots

`incident-list.png`, `incident-detail.png` and `timeline.png` show Warden with API data: the page was logged in
through the API Bridge with `scripts/ips/warden_screenshots.py`. These three were taken against a local stand-in server
that replays the recorded API responses of `services/frontend/test/fixtures.json`, because no stack was running; they show how
an IPS incident looks (MITRE T1498, IPS score 92, technical report, timeline). To take them from your own stack:
`make lab-up && python scripts/ips/ips_e2e.py && python scripts/ips/warden_screenshots.py`.
