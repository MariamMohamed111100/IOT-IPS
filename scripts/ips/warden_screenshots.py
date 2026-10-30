#!/usr/bin/env python3
"""Screenshots of Warden WITH real backend data (Task 5 demo): incident list, incident detail (MITRE, IPS score, report), timeline.

    make lab-up && python scripts/ips/ips_e2e.py           # or any run that created incidents
    python scripts/ips/warden_screenshots.py [--base http://localhost:8080] [--out docs/screenshots]

It logs in through the dashboard's "API Bridge" page (the page shows mock data until you do). The password is read
from the environment or .env (API_ADMIN_PASSWORD) and is never printed or put in a screenshot (the field is
cleared before the page is photographed). Needs: pip install playwright && playwright install chromium
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ws_listen  # noqa: E402  (credential helpers shared with the websocket debug tool)

ROOT = Path(__file__).resolve().parent.parent.parent


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base", default="http://localhost:8080")
    p.add_argument("--out", default=str(ROOT / "docs" / "screenshots"))
    p.add_argument("--incident", help="incident id to open (default: the newest)")
    a = p.parse_args(argv)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        sys.exit("pip install playwright && playwright install chromium")
    user, password = ws_listen.default_credentials()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    problems = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(a.base)
        page.click('[data-view="api"]')
        page.fill("#apiUsername", user)
        page.fill("#apiPassword", password)
        page.click("#apiLoginBtn")
        page.wait_for_function("document.getElementById('apiModePill').textContent.toLowerCase().includes('live') "
                               "|| document.getElementById('apiModePill').textContent.toLowerCase().includes('connected')",
                               timeout=20000)
        page.fill("#apiPassword", "")                                  # never photograph the password
        page.click('[data-view="incidents"]')
        page.wait_for_selector("#incidentList .incident-card", timeout=20000)
        cards = page.locator("#incidentList .incident-card")
        print("incidents shown:", cards.count())
        if cards.count() == 0:
            problems.append("no incidents in the list")
        page.screenshot(path=str(out / "incident-list.png"))
        card = page.locator('[data-incident="%s"]' % a.incident) if a.incident else cards.first
        card.click()
        page.wait_for_selector("#view-incident-detail.active", timeout=10000)
        page.wait_for_selector("#incTimeline .timeline-item", timeout=10000)
        mitre = page.inner_text("#incMitre").strip()
        score = page.inner_text("#incScore").strip()
        print("MITRE panel:", mitre[:60], "| score:", score)
        if "T1" not in mitre:
            problems.append("the MITRE panel shows no technique")
        if "IPS" not in score:
            problems.append("no IPS score in the header")
        page.screenshot(path=str(out / "incident-detail.png"), full_page=True)
        page.locator("#incTimeline").scroll_into_view_if_needed()
        page.locator("#incTimeline").screenshot(path=str(out / "timeline.png"))
        browser.close()
    for q in problems:
        print("PROBLEM:", q)
    print("screenshots in", out)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
