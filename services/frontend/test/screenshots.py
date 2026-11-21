# ruff: noqa: E501
#!/usr/bin/env python3
"""Opens every dashboard page in a real browser, logs in, checks what it shows and saves a screenshot of each page.

    pip install playwright && python -m playwright install chromium        (once)
    python services/frontend/test/screenshots.py                           # http://localhost:8080, login from .env
    python services/frontend/test/screenshots.py --base http://localhost:8080 --user admin --password SECRET

Screenshots go to services/frontend/test/screenshots/. Exit code 0 = every check passed, 1 = something is wrong
(the report names it), 2 = the dashboard could not be reached or the login failed.
"""

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
PAGES = [
    "overview",
    "digital-twin",
    "network",
    "devices",
    "incidents",
    "alerts",
    "timeline",
    "copilot",
    "reports",
    "api",
]


def env_login():
    try:
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            if line.startswith("API_USERS="):
                user, _, pw = line.split("=", 1)[1].split(",")[0].partition(":")
                return user.strip(), pw.strip()
    except OSError:
        pass
    return None, None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--base", default="http://localhost:8080")
    p.add_argument("--user")
    p.add_argument("--password")
    p.add_argument("--out", default=str(HERE / "screenshots"))
    p.add_argument("--headed", action="store_true", help="show the browser window")
    a = p.parse_args(argv)
    user, pw = a.user, a.password
    if not (user and pw):
        user, pw = env_login()
    if not (user and pw):
        print("no login: pass --user and --password, or run from the repo with API_USERS in .env")
        return 2
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    problems, errors = [], []

    def check(ok, text):
        print(("PASS  " if ok else "FAIL  ") + text)
        if not ok:
            problems.append(text)

    with sync_playwright() as pw_:
        try:
            browser = pw_.chromium.launch(headless=not a.headed)
        except Exception:
            browser = pw_.chromium.launch(channel="msedge", headless=not a.headed)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.on("pageerror", lambda e: errors.append("page error: %s" % e))
        page.on(
            "console",
            lambda m: (
                errors.append("console error: %s" % m.text)
                if m.type == "error" and "WebSocket" not in m.text and "Failed to load resource" not in m.text
                else None
            ),
        )
        try:
            page.goto(a.base, wait_until="load", timeout=20000)
        except Exception as exc:  # noqa: BLE001
            print("cannot open %s (%s). Is the stack up?" % (a.base, str(exc).splitlines()[0]))
            return 2

        def open_page(name):
            sel = '.nav-item[data-view="%s"], [data-view="%s"]' % (name, name)
            page.locator(sel).first.click()
            page.wait_for_timeout(500)

        def shot(name):
            page.screenshot(path=str(out / (name + ".png")), full_page=True)

        open_page("api")  # the login form lives on the API Bridge page
        page.fill("#apiUsername", user)
        page.fill("#apiPassword", pw)
        page.click("#apiLoginBtn")
        import time as _t
        _deadline = _t.time() + 20
        while _t.time() < _deadline:
            try:
                if page.inner_text("#statDevices").strip() != "0":
                    break
                if "fail" in page.inner_text("#apiLoginMessage").lower():
                    break
            except Exception:
                pass
            page.wait_for_timeout(500)
        msg = page.inner_text("#apiLoginMessage").strip()
        if page.inner_text("#statDevices").strip() == "0":
            print(
                "login or loading failed: %r. Check the user, the password and that devices exist (seed_ips_devices.py)."
                % msg
            )
            shot("00-login-problem")
            return 2
        page.wait_for_timeout(1500)
        for i, name in enumerate(PAGES, 1):
            open_page(name)
            shot("%02d-%s" % (i, name))
        # live update without reload (real stack only)
        ws_text = page.inner_text("#socketState").strip() if page.locator("#socketState").count() else ""
        fixture_mode = "Connected" not in ws_text
        if fixture_mode:
            check(True, "live update: SKIPPED (fixture mode, no WebSocket)")
        else:
            def _threats():
                return page.inner_text("#statThreats").strip()
            def _alerts():
                return page.inner_text("#alertCount").strip()
            def _feed():
                loc = page.locator("#feedList > *")
                return loc.first.inner_text().strip() if loc.count() else ""
            def _incs():
                return page.locator("#incidentList .incident-card").count()
            before = (_threats(), _alerts(), _feed(), _incs())
            try:
                subprocess.run(
                    [sys.executable, "scripts/ips/fake_ips_publisher.py", "--now"],
                    cwd=str(ROOT), check=True, capture_output=True, text=True, timeout=120,
                )
            except Exception as exc:
                check(False, "live update: could not run fake_ips_publisher (%s)" % str(exc).splitlines()[0])
                before = None
            if before is not None:
                changed = False
                after = before
                deadline = time.time() + 60
                while time.time() < deadline:
                    after = (_threats(), _alerts(), _feed(), _incs())
                    if after != before:
                        changed = True
                        break
                    page.wait_for_timeout(1000)
                after = (_threats(), _alerts(), _feed(), _incs())
                check(changed, "live update without reload: %s (before %s -> after %s)" % ("PASS" if changed else "FAIL", before, after))
        # overview counters and feed
        open_page("overview")
        check(
            int(page.inner_text("#statDevices")) > 0,
            "overview: devices counter is %s" % page.inner_text("#statDevices").strip(),
        )
        check(
            page.locator("#feedList .feed-item").count() > 0,
            "overview: live feed has %d entries" % page.locator("#feedList .feed-item").count(),
        )
        for bad in ("Baby Monitor", "Smart TV", "Ward 3", "INC-1042", "96.4"):
            check(bad not in page.inner_text("body"), "overview: no demo text '%s'" % bad)
        check(
            not page.locator("#simulateEvent").is_visible(),
            "overview: the fake attack simulator is not shown",
        )
        # devices
        open_page("devices")
        rows = page.locator("#devicesTbody tr").count()
        check(
            rows > 0 and "No devices yet" not in page.inner_text("#devicesTbody"),
            "devices: %d rows from the backend" % rows,
        )
        # digital twin
        open_page("digital-twin")
        check(
            page.locator("#floorPlan .device-node").count() > 0,
            "digital twin: %d device nodes in rooms"
            % page.locator("#floorPlan .device-node").count(),
        )
        boxes = page.eval_on_selector_all(
            "#floorPlan .device-node circle.node-ring",
            "els => els.map(e => e.getBoundingClientRect()).map(r => [Math.round(r.x), Math.round(r.y)])",
        )
        check(
            len(set(map(tuple, boxes))) == len(boxes),
            "digital twin: no two devices are drawn on top of each other",
        )
        # network
        open_page("network")
        check(
            page.locator("#networkGraphLarge .topology-node").count() > 1,
            "network: graph has %d nodes"
            % page.locator("#networkGraphLarge .topology-node").count(),
        )
        # incidents
        open_page("incidents")
        cards = page.locator("#incidentList .incident-card")
        check(cards.count() > 0, "incidents: %d incidents listed" % cards.count())
        if cards.count():
            cards.first.click()
            page.wait_for_timeout(3000)
            check(
                page.locator("#view-incident-detail.active").count() == 1, "incident detail opens"
            )
            check(
                page.locator("#incTimeline .timeline-item").count() > 0,
                "incident detail: timeline has events",
            )
            shot("%02d-incident-detail" % (len(PAGES) + 1))
        # copilot
        open_page("copilot")
        page.fill("#copilotInput", "Summarize the last 24 hours")
        page.press("#copilotInput", "Enter")
        page.wait_for_timeout(2200)
        last = page.locator("#copilotMessages .bubble").last.inner_text()
        check(
            re.search(r"\d+ devices", last) is not None,
            "copilot answers from live data: %s" % last[:80],
        )
        shot("%02d-copilot-answer" % (len(PAGES) + 2))
        check(
            not errors,
            "no JavaScript errors in the console%s"
            % ("" if not errors else ": " + "; ".join(errors[:3])),
        )
        browser.close()
    print("\nscreenshots saved in %s" % out)
    print("ALL CHECKS PASSED" if not problems else "%d CHECK(S) FAILED" % len(problems))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
