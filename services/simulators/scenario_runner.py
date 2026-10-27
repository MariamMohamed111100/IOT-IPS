"""CLI: replay a scenario against the running simulators.

    python scenario_runner.py --list
    python scenario_runner.py night_intruder
    python scenario_runner.py kitchen_fire --speed 2
    python scenario_runner.py water_leak --dry-run        # validate and print, send nothing

In Docker:  docker compose exec simulators python scenario_runner.py night_intruder
"""
from __future__ import annotations

import argparse
import sys

from sim import scenario
from sim.devices import load_config


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("scenario", nargs="?", help="scenario name (see --list) or path to a .yaml")
    ap.add_argument("--list", action="store_true", help="list available scenarios")
    ap.add_argument("--dry-run", action="store_true", help="validate and print only")
    ap.add_argument("--speed", type=float, default=1.0, help="2 = twice as fast")
    args = ap.parse_args(argv)

    if args.list or not args.scenario:
        for name in scenario.list_scenarios():
            print(name)
        return 0

    sc = scenario.load_scenario(args.scenario)
    problems = scenario.validate(sc, load_config())
    if problems:
        print("Scenario is invalid:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 2

    if args.dry_run:
        from sim.bus import LoopbackBus
        scenario.run(sc, LoopbackBus(), sleep=lambda s: None, speed=args.speed)
        return 0

    from sim.bus import MqttBus
    from smartsecure_common import connect
    client = connect("sim_runner")
    try:
        scenario.run(sc, MqttBus(client), speed=args.speed, wait=True)
    finally:
        client.loop_stop()
        client.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main())
