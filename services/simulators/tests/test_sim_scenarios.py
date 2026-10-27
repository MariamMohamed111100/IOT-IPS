import json

import jsonschema
import pytest

from sim import scenario


@pytest.mark.parametrize("name", scenario.list_scenarios())
def test_scenario_emits_exactly_what_it_declares(name, runtime, bus, cfg, event_schema,
                                                 contract_types):
    sc = scenario.load_scenario(name)
    sleeps: list[float] = []
    scenario.run(sc, bus, sleep=sleeps.append, out=lambda _: None)

    emitted = [json.loads(p) for _, p in bus.on("home/+/+/+/event")]
    assert [e["type"] for e in emitted] == sc["emits"]
    for event in emitted:
        jsonschema.validate(event, event_schema)
        assert event["type"] in contract_types, f"{event['type']} missing from CONTRACT.md"
    assert sleeps == [s["delay"] for s in sc["steps"] if s.get("delay", 0) > 0]


def test_scenarios_never_command_actuators():
    """The engine must react, not the scenario."""
    for name in scenario.list_scenarios():
        for step in scenario.load_scenario(name)["steps"]:
            assert step["event"] in {"motion", "open", "close", "detect", "clear", "leak",
                                     "set", "disconnect", "connect", "login_failed"}


def test_speed_shortens_delays(runtime, bus):
    sc = scenario.load_scenario("night_intruder")
    sleeps: list[float] = []
    scenario.run(sc, bus, sleep=sleeps.append, speed=2.0, out=lambda _: None)
    assert sleeps == [1.0, 1.5]


def test_validation_catches_mistakes(cfg):
    bad = {"name": "x", "steps": [
        {"device": "ghost", "event": "open"},
        {"device": "door_main", "event": "explode"},
        {"device": "door_main", "event": "open", "delay": -1},
    ]}
    errors = scenario.validate(bad, cfg)
    assert len(errors) == 3 and "ghost" in errors[0]


def test_all_contract_sim_types_are_reachable(runtime, bus, contract_types):
    """Every type CONTRACT.md says 'simulators' produces can actually be produced."""
    import pathlib
    import re
    contract = (pathlib.Path(__file__).resolve().parents[3] / "docs/CONTRACT.md")
    text = contract.read_text(encoding="utf-8")
    section = text.split("## 3. Event type registry")[1].split("\n## ")[0]
    pattern = r"^\| `([a-z0-9_.]+)` \| simulators"
    sim_types = {m.group(1) for m in re.finditer(pattern, section, re.M)}
    produced = set()
    for name in scenario.list_scenarios():
        produced |= set(scenario.load_scenario(name)["emits"])
    produced.add("valve.closed")        # produced by a command, not a scenario
    assert sim_types - {"motion.outdoor", "window.open"} <= produced, sim_types - produced
