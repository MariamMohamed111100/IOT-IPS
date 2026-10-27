from sim import catalog, scenario
from smartsecure_common import topics


def test_enough_devices(cfg):
    assert len(cfg["devices"]) >= 15


def test_all_kinds_are_covered(cfg):
    required = {"pir", "door", "window", "smoke", "gas", "water_leak", "temperature",
                "lock", "bulb", "siren", "valve", "camera"}
    assert required <= {d["kind"] for d in cfg["devices"]}


def test_zones_exist_in_repo_config(cfg, zones_cfg):
    unknown = {d["zone"] for d in cfg["devices"]} - set(zones_cfg["zones"])
    assert not unknown, f"zones missing from config/zones.yaml: {unknown}"


def test_outdoor_zones_match_repo_config(cfg, zones_cfg):
    assert set(cfg["outdoor_zones"]) == set(zones_cfg["outdoor_zones"])


def test_every_device_builds_valid_topics(cfg):
    for d in cfg["devices"]:
        assert topics.sensor_event(d["zone"], d["kind"], d["id"]).endswith("/event")


def test_every_kind_has_behaviour():
    for kind in catalog.SENSOR_KINDS:
        assert catalog.stimuli_for(kind), kind
    for kind in catalog.ACTUATOR_KINDS:
        assert catalog.ACTIONS[kind], kind


def test_actions_are_the_contract_actions():
    allowed = {"on", "off", "lock", "unlock", "close", "open"}   # CONTRACT 4.1
    assert {a for spec in catalog.ACTIONS.values() for a in spec} <= allowed


def test_at_least_three_scenarios_and_all_valid(cfg):
    names = scenario.list_scenarios()
    assert len(names) >= 3
    for name in names:
        assert scenario.validate(scenario.load_scenario(name), cfg) == [], name
