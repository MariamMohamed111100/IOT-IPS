import json

import jsonschema

from smartsecure_common import topics


def events(bus):
    return [(t, json.loads(p)) for t, p in bus.on("home/+/+/+/event")]


def test_start_publishes_retained_status_for_every_device(runtime, bus, devices):
    statuses = bus.on("home/+/+/+/status")
    assert len(statuses) == len(devices)
    assert all(retain for t, _, retain in bus.published if t.endswith("/status"))
    topic = topics.device_status("living_room", "bulb", "bulb_living")
    payload = json.loads(bus.retained[topic])
    assert payload["online"] is True and payload["state"] == {"power": "off"}
    assert {"id", "ts", "state", "online"} <= payload.keys()          # CONTRACT 4.2


def test_command_changes_state_and_republishes(runtime, bus):
    cmd = topics.device_cmd("living_room", "bulb", "bulb_living")
    bus.publish(cmd, json.dumps({"id": "x", "action": "on", "reason": "incident-42"}))
    status = json.loads(bus.retained[topics.device_status("living_room", "bulb", "bulb_living")])
    assert status["state"]["power"] == "on"


def test_bad_commands_are_ignored_not_fatal(runtime, bus):
    cmd = topics.device_cmd("living_room", "bulb", "bulb_living")
    before = len(bus.published)
    for bad in ["not json", "[]", '{"nope": 1}', '{"action": "explode"}', '"on"', "null"]:
        bus.publish(cmd, bad)
    assert len(bus.published) == before + 6          # only our own 6 publishes, no replies
    status = json.loads(bus.retained[topics.device_status("living_room", "bulb", "bulb_living")])
    assert status["state"]["power"] == "off"


def test_valve_close_publishes_confirmation_event(runtime, bus, event_schema):
    bus.publish(topics.device_cmd("kitchen", "valve", "valve_main"), '{"action": "close"}')
    (topic, event), = events(bus)
    assert topic == "home/kitchen/valve/valve_main/event"
    assert event["type"] == "valve.closed" and event["data"] == {"valve_id": "valve_main"}
    jsonschema.validate(event, event_schema)


def test_inject_publishes_contract_event_and_status(runtime, bus, event_schema):
    msg = {"device": "pir_garage", "event": "motion"}
    bus.publish(topics.SIM_INJECT, json.dumps(msg))
    (topic, event), = events(bus)
    assert topic == "home/garage/pir/pir_garage/event"
    assert event["type"] == "motion.night" and event["zone"] == "garage"
    assert event["source"] == "sim.pir"
    jsonschema.validate(event, event_schema)
    status = json.loads(bus.retained["home/garage/pir/pir_garage/status"])
    assert status["state"]["motion"] is True


def test_outdoor_motion_uses_outdoor_type(runtime, bus):
    bus.publish(topics.SIM_INJECT, json.dumps({"device": "pir_backyard", "event": "motion"}))
    assert events(bus)[0][1]["type"] == "motion.outdoor"


def test_bad_injects_are_ignored(runtime, bus):
    for bad in ["junk", '{"device": "ghost", "event": "motion"}',
                '{"device": "door_main", "event": "explode"}', "[]"]:
        bus.publish(topics.SIM_INJECT, bad)
    assert events(bus) == []


def test_inject_can_be_disabled(devices, bus):
    from sim.runtime import SimulatorRuntime
    SimulatorRuntime(devices, bus, allow_inject=False).start()
    bus.publish(topics.SIM_INJECT, json.dumps({"device": "pir_garage", "event": "motion"}))
    assert events(bus) == []


def test_tick_clears_motion_and_publishes_status(runtime, bus, clock):
    bus.publish(topics.SIM_INJECT, json.dumps({"device": "pir_garage", "event": "motion"}))
    clock.t += 10
    runtime.tick()
    status = json.loads(bus.retained["home/garage/pir/pir_garage/status"])
    assert status["state"]["motion"] is False


def test_tick_publishes_temperature_status_but_no_event(runtime, bus, clock):
    before = len(bus.on("home/kitchen/temperature/temp_kitchen/status"))
    clock.t += 10
    runtime.tick()
    assert len(bus.on("home/kitchen/temperature/temp_kitchen/status")) == before + 1
    assert events(bus) == []


def test_fire_temperature_event_once(runtime, bus, clock):
    msg = {"device": "temp_kitchen", "event": "set", "data": {"value_c": 68.5}}
    bus.publish(topics.SIM_INJECT, json.dumps(msg))
    for _ in range(3):
        clock.t += 10
        runtime.tick()
    abnormal = [e for _, e in events(bus) if e["type"] == "temperature.abnormal"]
    assert len(abnormal) == 1 and abnormal[0]["data"]["value_c"] == 68.5


def test_stop_marks_everything_offline(runtime, bus, devices):
    runtime.stop()
    offline = [json.loads(p) for t, p in bus.on("home/+/+/+/status")][-len(devices):]
    assert all(s["online"] is False for s in offline)
