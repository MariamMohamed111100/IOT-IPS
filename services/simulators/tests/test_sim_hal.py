import random

import pytest

from sim.devices import build_devices
from sim.hal import SimActuator, SimSensor


def sensor(kind, zone="garage", outdoor=False, clock=None, **opts):
    return SimSensor("s1", kind, zone, outdoor, opts, clock=clock or (lambda: 0.0))


def test_indoor_motion_is_night_outdoor_motion_is_outdoor():
    assert sensor("pir").inject("motion") == [("motion.night", {"sensor_id": "s1"})]
    assert sensor("pir", "backyard", outdoor=True).inject("motion") == [
        ("motion.outdoor", {"sensor_id": "s1"})]


def test_motion_flag_clears_after_hold(clock):
    pir = sensor("pir", clock=clock, hold_s=5)
    pir.inject("motion")
    assert pir.state()["motion"] is True
    clock.t += 4
    pir.poll()
    assert pir.state()["motion"] is True
    clock.t += 2
    pir.poll()
    assert pir.state()["motion"] is False


def test_door_open_event_and_silent_close():
    door = sensor("door")
    assert door.inject("open") == [("door.open", {"door_id": "s1"})]
    assert door.state() == {"open": True}
    assert door.inject("close") == [] and door.state() == {"open": False}


def test_gas_event_carries_ppm():
    assert sensor("gas").inject("detect", {"ppm": 450}) == [
        ("gas.detected", {"sensor_id": "s1", "ppm": 450})]


def test_lock_login_failed_has_required_fields():
    lock = SimActuator("l1", "lock", "entrance")
    assert lock.inject("login_failed", {"attempts": 3}) == [
        ("lock.login_failed", {"lock_id": "l1", "attempts": 3})]


def test_temperature_abnormal_fires_once_then_rearms(clock):
    t = sensor("temperature", clock=clock, threshold_c=50, base_c=24)
    first = t.inject("set", {"value_c": 68.5})
    assert first == [("temperature.abnormal",
                      {"sensor_id": "s1", "value_c": 68.5, "threshold_c": 50.0})]
    assert t.inject("set", {"value_c": 70}) == []            # still hot: no duplicate event
    assert t.inject("set", {"value_c": 30}) == []            # cooled: re-armed silently
    assert len(t.inject("set", {"value_c": 60})) == 1        # hot again: fires again


def test_temperature_drifts_around_base_and_stays_normal(clock):
    t = SimSensor("t", "temperature", "kitchen", False, {"base_c": 24, "threshold_c": 50},
                  clock=clock, temp_interval=10, rng=random.Random(1))
    for _ in range(20):
        clock.t += 10
        assert t.poll() == []
        assert 23.0 <= t.state()["temperature_c"] <= 25.0


def test_invalid_stimulus_and_data_rejected():
    with pytest.raises(ValueError):
        sensor("door").inject("explode")
    with pytest.raises(ValueError):
        sensor("temperature").inject("set", {"value_c": "hot"})


@pytest.mark.parametrize("kind,action,state", [
    ("bulb", "on", {"power": "on"}), ("siren", "on", {"power": "on"}),
    ("lock", "unlock", {"lock": "unlocked"}), ("valve", "close", {"open": False}),
])
def test_actuator_actions_and_idempotence(kind, action, state):
    a = SimActuator("a1", kind, "kitchen")
    a.apply(action)
    first = a.state()
    a.apply(action)
    assert a.state() == first and state.items() <= first.items()


def test_valve_close_confirms_with_event():
    assert SimActuator("v", "valve", "kitchen").apply("close") == [
        ("valve.closed", {"valve_id": "v"})]


def test_actuator_rejects_unknown_action():
    with pytest.raises(ValueError):
        SimActuator("b", "bulb", "kitchen").apply("explode")


# ---------------------------------------------------------------- real GPIO drivers (mock pins)
gpiozero = pytest.importorskip("gpiozero")


@pytest.fixture
def pins():
    from gpiozero.pins.mock import MockFactory
    return MockFactory()


def test_gpio_sensor_has_same_events_as_simulator(pins):
    from sim.hal_gpio import GpioSensor
    door = GpioSensor("d1", "door", "entrance", pin=17, pin_factory=pins)
    assert door.poll() == []
    pins.pin(17).drive_high()                       # reed switch opens
    assert door.poll() == [("door.open", {"door_id": "d1"})]
    assert door.source == "hw.door"
    pins.pin(17).drive_low()
    assert door.poll() == [] and door.state() == {"open": False}


def test_real_hardware_refuses_injection(pins):
    from sim.hal_gpio import GpioSensor
    pir = GpioSensor("p1", "pir", "garage", pin=4, pin_factory=pins)
    with pytest.raises(PermissionError):
        pir.inject("motion")


def test_relay_actuator_drives_pin(pins):
    from sim.hal_gpio import RelayActuator
    bulb = RelayActuator("b1", "bulb", "garage", pin=27, pin_factory=pins)
    bulb.apply("on")
    assert pins.pin(27).state == 1 and bulb.state()["power"] == "on"
    bulb.apply("off")
    assert pins.pin(27).state == 0


def test_gpio_only_for_supported_kinds(pins):
    from sim.hal_gpio import GpioSensor
    with pytest.raises(NotImplementedError):
        GpioSensor("t", "temperature", "kitchen", pin=5, pin_factory=pins)


def test_mixed_mode_factory_swaps_only_devices_with_pins(cfg, pins):
    cfg = {**cfg, "devices": [dict(d, gpio_pin=17) if d["id"] == "door_main" else d
                              for d in cfg["devices"]]}
    devs = build_devices(cfg, "gpio", pin_factory=pins)
    assert devs["door_main"].source == "hw.door"
    assert devs["door_garage"].source == "sim.door"
