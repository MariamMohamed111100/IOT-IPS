# Simulators (Person 3)

The simulated house: 20 devices that publish contract events, obey commands, and replay
scenarios. Built so that the Raspberry Pi phase swaps *drivers*, not code.

```
scenario_runner ──inject──▶ system/sim/inject ──▶ SimSensor ──▶ home/<zone>/<kind>/<id>/event
engine / api    ──cmd────▶ home/.../cmd       ──▶ SimActuator ─▶ home/.../status (retained)
```

## Run it

```bash
make up                         # whole stack (simulators included)
make watch                      # live events (second terminal)
make sim-list                   # night_intruder, kitchen_fire, water_leak, smart_lock_attack
make sim S=night_intruder       # replay a scenario
make smoke                      # includes: 20 device statuses + a water_leak event over mTLS
```

Without Docker (unit level, no broker needed):

```bash
pip install -e libs/common pytest jsonschema pyyaml gpiozero
pytest services/simulators/tests -q
python services/simulators/scenario_runner.py night_intruder --dry-run
```

## What a scenario may and may not do

A scenario only says what **happens** (door opens, smoke appears). It never switches the siren,
lights or valve on: the engine must do that, otherwise the demo proves nothing. A test enforces it.

Every scenario declares `emits:` (the exact event types it must produce) and `expect:`
(what the engine should then do). `pytest` fails if the two ever drift or an event type is
missing from `docs/CONTRACT.md`.

## Hardware Abstraction Layer

| | Simulation (M1) | Raspberry Pi (M4) |
|---|---|---|
| Sensors (`Sensor.poll`) | `SimSensor` | `GpioSensor` (PIR, door, window, smoke, water) |
| Actuators (`Actuator.apply`) | `SimActuator` | `RelayActuator` (bulb, siren, lock, valve) |
| Event content | `sim/catalog.py` | the same `sim/catalog.py` |
| `inject` (spoofing) | allowed | **refused** (`PermissionError`) |

Bring-up on the Pi, one device at a time:
1. Add `gpio_pin: 17` to a device in `devices.yaml`.
2. Run the container with `HAL_DRIVER=gpio` and `SIM_ALLOW_INJECT=false`.
   Devices without a pin stay simulated, so a half-wired house still works.
3. Temperature, gas and camera need other drivers (ADC / I2C / RTSP): `GpioSensor` raises
   `NotImplementedError` for them on purpose.

The GPIO drivers are tested with mock pins only. Pull-up/down, debounce and relay polarity
(`energize_action`, `active_high`) must be validated on real hardware.

## Add things

- **Device:** one line in `devices.yaml` (zone must exist in `config/zones.yaml`).
- **Scenario:** a YAML in `scenarios/`; validate with `--dry-run`.
- **New device kind or event:** `sim/catalog.py` + a row in `docs/CONTRACT.md` section 3.

## Settings (env)

| Variable | Default | Meaning |
|---|---|---|
| `HAL_DRIVER` | `sim` | `gpio` = use real hardware for devices that have `gpio_pin` |
| `SIM_ALLOW_INJECT` | `true` | **set `false` on real hardware** |
| `SIM_TEMP_INTERVAL` | `10` | seconds between temperature status updates |
| `LOG_LEVEL` | `INFO` | `DEBUG` to see every message |
