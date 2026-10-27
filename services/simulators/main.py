"""simulators service: the simulated house. Publishes device events/status and obeys commands."""
from __future__ import annotations

import logging
import os
import signal
import threading

from sim.bus import MqttBus
from sim.devices import build_devices, load_config
from sim.runtime import SimulatorRuntime
from smartsecure_common import connect, start_heartbeat

SERVICE = "simulators"


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    driver = os.getenv("HAL_DRIVER", "sim")
    devices = build_devices(load_config(), driver,
                            temp_interval=float(os.getenv("SIM_TEMP_INTERVAL", "10")))
    client = connect(SERVICE)
    start_heartbeat(client, SERVICE)
    runtime = SimulatorRuntime(
        devices, MqttBus(client),
        allow_inject=os.getenv("SIM_ALLOW_INJECT", "true").lower() == "true",
    )
    runtime.start()

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    while not stop.wait(1.0):
        runtime.tick()
    runtime.stop()                      # devices are marked offline on a clean shutdown
    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
