"""Starts ips_cyber (rules + ML model, flow events + 10-packet windows) in live mode on the interface that has the lab address (10.77.0.x).

The gateway shares the camera's network namespace, so it sees every packet to and from the camera.
Which interface that is (eth0, eth1) depends on the order Docker attached the networks, so find it.
"""
import os
import sys

from scapy.all import get_if_addr, get_if_list

PREFIX = os.getenv("LAB_PREFIX", "10.77.0.")
iface = next((i for i in get_if_list() if get_if_addr(i).startswith(PREFIX)), None)
if iface is None:
    sys.exit("no interface with a %s* address: is the gateway on the camera's network?" % PREFIX)
print("lab gateway captures on", iface, flush=True)
os.execvp("python", ["python", "main.py", "--source", "live", "--iface", iface,
                     "--devices", "/lab/ips_devices.json", "--publisher", "mqtt", "--idle",
                     "--detector", "combined", "--ml-windows"])
