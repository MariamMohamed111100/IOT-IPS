"""Normal client of the lab: looks at the camera like the owner's phone would (a few requests a minute)."""
import base64
import os
import random
import socket
import time

HOST = os.getenv("CAM_HOST", "10.77.0.10")
AUTH = "Basic " + base64.b64encode(
    f"{os.getenv('CAM_USER', 'admin')}:{os.getenv('CAM_PASSWORD', 'lab-only-not-a-real-password')}".encode()).decode()


def ask(port, line):
    with socket.create_connection((HOST, port), timeout=5) as s:
        s.sendall(f"{line}\r\nAuthorization: {AUTH}\r\n\r\n".encode())
        s.recv(4096)


while True:
    try:
        ask(443, "GET / HTTP/1.1")
        if random.random() < 0.5:
            ask(554, f"DESCRIBE rtsp://{HOST}/stream RTSP/1.0\r\nCSeq: 1")
    except OSError as exc:
        print("client:", exc, flush=True)
    time.sleep(random.uniform(8, 20))
