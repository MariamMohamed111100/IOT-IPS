"""Fake IP camera for the lab: RTSP-like service on 554 and an HTTP-like service on 443.

It only exists inside the internal lab network. Both services answer 401 to anything without the
right Basic credentials, and close the connection after each answer (like a small camera), so a
password guesser makes many short failed attempts. It starts no outbound connection.
"""
import base64
import os
import socketserver
import threading

USER, PASSWORD = os.getenv("CAM_USER", "admin"), os.getenv("CAM_PASSWORD", "lab-only-not-a-real-password")
GOOD = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()


class Handler(socketserver.StreamRequestHandler):
    proto = "HTTP/1.1"

    def handle(self):
        self.request.settimeout(1)      # a failed guess must not hold the connection
        try:
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 8192:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                head += chunk
        except OSError:
            return
        if not head:
            return
        ok = any(line.lower().startswith(b"authorization:") and line.split(b":", 1)[1].strip().decode(errors="replace") == GOOD
                 for line in head.split(b"\r\n"))
        if ok:
            body = b"lab camera: stream ok\r\n" * 20
            status = "200 OK"
            extra = ""
        else:
            body = b"unauthorized\r\n"
            status = "401 Unauthorized"
            extra = 'WWW-Authenticate: Basic realm="lab-camera"\r\n'
        try:
            self.request.sendall((f"{self.proto} {status}\r\n{extra}Content-Length: {len(body)}\r\n"
                                  "Connection: close\r\n\r\n").encode() + body)
        except OSError:
            pass


class Rtsp(Handler):
    proto = "RTSP/1.0"


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256


def main():
    for port, handler in ((554, Rtsp), (443, Handler)):
        server = Server(("0.0.0.0", port), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print("lab camera listening on", port, flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
