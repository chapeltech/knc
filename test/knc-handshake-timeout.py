#!/usr/bin/env python3

import os
import socket
import subprocess
import time


knc = os.environ.get("KNC", os.path.join("..", "bin", "knc"))
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen(1)
port = listener.getsockname()[1]

server = subprocess.Popen(
    [
        knc,
        "-l",
        "-f",
        "-M", "1",
        "-N", "0",
        "-o", "handshake-timeout=1",
        "/bin/cat",
    ],
    stdin=listener,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
listener.close()

client = None
try:
    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    client.settimeout(4)
    started = time.monotonic()
    data = client.recv(1)
    elapsed = time.monotonic() - started

    if data != b"":
        raise RuntimeError("idle handshake returned unexpected data")
    if elapsed > 3:
        raise RuntimeError(
            "one-second handshake timeout took %.2f seconds" % elapsed
        )

    returncode = server.wait(timeout=2)
    if returncode not in (0, 1):
        raise RuntimeError("knc server exited with status %d" % returncode)
finally:
    if client is not None:
        client.close()
    if server.poll() is None:
        server.kill()
        server.wait()
