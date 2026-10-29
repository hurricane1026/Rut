#!/usr/bin/env python3
"""Exercise the limited static runtime profile, including its source-load rejection."""

import socket
import ssl
import subprocess
import sys
import time


def available_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def exercise(binary, cert, key, backend, use_tls):
    port = available_port()
    args = [binary, str(port), "--shards", "1", "--backend", backend]
    if use_tls:
        args.extend(["--tls-cert", cert, "--tls-key", key])
    process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        connection = None
        for _ in range(100):
            if process.poll() is not None:
                error = process.stderr.read().decode(errors="replace")
                if backend == "io_uring" and "io_uring is unavailable" in error:
                    print("SKIP io_uring: unavailable in this environment", flush=True)
                    return False
                raise RuntimeError(f"{backend} server exited: {error}")
            try:
                connection = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        if connection is None:
            raise RuntimeError(f"{backend} server startup timed out")
        if use_tls:
            connection = ssl._create_unverified_context().wrap_socket(
                connection, server_hostname="localhost"
            )
        with connection:
            connection.settimeout(5)
            connection.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            response = connection.recv(4096)
            if not response.startswith(b"HTTP/1.1 200 "):
                raise RuntimeError(f"{backend} TLS={use_tls}: unexpected response {response!r}")
        print(f"{backend} TLS={use_tls}: HTTP 200", flush=True)
        return True
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main():
    binary, cert, key, source = sys.argv[1:]
    for backend in ("epoll", "io_uring"):
        if not exercise(binary, cert, key, backend, False):
            continue
        exercise(binary, cert, key, backend, True)
    result = subprocess.run([binary, source], capture_output=True, text=True, timeout=10)
    if result.returncode == 0 or "no JIT" not in result.stdout + result.stderr:
        raise RuntimeError("static runtime must reject .rut source without JIT")
    print("source loading rejected as documented", flush=True)


if __name__ == "__main__":
    main()
