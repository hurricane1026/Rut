#!/usr/bin/env python3
"""Opt-in privileged smoke test: real TCP relay, byte checks, faults and scheduling."""

import argparse
import json
import mmap
import multiprocessing
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time

import trace


def receive(sock, size):
    chunks = []
    while size:
        chunk = sock.recv(size)
        if not chunk:
            raise RuntimeError("unexpected EOF")
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def attached(path):
    if not path.exists():
        return False
    for line in path.read_text().splitlines():
        try:
            event = json.loads(line)
            data = event.get("data") if isinstance(event, dict) else None
            if (isinstance(event, dict) and event.get("type") == "attached_probes" and
                    isinstance(data, dict) and type(data.get("probes")) is int and
                    data["probes"] > 0):
                return True
        except (AttributeError, TypeError, json.JSONDecodeError):
            continue
    return False


def armed(path):
    if not path.exists():
        return False
    for line in path.read_text().splitlines():
        try:
            event = json.loads(line)
            data = event.get("data") if isinstance(event, dict) else None
            if (isinstance(event, dict) and event.get("type") == "printf" and
                    isinstance(data, str) and data.strip() == "RUT_TRACE_ARMED"):
                return True
        except (AttributeError, TypeError, json.JSONDecodeError):
            continue
    return False


def secure_write(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(text)


def fixture(pipe, stop):
    def listener():
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        sock.settimeout(0.1)
        return sock

    origin, front = listener(), listener()
    origin_port = origin.getsockname()[1]

    def echo(peer):
        with peer:
            while data := peer.recv(65536):
                peer.sendall(data)

    def relay(peer):
        # Fault fresh ordinary pages while the trace is active.
        with mmap.mmap(-1, 1024 * 1024) as memory:
            for offset in range(0, len(memory), 4096):
                memory[offset] = 1
        with peer, socket.create_connection(("127.0.0.1", origin_port), timeout=3) as upstream:
            while data := peer.recv(65536):
                upstream.sendall(data)
                peer.sendall(receive(upstream, len(data)))

    def accept(sock, handler):
        while not stop.is_set():
            try:
                peer, _ = sock.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handler, args=(peer,), daemon=True).start()

    for sock, handler in ((origin, echo), (front, relay)):
        threading.Thread(target=accept, args=(sock, handler), daemon=True).start()
    pipe.send((front.getsockname()[1], origin_port))
    stop.wait()
    origin.close()
    front.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bpftrace", default="bpftrace")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.is_symlink():
        parser.error("output must not be a symlink")
    output_fd = trace.open_output_dir(args.output)
    output = Path(f"/proc/self/fd/{output_fd}")
    tracer = None
    server = None
    stop = None
    try:
        parent, child = multiprocessing.Pipe()
        stop = multiprocessing.Event()
        server = multiprocessing.Process(target=fixture, args=(child, stop))
        server.start()
        if not parent.poll(10):
            raise RuntimeError("fixture did not start")
        front, origin = parent.recv()
        command = [sys.executable, str(Path(__file__).with_name("trace.py")),
                   "--pid", str(server.pid), "--front-port", str(front),
                   "--origin-port", str(origin), "--duration", "8",
                   "--groups", "tcp", "sched", "fault", "rx-copy", "stacks",
                   "--bpftrace", args.bpftrace, "--output", str(args.output / "trace")]
        tracer = subprocess.Popen(command)
        raw = output / "trace" / "trace.jsonl"
        deadline = time.monotonic() + 120
        while not attached(raw):
            if tracer.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("tracer did not become ready; inspect stderr.log")
            time.sleep(0.1)
        while not armed(raw):
            if tracer.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("tracer did not arm; inspect stderr.log")
            time.sleep(0.1)
        body = bytes(range(256)) * 256
        transferred = 0
        # Threads are created after attach, exercising dynamic scheduler selection.
        for _ in range(12):
            with socket.create_connection(("127.0.0.1", front), timeout=3) as client:
                for _ in range(8):
                    client.sendall(body)
                    if receive(client, len(body)) != body:
                        raise RuntimeError("relay body mismatch")
                    transferred += len(body)
        if tracer.wait(timeout=120) != 0:
            raise RuntimeError("trace rejected; inspect status.json/stderr.log")
        result = json.loads((output / "trace" / "summary.json").read_text())
        maps = result["maps"]
        for name in ("@tcp_calls", "@tcp_returned_bytes", "@runqueue_samples",
                     "@offcpu_samples", "@minor_faults", "@copy_success_bytes"):
            if not maps.get(name):
                raise RuntimeError(f"expected events absent: {name}")
        for side in (1, 2):
            for direction in (1, 2):
                key = f"{server.pid},{direction},{side}"
                if maps["@tcp_returned_bytes"].get(key) != transferred:
                    raise RuntimeError(f"incorrect PID/side/byte accounting: {key}")
            key = f"{server.pid},1,{side}"
            if maps["@copy_success_bytes"].get(key) != transferred:
                raise RuntimeError(f"incorrect receive-copy byte accounting: {key}")
        secure_write(output / "smoke.json", json.dumps(
            {"passed": True, "echo_bytes_checked": transferred, "target_pid": server.pid,
             "front_port": front, "origin_port": origin}, indent=2) + "\n")
        print(f"PASS: {transferred} echoed bytes checked; tracing evidence in {args.output}")
    finally:
        try:
            if tracer is not None and tracer.poll() is None:
                tracer.send_signal(signal.SIGINT)
                try:
                    tracer.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    tracer.kill()
                    tracer.wait()
            if stop is not None:
                stop.set()
            if server is not None:
                server.join(timeout=5)
                if server.is_alive():
                    server.terminate()
                    server.join()
        finally:
            os.close(output_fd)


if __name__ == "__main__":
    main()
