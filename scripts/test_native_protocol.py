#!/usr/bin/env python3
"""Exercise failure handling through the production compiler output pipe."""
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def check_startup(server, source, explicit):
    command = [str(server.resolve())]
    command += ["--compile", str(source)] if explicit else [str(source)]
    command += ["--shards", "1", "--no-pin", "--drain", "0"]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    diagnostic = b""
    ready = None
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stderr, selectors.EVENT_READ)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if not selector.select(max(0, deadline - time.monotonic())):
                    break
                chunk = os.read(process.stderr.fileno(), 4096)
                if not chunk:
                    break
                diagnostic += chunk
                ready = re.search(rb"Listening on port (\d+) with", diagnostic)
                if ready:
                    break
        assert ready, diagnostic.decode()
        maps = Path(f"/proc/{process.pid}/maps").read_text()
        assert "libLLVM" not in maps, maps
        assert "/memfd:rut-program" in maps, maps
        children = Path(f"/proc/{process.pid}/task/{process.pid}/children").read_text()
        assert not children.strip(), children
        # No compiler process or source is needed once serving starts.
        source.unlink()
        with socket.create_connection(("127.0.0.1", int(ready.group(1))), timeout=3) as client:
            client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            response = b""
            while chunk := client.recv(4096):
                response += chunk
        assert b"200 OK" in response and response.endswith(b"native"), response
        print(json.dumps({"case": "explicit flag" if explicit else "positional source",
                          "llvm_loaded": False, "compiler_exited": True}))
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def check_startup_cancellation(server, source, header, image, signal_name, mode, root):
    """Terminate startup while the compiler is blocked at each pipe boundary."""
    pid_file = root / f"producer-{signal_name}-{mode}.pid"
    helper = root / "rut-compile"
    frame = header + image
    write = "" if mode == "header" else (
        f"sys.stdout.buffer.write(bytes.fromhex({frame.hex()!r}));sys.stdout.flush()\n")
    close = "sys.stdout.close()\n" if mode == "eof" else ""
    helper.write_text(
        f"#!{sys.executable}\nimport os,sys,time\n"
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        f"{write}{close}time.sleep(30)\n")
    helper.chmod(0o700)
    process = subprocess.Popen(
        [str(server), "--compile", str(source), "--shards", "1", "--no-pin"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not pid_file.exists():
            time.sleep(0.01)
        assert pid_file.exists(), f"producer did not start: {mode}"
        producer_pid = int(pid_file.read_text())
        os.kill(process.pid, getattr(signal, signal_name))
        process.wait(timeout=3)
        diagnostic = process.stderr.read().decode()
        assert process.returncode != 0 and "startup cancelled" in diagnostic, diagnostic
        assert not Path(f"/proc/{producer_pid}").exists(), (mode, producer_pid)
        print(json.dumps({"case": f"{signal_name} during {mode}", "producer_reaped": True}))
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    args = parser.parse_args()
    for arguments in (["--compile"], ["--compile", "--shards", "1"], ["--compile", ""]):
        result = subprocess.run([str(args.server.resolve()), *arguments],
                                capture_output=True, timeout=5)
        assert result.returncode != 0 and b"--compile requires" in result.stderr, result.stderr
    with tempfile.TemporaryDirectory(prefix="rut-native-protocol-") as directory:
        root = Path(directory)
        source = root / "app.rut"
        for explicit in (True, False):
            source.write_text('listen 127.0.0.1:0\n'
                              'route GET "/" { return response(200, body: "native") }\n')
            check_startup(args.server, source, explicit)
        source.write_text('route GET "/" { return 200 }\n')
        result = subprocess.run([str(args.compiler.resolve()), str(source), "2"],
                                capture_output=True, check=True, timeout=15)
        data = result.stdout
        offset = data.find(b"\x7fELF")
        assert offset > 0, "compiler stream must contain a framed native image"
        header, image = data[:offset], data[offset:]
        fingerprint = re.search(rb"[0-9a-f]{64}\x00", header)
        assert fingerprint, "compiler stream must identify its build"
        start = fingerprint.start()
        wrong = header[:start] + b"x" + header[start + 1:]
        server = root / "rut"
        shutil.copy2(args.server, server)
        for signal_name in ("SIGINT", "SIGTERM"):
            for mode in ("header", "tail", "eof"):
                source.write_text('route GET "/" { return 200 }\n')
                check_startup_cancellation(
                    server, source, header, image, signal_name, mode, root)
        cases = (
            ("mismatched build", wrong, b"", 30, "build mismatch"),
            ("truncated image", header, image[:16], 0, "truncated compiler artifact"),
            ("trailing bytes", header, image + b"x", 0, "invalid compiler artifact framing"),
        )
        for name, frame, payload, delay, expected in cases:
            pid_file = root / "producer.pid"
            helper = root / "rut-compile"
            helper.write_text(
                f"#!{sys.executable}\nimport os,sys,time\n"
                f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
                f"sys.stdout.buffer.write(bytes.fromhex({(frame + payload).hex()!r}))\n"
                f"sys.stdout.flush()\ntime.sleep({delay})\n")
            helper.chmod(0o700)
            run = subprocess.run([str(server), "--compile", str(source), "--shards", "1", "--no-pin"],
                                 capture_output=True, timeout=5)
            diagnostic = run.stderr.decode()
            assert run.returncode != 0 and expected in diagnostic, (name, diagnostic)
            assert "Listening on" not in diagnostic, (name, diagnostic)
            # The consumer must stop and reap even a producer that would sleep
            # or block with a full pipe after sending an invalid handshake.
            producer_pid = int(pid_file.read_text())
            assert not Path(f"/proc/{producer_pid}").exists(), (name, producer_pid)
            print(json.dumps({"case": name, "exit_code": run.returncode,
                              "diagnostic": diagnostic.strip()}))


if __name__ == "__main__":
    main()
