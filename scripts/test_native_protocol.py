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
import struct
import subprocess
import sys
import tempfile
import time


def wait_dead(pid, timeout=2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return "gone"
        if sys.platform.startswith("linux"):
            stat = Path(f"/proc/{pid}/stat")
            try:
                if stat.read_text().split()[2] == "Z":
                    return "zombie"
            except FileNotFoundError:
                return "gone"
        time.sleep(0.01)
    raise AssertionError(("still alive", pid))


def check_startup(server, source, explicit, environment=None, preexec_fn=None):
    command = [str(server.resolve())]
    command += ["--compile", str(source)] if explicit else [str(source)]
    command += ["--shards", "1", "--no-pin", "--drain", "0"]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                               env=environment, preexec_fn=preexec_fn)
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
        if sys.platform.startswith("linux"):
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


def check_startup_cancellation(server, source, header, image, signal_name, mode, root,
                               grandchild=False):
    """Terminate startup while the compiler is blocked at each pipe boundary."""
    suffix = "-grandchild" if grandchild else ""
    pid_file = root / f"producer-{signal_name}-{mode}{suffix}.pid"
    pid_file.unlink(missing_ok=True)
    helper = root / "rut-compile"
    frame = header + image
    write = "" if mode == "header" else (
        f"sys.stdout.buffer.write(bytes.fromhex({frame.hex()!r}));sys.stdout.flush()\n")
    close = "os.close(1)\n" if mode == "eof" else ""
    child_setup = ("grand=os.fork();\nif grand==0: time.sleep(30)\n" if grandchild else
                   "grand=0\n")
    marker = (f"tmp={str(pid_file)!r}+'.tmp';open(tmp,'w').write(str(os.getpid())+','+str(grand));"
              f"os.replace(tmp,{str(pid_file)!r})\n")
    helper.write_text(
        f"#!{sys.executable}\nimport os,sys,time\n"
        f"{write}{close}{child_setup}{marker}time.sleep(30)\n")
    helper.chmod(0o700)
    process = subprocess.Popen(
        [str(server), "--compile", str(source), "--shards", "1", "--no-pin"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not pid_file.exists():
            time.sleep(0.01)
        if not pid_file.exists():
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
            os.set_blocking(process.stderr.fileno(), False)
            try:
                diagnostic = os.read(process.stderr.fileno(), 4096).decode(errors="replace")
            except BlockingIOError:
                diagnostic = ""
            raise AssertionError(
                f"producer did not start: {mode}; server return code: {process.returncode}; "
                f"server stderr (first 4096 bytes): {diagnostic!r}")
        producer_pid, grandchild_pid = map(int, pid_file.read_text().split(','))
        pid_file.unlink(missing_ok=True)
        if grandchild:
            assert grandchild_pid > 0, (mode, grandchild_pid)
        os.kill(process.pid, getattr(signal, signal_name))
        process.wait(timeout=3)
        diagnostic = process.stderr.read().decode()
        assert process.returncode != 0 and "startup cancelled" in diagnostic, (process.returncode, diagnostic)
        states = {"producer": wait_dead(producer_pid)}
        producer_pid = 0
        if grandchild:
            states["grandchild"] = wait_dead(grandchild_pid)
            grandchild_pid = 0
        print(json.dumps({"case": f"{signal_name} during {mode}{suffix}", **states}))
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        for tracked_pid in (locals().get("producer_pid", 0), locals().get("grandchild_pid", 0)):
            if tracked_pid:
                try:
                    os.kill(tracked_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--websocket-enabled", choices=("0", "1"), default="1")
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
        if sys.platform != "win32":
            source.write_text('listen 127.0.0.1:0\n'
                              'route GET "/" { return response(200, body: "native") }\n')
            check_startup(args.server, source, True, preexec_fn=lambda: signal.signal(signal.SIGCHLD, signal.SIG_IGN))
            source.write_text('listen 127.0.0.1:0\n'
                              'route GET "/" { return response(200, body: "native") }\n')
            check_startup(args.server, source, True, preexec_fn=lambda: (os.close(0), os.close(1)))
        source.write_text('listen 127.0.0.1:0\n'
                          'route GET "/" { return response(200, body: "native") }\n')
        check_startup(args.server, source, True, {})
        source.write_text('route GET "/" { return 200 }\n')
        result = subprocess.run([str(args.compiler.resolve()), str(source), "2"],
                                capture_output=True, check=True, timeout=15)
        data = result.stdout
        offset = data.find(b"\x7fELF" if sys.platform.startswith("linux") else b"\xcf\xfa\xed\xfe")
        assert offset > 0, "compiler stream must contain a framed native image"
        header, image = data[:offset], data[offset:]
        fingerprint = re.search(rb"[0-9a-f]{64}\x00", header)
        assert fingerprint, "compiler stream must identify its build"
        start = fingerprint.start()
        wrong = header[:start] + b"x" + header[start + 1:]
        server = root / "rut"
        shutil.copy2(args.server, server)
        helper = root / "rut-compile"

        if args.websocket_enabled == "1":
            # Generate a real native artifact, then corrupt only its WebSocket route metadata.
            # The copied server must reject this at the native load boundary before rebuilding
            # the route dispatch index.
            ws_source = root / "ws-limit.rut"
            ws_source.write_text(
                'upstream backend at "127.0.0.1:9999"\n'
                'route GET "/ws-limit-contract" { return websocket(backend, '
                'maxMessageSize: 16001b) { message in message.forward() } }\n'
            )
            ws_result = subprocess.run(
                [str(args.compiler.resolve()), str(ws_source), "2"],
                capture_output=True,
                check=True,
                timeout=15,
            )
            ws_data = ws_result.stdout
            ws_offset = ws_data.find(b"\x7fELF" if sys.platform.startswith("linux") else b"\xcf\xfa\xed\xfe")
            assert ws_offset > 0, "WebSocket compiler stream must contain a native image"
            ws_header, ws_image = ws_data[:ws_offset], ws_data[ws_offset:]
            native_magic = struct.pack("<Q", 0x5255544E41544956)
            native_headers = [match.start() for match in re.finditer(re.escape(native_magic), ws_image)]
            assert len(native_headers) == 1, native_headers
            config_offset = native_headers[0]
            assert config_offset + 32 <= len(ws_image)
            native_version, config_struct_size = struct.unpack_from("<II", ws_image, config_offset + 8)
            config_blob_size = struct.unpack_from("<Q", ws_image, config_offset + 16)[0]
            metadata_size = struct.unpack_from("<I", ws_image, config_offset + 24)[0]
            route_count = struct.unpack_from("<I", ws_image, config_offset + 28)[0]
            assert native_version > 0 and config_struct_size > metadata_size > 0 and route_count == 1
            config_end = config_offset + config_blob_size
            assert config_blob_size >= 32 and config_end <= len(ws_image), (
                config_offset,
                config_blob_size,
                len(ws_image),
            )
            config_blob = ws_image[config_offset:config_end]
            path_marker = b"/ws-limit-contract\x00"
            assert config_blob.count(path_marker) == 1, "native route metadata must contain its path once"
            path_offset = config_blob.find(path_marker)
            size_marker = struct.pack("<I", 16001)
            size_offsets = [
                match.start()
                for match in re.finditer(re.escape(size_marker), config_blob)
                if path_offset < match.start()
            ]
            assert len(size_offsets) == 1, (path_offset, size_offsets)
            size_offset = config_offset + size_offsets[0]
            for invalid_size in (0, 16371, 0xFFFFFFFF):
                damaged = bytearray(ws_image)
                before = bytes(damaged[size_offset : size_offset + 4])
                damaged[size_offset : size_offset + 4] = struct.pack("<I", invalid_size)
                changed = [index for index, pair in enumerate(zip(ws_image, damaged)) if pair[0] != pair[1]]
                assert changed and min(changed) >= size_offset and max(changed) < size_offset + 4, changed
                assert before == size_marker
                frame_hex = (ws_header + damaged).hex()
                helper.write_text(
                    f"#!{sys.executable}\nimport os\n"
                    f"view=memoryview(bytes.fromhex({frame_hex!r}))\n"
                    "while view:\n"
                    " written=os.write(1, view)\n"
                    " view=view[written:]\n"
                    "os._exit(0)\n"
                )
                helper.chmod(0o700)
                run = subprocess.run(
                    [str(server), "--compile", str(ws_source), "--shards", "1", "--no-pin"],
                    capture_output=True,
                    timeout=5,
                )
                diagnostic = run.stderr.decode()
                assert run.returncode != 0 and "invalid native WebSocket message limit" in diagnostic, (
                    invalid_size,
                    diagnostic,
                )
                assert "cannot rebuild native route index" not in diagnostic, diagnostic
            print(json.dumps({"case": "native WebSocket message limits fail before route dispatch rebuild"}))

        helper.write_text(f"#!{sys.executable}\nimport os\nos._exit(37)\n")
        helper.chmod(0o700)
        run = subprocess.run(
            [str(server), "--compile", str(source), "--shards", "1", "--no-pin"],
            capture_output=True,
            timeout=5,
        )
        diagnostic = run.stderr.decode()
        assert run.returncode != 0 and "failed during header:" in diagnostic, diagnostic
        assert any(text in diagnostic for text in (
            "status observed during SIGKILL cleanup: exit code 37",
            "status observed during SIGKILL cleanup: signal 9",
            "post-cleanup status unavailable",
        )), diagnostic
        assert "Listening on" not in diagnostic, diagnostic
        print(json.dumps({"case": "compiler exits before header", "diagnostic": diagnostic.strip()}))

        grandchild_pid_file = root / "header-failure-grandchild.pid"
        helper.write_text(
            f"#!{sys.executable}\nimport os,time\n"
            "leader_pid=os.getpid()\n"
            "grandchild=os.fork()\n"
            "if grandchild == 0:\n"
            " while os.getppid() == leader_pid:\n"
            "  time.sleep(0.001)\n"
            " os.close(1)\n"
            " os.close(2)\n"
            " time.sleep(30)\n"
            " os._exit(0)\n"
            f"with open({str(grandchild_pid_file)!r}, 'w') as marker:\n"
            " marker.write(f'{leader_pid},{grandchild}')\n"
            "os.close(1)\n"
            "os._exit(37)\n"
        )
        helper.chmod(0o700)
        unconfirmed_pids = set()
        group_cleanup_passed = False
        try:
            run = subprocess.run(
                [str(server), "--compile", str(source), "--shards", "1", "--no-pin"],
                capture_output=True,
                timeout=5,
            )
            diagnostic = run.stderr.decode()
            assert run.returncode != 0 and "failed during header:" in diagnostic, diagnostic
            assert grandchild_pid_file.exists(), diagnostic
            producer_pid, grandchild_pid = map(int, grandchild_pid_file.read_text().split(','))
            unconfirmed_pids.update((producer_pid, grandchild_pid))
            for pid in (producer_pid, grandchild_pid):
                wait_dead(pid)
                unconfirmed_pids.discard(pid)
            group_cleanup_passed = True
        finally:
            if not group_cleanup_passed and not unconfirmed_pids and grandchild_pid_file.exists():
                unconfirmed_pids.update(
                    map(int, grandchild_pid_file.read_text().split(',')))
            for pid in unconfirmed_pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        print(json.dumps({"case": "header failure reaps compiler process group",
                          "diagnostic": diagnostic.strip()}))

        frame_hex = (header + image).hex()
        helper.write_text(
            f"#!{sys.executable}\nimport os\n"
            f"view=memoryview(bytes.fromhex({frame_hex!r}))\n"
            "while view:\n"
            " written=os.write(1, view)\n"
            " view=view[written:]\n"
            "os._exit(37)\n"
        )
        helper.chmod(0o700)
        run = subprocess.run(
            [str(server), "--compile", str(source), "--shards", "1", "--no-pin"],
            capture_output=True,
            timeout=5,
        )
        diagnostic = run.stderr.decode()
        assert run.returncode != 0 and "failed during tail: exit code 37" in diagnostic, diagnostic
        assert "Listening on" not in diagnostic, diagnostic
        print(json.dumps({"case": "compiler exits after artifact", "diagnostic": diagnostic.strip()}))
        for signal_name in ("SIGINT", "SIGTERM"):
            for mode in ("header", "tail", "eof"):
                source.write_text('route GET "/" { return 200 }\n')
                check_startup_cancellation(
                    server, source, header, image, signal_name, mode, root)
            check_startup_cancellation(
                server, source, header, image, signal_name, "header", root, grandchild=True)
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
            try:
                os.kill(producer_pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise AssertionError((name, producer_pid))
            print(json.dumps({"case": name, "exit_code": run.returncode,
                              "diagnostic": diagnostic.strip()}))


if __name__ == "__main__":
    main()
