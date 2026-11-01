#!/usr/bin/env python3
"""End-to-end admission checks for terminate and generic Upgrade routes."""

import argparse
import os
import select
import socket
import subprocess
import tempfile
import time


REQUEST = (
    b"GET /ws HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\n"
    b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    b"Sec-WebSocket-Version: 13\r\n\r\n"
)
CLIENT_TAIL = b"CLIENT-TAIL-MARKER"
RAW_RESPONSE = (
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
    b"Upgrade: h2c\r\n\r\nUNINSPECTED-WIRE-MARKER"
)
MISSING_CONNECTION_RESPONSE = (
    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
    b"UNINSPECTED-WIRE-MARKER"
)
WS_RESPONSE_HEADERS = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: WebSocket\r\n\r\n"


def masked_frame(opcode, payload):
    key = b"\x12\x34\x56\x78"
    masked = bytes(value ^ key[index & 3] for index, value in enumerate(payload))
    return bytes((0x80 | opcode, 0x80 | len(payload))) + key + masked


def recv_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise AssertionError("unexpected EOF while reading WebSocket frame")
        data.extend(part)
    return bytes(data)


def recv_client_frame(sock):
    first, second = recv_exact(sock, 2)
    if second & 0x7F >= 126:
        raise AssertionError("short test frame unexpectedly used an extended length")
    length = second & 0x7F
    mask_key = recv_exact(sock, 4) if second & 0x80 else b""
    payload = bytearray(recv_exact(sock, length))
    if mask_key:
        for index in range(length):
            payload[index] ^= mask_key[index & 3]
    return first & 0x0F, bytes(payload), bool(mask_key)


def recv_until(sock, marker, timeout=3.0):
    sock.settimeout(timeout)
    data = bytearray()
    while marker not in data:
        part = sock.recv(4096)
        if not part:
            break
        data.extend(part)
    return bytes(data)


def launch(server, source, backend):
    process = subprocess.Popen(
        [server, "--compile", source, "--shards", "1", "--no-pin", "--drain", "0", "--backend", backend],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=False,
    )
    log = bytearray()
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        ready, _, _ = select.select([process.stderr], [], [], 0.25)
        if ready:
            part = os.read(process.stderr.fileno(), 4096)
            if not part:
                break
            log.extend(part)
            for line in log.splitlines():
                if line.startswith(b"Listening on port "):
                    try:
                        return process, int(line.split()[3]), bytes(log)
                    except (ValueError, IndexError):
                        break
        if process.poll() is not None:
            break
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    return None, None, bytes(log)


def scenario(server, backend_kind, terminate, response, expected):
    upstream = socket.socket()
    upstream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(1)
    upstream.settimeout(3)
    upstream_port = upstream.getsockname()[1]
    block = " { message in message.drop() }" if terminate else ""
    source = (
        f'listen 127.0.0.1:0\nupstream backend at "127.0.0.1:{upstream_port}"\n'
        f'route GET "/ws" {{ return websocket(backend){block} }}\n'
    )
    with tempfile.TemporaryDirectory(prefix="rut-ws-upgrade-") as temp:
        path = os.path.join(temp, "route.rut")
        with open(path, "w", encoding="utf-8") as route_file:
            route_file.write(source)
        process, port, diagnostic = launch(server, path, backend_kind)
        if process is None:
            upstream.close()
            text = diagnostic.decode(errors="replace")
            if backend_kind == "io_uring" and \
                    "--backend io_uring requested, but io_uring is unavailable" in text:
                return "skip", text
            raise AssertionError(f"{backend_kind} server failed before listen:\n{text}")

        client = peer = None
        try:
            client = socket.create_connection(("127.0.0.1", port), timeout=3)
            client.sendall(REQUEST + CLIENT_TAIL if expected == "reject" else REQUEST)
            peer, _ = upstream.accept()
            forwarded_request = recv_until(peer, b"\r\n\r\n")
            if expected == "reject" and CLIENT_TAIL in forwarded_request:
                raise AssertionError("client pipeline tail was forwarded before terminate admission")
            peer.sendall(response)
            if expected == "reject":
                client.settimeout(3)
                received = client.recv(4096)
                if received:
                    raise AssertionError(f"terminate route leaked response bytes: {received!r}")
                peer.settimeout(0.25)
                try:
                    forwarded_tail = peer.recv(4096)
                except TimeoutError:
                    forwarded_tail = b""
                if CLIENT_TAIL in forwarded_tail:
                    raise AssertionError("terminate route leaked the stashed client pipeline tail")
            elif expected == "tunnel":
                received = recv_until(client, b"UNINSPECTED-WIRE-MARKER")
                if not received.startswith(b"HTTP/1.1 101") or b"UNINSPECTED-WIRE-MARKER" not in received:
                    raise AssertionError(f"generic passthrough did not relay the 101 tail: {received!r}")
            else:
                headers = recv_until(client, b"\r\n\r\n")
                if not headers.startswith(b"HTTP/1.1 101"):
                    raise AssertionError(f"valid WebSocket 101 was not sent: {headers!r}")
                if b"DROP" in headers:
                    raise AssertionError("terminate route forwarded the early upstream DROP")
                peer.sendall(b"\x81\x04DROP")
                client.sendall(masked_frame(1, b"DROP") + masked_frame(9, b"PING"))
                peer.settimeout(3)
                opcode, payload, masked = recv_client_frame(peer)
                if opcode != 9 or payload != b"PING" or not masked:
                    raise AssertionError(
                        f"backend should receive the masked control Ping after dropping DROP; "
                        f"got opcode={opcode} payload={payload!r}"
                    )
                peer.sendall(b"\x8a\x04PONG")
                opcode, payload, masked = recv_client_frame(client)
                if opcode != 10 or payload != b"PONG" or masked:
                    raise AssertionError(
                        f"client should receive only the unmasked control Pong; "
                        f"got opcode={opcode} payload={payload!r}"
                    )
        finally:
            if peer is not None:
                peer.close()
            if client is not None:
                client.close()
            upstream.close()
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return "pass", ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    args = parser.parse_args()
    for backend in ("epoll", "io_uring"):
        for terminate, response, expected in (
            (True, RAW_RESPONSE, "reject"),
            (True, MISSING_CONNECTION_RESPONSE, "reject"),
            (True, WS_RESPONSE_HEADERS, "drop"),
            (False, RAW_RESPONSE, "tunnel"),
        ):
            status, details = scenario(args.server, backend, terminate, response, expected)
            if status == "skip":
                print(f"SKIP {backend}: {details.strip()}")
                break
            print(f"PASS {backend} terminate={terminate} expected={expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
