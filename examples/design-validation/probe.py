#!/usr/bin/env python3
import argparse
import concurrent.futures
import http.client
import os
import socket
import threading
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def recv_exact(conn, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = conn.recv(remaining)
        if not chunk:
            raise RuntimeError(f"connection closed with {remaining} bytes remaining")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def keepalive(port):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    conn.request("GET", "/health")
    first = conn.getresponse()
    first.read()
    require(first.status == 204, f"first keep-alive response returned {first.status}")
    local_port = conn.sock.getsockname()[1]
    conn.request("GET", "/health")
    second = conn.getresponse()
    second.read()
    require(second.status == 204, f"second keep-alive response returned {second.status}")
    require(conn.sock.getsockname()[1] == local_port, "second request opened a new connection")
    conn.close()


def concurrency(port, count):
    workers = min(count, 16)
    require(count % workers == 0, "concurrency count must be divisible by worker count")
    barrier = threading.Barrier(workers, timeout=3)

    def one(_):
        barrier.wait()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        conn.request("GET", "/concurrent")
        response = conn.getresponse()
        response.read()
        conn.close()
        return response.status

    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        statuses = list(pool.map(one, range(count)))
    elapsed = time.monotonic() - started
    require(statuses == [204] * count, f"concurrent response statuses: {statuses}")
    serialized_seconds = count * 0.1
    require(
        elapsed < serialized_seconds * 0.5,
        f"concurrent timer requests took {elapsed:.3f}s; serialized bound is "
        f"{serialized_seconds * 0.5:.3f}s",
    )


def pipeline(port):
    request = (
        "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n"
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    ).encode()
    chunks = []
    with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
        conn.sendall(request)
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if b"".join(chunks).count(b"\r\n\r\n") >= 2:
                break
    response = b"".join(chunks)
    header_blocks = response.split(b"\r\n\r\n")
    require(
        len(header_blocks) >= 3,
        f"incomplete pipelined headers: {response.decode('latin1')}",
    )
    require(
        all(block.startswith(b"HTTP/1.1 204 No Content\r\n") for block in header_blocks[:2]),
        f"incomplete pipelined response: {response.decode('latin1')}",
    )


def wait_port(port, pid, timeout):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError as error:
            raise RuntimeError(f"fixture process {pid} exited before listening") from error
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError as error:
            last_error = error
            time.sleep(0.05)
    raise RuntimeError(f"fixture process {pid} did not listen on port {port}: {last_error}")


def websocket(port):
    request = (
        "GET /ws HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    ).encode()
    with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
        conn.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = conn.recv(4096)
            if not chunk:
                raise RuntimeError("connection closed before the WebSocket handshake completed")
            response.extend(chunk)
        header_end = response.index(b"\r\n\r\n") + 4
        text = response[:header_end].decode("latin1")
        require(text.startswith("HTTP/1.1 101 "), text)
        headers = {}
        for line in text.split("\r\n")[1:]:
            if not line:
                continue
            name, separator, value = line.partition(":")
            require(bool(separator), f"malformed WebSocket response header: {line!r}")
            headers.setdefault(name.strip().lower(), []).append(value.strip())
        require(
            any(value.lower() == "websocket" for value in headers.get("upgrade", [])),
            f"missing Upgrade: websocket response header: {text}",
        )
        connection_tokens = {
            token.strip().lower()
            for value in headers.get("connection", [])
            for token in value.split(",")
        }
        require("upgrade" in connection_tokens, f"missing Connection: Upgrade token: {text}")
        expected_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        require(
            headers.get("sec-websocket-accept") == [expected_accept],
            f"invalid Sec-WebSocket-Accept response header: {text}",
        )

        payload = b"rut"
        mask = b"\x01\x02\x03\x04"
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        conn.sendall(bytes((0x81, 0x80 | len(payload))) + mask + masked)
        frame = bytes(response[header_end:])
        if len(frame) < 2:
            frame += recv_exact(conn, 2 - len(frame))
        require(frame[0] == 0x81, f"unexpected WebSocket opcode: {frame[0]:#x}")
        length = frame[1] & 0x7F
        require((frame[1] & 0x80) == 0, "origin echo frame must not be masked")
        require(length < 126, f"unexpected WebSocket echo length: {length}")
        body = frame[2:]
        if len(body) < length:
            body += recv_exact(conn, length - len(body))
        require(body[:length] == payload, f"unexpected WebSocket echo payload: {body[:length]!r}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "probe", choices=("keepalive", "pipeline", "concurrency", "websocket", "wait-port")
    )
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--count", type=int, default=32)
    parser.add_argument("--pid", type=int)
    parser.add_argument("--timeout", type=float, default=5)
    args = parser.parse_args()
    if args.probe == "keepalive":
        keepalive(args.port)
    elif args.probe == "pipeline":
        pipeline(args.port)
    elif args.probe == "concurrency":
        concurrency(args.port, args.count)
    elif args.probe == "wait-port":
        require(args.pid is not None, "wait-port requires --pid")
        wait_port(args.port, args.pid, args.timeout)
    else:
        websocket(args.port)


if __name__ == "__main__":
    main()
