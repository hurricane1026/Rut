#!/usr/bin/env python3
import argparse
import concurrent.futures
import http.client
import os
import socket
import threading
import time
from pathlib import Path


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


def timer_wait(port):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)

    def elapsed(path):
        started = time.monotonic()
        conn.request("GET", path)
        response = conn.getresponse()
        response.read()
        duration = time.monotonic() - started
        require(response.status == 204, f"{path} returned {response.status}")
        return duration

    elapsed("/health")
    control = min(elapsed("/health") for _ in range(3))
    timer = elapsed("/concurrent")
    conn.close()
    require(timer >= 0.08, f"timer request completed too quickly: {timer:.3f}s")
    require(
        timer - control >= 0.06,
        f"timer request ({timer:.3f}s) was not delayed relative to control ({control:.3f}s)",
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


def no_content_length(port):
    request = b"POST /upload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
        conn.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = conn.recv(4096)
            if not chunk:
                raise RuntimeError("connection closed before the response headers completed")
            response.extend(chunk)
        header, body = bytes(response).split(b"\r\n\r\n", 1)
        lines = header.split(b"\r\n")
        require(lines[0].startswith(b"HTTP/1.1 411 "), header.decode("latin1"))
        content_lengths = [
            value.strip()
            for name, separator, value in (line.partition(b":") for line in lines[1:])
            if separator and name.strip().lower() == b"content-length"
        ]
        require(content_lengths == [b"7"], f"invalid Content-Length response: {header!r}")
        if len(body) < 7:
            body += recv_exact(conn, 7 - len(body))
        require(body == b"Unknown", f"unexpected no-Content-Length response body: {body!r}")


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


def websocket_connect(port, path):
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    ).encode()
    conn = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
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
        return conn, bytes(response[header_end:])
    except Exception:
        conn.close()
        raise


def send_websocket_text(conn, payload):
    require(len(payload) < 126, "test WebSocket payload must use the short frame form")
    mask = b"\x01\x02\x03\x04"
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    conn.sendall(bytes((0x81, 0x80 | len(payload))) + mask + masked)


def recv_websocket_text(conn, buffered=b""):
    frame = buffered
    if len(frame) < 2:
        frame += recv_exact(conn, 2 - len(frame))
    require(frame[0] == 0x81, f"unexpected WebSocket opcode: {frame[0]:#x}")
    length = frame[1] & 0x7F
    require((frame[1] & 0x80) == 0, "origin echo frame must not be masked")
    require(length < 126, f"unexpected WebSocket echo length: {length}")
    body = frame[2:]
    if len(body) < length:
        body += recv_exact(conn, length - len(body))
    return body[:length]


def websocket(port):
    conn, buffered = websocket_connect(port, "/ws")
    with conn:
        payload = b"rut"
        send_websocket_text(conn, payload)
        echo = recv_websocket_text(conn, buffered)
        require(echo == payload, f"unexpected WebSocket echo payload: {echo!r}")


def websocket_filter(port):
    conn, buffered = websocket_connect(port, "/ws-filter")
    with conn:
        send_websocket_text(conn, b"blocked")
        send_websocket_text(conn, b"allowed")
        echo = recv_websocket_text(conn, buffered)
        require(echo == b"allowed", f"terminate filter forwarded the wrong payload: {echo!r}")


def wait_for_access_log_shards(access_log, request_path, count):
    deadline = time.monotonic() + 5
    observed = []
    while time.monotonic() < deadline:
        observed = []
        contents = Path(access_log).read_text()
        complete_end = contents.rfind("\n")
        for line in contents[: complete_end + 1].splitlines():
            fields = line.split()
            if len(fields) < 9 or fields[2] != request_path:
                continue
            require(
                fields[-1].startswith("s="),
                f"malformed access-log shard field: {line!r}",
            )
            observed.append(int(fields[-1][2:]))
        if len(observed) >= count:
            shards = set(observed)
            require(shards == {0, 1}, f"shared rate-limit requests reached shards {shards}")
            return
        time.sleep(0.05)
    raise RuntimeError(
        f"access log recorded {len(observed)}/{count} shared rate-limit requests"
    )


def global_rate_limit(port, count, access_log):
    barrier = threading.Barrier(count, timeout=5)

    def one(_):
        barrier.wait()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        conn.request("GET", "/global-limit?key=shared", headers={"X-Client": "shared"})
        response = conn.getresponse()
        response.read()
        conn.close()
        return response.status

    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
        statuses = list(pool.map(one, range(count)))
    require(statuses.count(204) == 2, f"global rate limit admitted {statuses.count(204)}: {statuses}")
    require(statuses.count(429) == count - 2, f"global rate limit statuses: {statuses}")
    wait_for_access_log_shards(access_log, "/global-limit?key=shared", count)

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    conn.request("GET", "/global-limit?key=independent", headers={"X-Client": "independent"})
    response = conn.getresponse()
    response.read()
    conn.close()
    require(response.status == 204, f"independent rate-limit key returned {response.status}")


def active_health(port, state_file):
    def result():
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        conn.request("GET", "/health-proxy")
        response = conn.getresponse()
        body = response.read()
        conn.close()
        return response.status, body

    def wait_for(expected):
        deadline = time.monotonic() + 5
        observed = []
        while time.monotonic() < deadline:
            current = result()
            observed.append(current)
            if current == expected:
                return
            time.sleep(0.1)
        raise RuntimeError(f"active health never returned {expected}; observed {observed}")

    wait_for((503, b"Service Unavailable"))
    Path(state_file).write_text("up\n")
    wait_for((200, b"origin-ok"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "probe",
        choices=(
            "keepalive",
            "pipeline",
            "concurrency",
            "no-content-length",
            "timer-wait",
            "websocket",
            "websocket-filter",
            "global-rate-limit",
            "active-health",
            "wait-port",
        ),
    )
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--count", type=int, default=32)
    parser.add_argument("--pid", type=int)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--state-file")
    parser.add_argument("--access-log")
    args = parser.parse_args()
    if args.probe == "keepalive":
        keepalive(args.port)
    elif args.probe == "pipeline":
        pipeline(args.port)
    elif args.probe == "concurrency":
        concurrency(args.port, args.count)
    elif args.probe == "no-content-length":
        no_content_length(args.port)
    elif args.probe == "timer-wait":
        timer_wait(args.port)
    elif args.probe == "wait-port":
        require(args.pid is not None, "wait-port requires --pid")
        wait_port(args.port, args.pid, args.timeout)
    elif args.probe == "websocket-filter":
        websocket_filter(args.port)
    elif args.probe == "global-rate-limit":
        require(args.access_log is not None, "global-rate-limit requires --access-log")
        global_rate_limit(args.port, args.count, args.access_log)
    elif args.probe == "active-health":
        require(args.state_file is not None, "active-health requires --state-file")
        active_health(args.port, args.state_file)
    else:
        websocket(args.port)


if __name__ == "__main__":
    main()
