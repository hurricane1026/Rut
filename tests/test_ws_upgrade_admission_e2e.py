#!/usr/bin/env python3
"""End-to-end admission checks for terminate and generic Upgrade routes."""

import argparse
import os
import select
import socket
import ssl
import subprocess
import tempfile
import threading
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


def recv_http_response(sock, timeout=3.0):
    sock.settimeout(timeout)
    header = bytearray()
    while not header.endswith(b"\r\n\r\n"):
        part = sock.recv(1)
        if not part:
            raise AssertionError("connection closed before HTTP response headers")
        header.extend(part)
    content_length = 0
    for line in header.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
            break
    return bytes(header) + recv_exact(sock, content_length)


def ws_upgrade_request(origin, connection=b"Upgrade", tail=False):
    origin_header = b"" if origin is None else origin
    request = (
        b"GET /ws HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\nConnection: " +
        connection + b"\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n" + origin_header + b"\r\n")
    return request + (masked_frame(1, b"COALESCED-TAIL") if tail else b"")


def launch(server, source, backend, extra_args=()):
    process = subprocess.Popen(
        [server, "--compile", source, "--shards", "1", "--no-pin", "--drain", "0", "--backend", backend,
         *extra_args],
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


def admission_scenario(server, backend_kind):
    ws_backend = socket.socket()
    ws_backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ws_backend.bind(("127.0.0.1", 0))
    ws_backend.listen(4)
    ws_backend.settimeout(0.5)
    normal_backend = socket.socket()
    normal_backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    normal_backend.bind(("127.0.0.1", 0))
    normal_backend.listen(1)
    normal_backend.settimeout(3)
    source = (
        f'listen 127.0.0.1:0\n'
        f'upstream ws at "127.0.0.1:{ws_backend.getsockname()[1]}"\n'
        f'upstream normal at "127.0.0.1:{normal_backend.getsockname()[1]}"\n'
        'route GET "/ws" {\n'
        '  guard let origin = req.uniqueHeader("Origin") else { return 403 }\n'
        '  guard origin == "https://allowed.example" else { return 403 }\n'
        '  return websocket(ws) { message in\n'
        '    guard message.text != "DROP" else { message.drop() }\n'
        '    message.forward("REWRITTEN")\n'
        '  }\n'
        '}\n'
        'route GET "/next" { return forward(normal, load_balance: .roundRobin) }\n'
    )
    with tempfile.TemporaryDirectory(prefix="rut-ws-admission-") as temp:
        path = os.path.join(temp, "route.rut")
        with open(path, "w", encoding="utf-8") as route_file:
            route_file.write(source)
        process, port, diagnostic = launch(server, path, backend_kind)
        if process is None:
            ws_backend.close()
            normal_backend.close()
            text = diagnostic.decode(errors="replace")
            if backend_kind == "io_uring" and \
                    "--backend io_uring requested, but io_uring is unavailable" in text:
                return "skip", text
            raise AssertionError(f"{backend_kind} server failed before listen:\n{text}")

        peers = []
        clients = []
        try:
            # The local deny response must happen before opening any backend socket.
            cases = (
                (b"", "missing Origin"),
                (b"Origin: https://wrong.example\r\n", "wrong Origin"),
                (b"Origin: https://allowed.example\r\nOrigin: https://wrong.example\r\n",
                 "duplicate Origin"),
            )
            for headers, label in cases:
                client = socket.create_connection(("127.0.0.1", port), timeout=3)
                clients.append(client)
                client.sendall(ws_upgrade_request(headers, tail=True))
                denied = recv_http_response(client)
                if not denied.startswith(b"HTTP/1.1 403"):
                    raise AssertionError(f"{label} did not get local 403: {denied!r}")
                try:
                    peer, _ = ws_backend.accept()
                    peers.append(peer)
                except TimeoutError:
                    pass
                else:
                    raise AssertionError(f"{label} opened a WebSocket upstream connection")
                client.close()
                clients.remove(client)

            # After a rejected keepalive request, a normal forward route on the same
            # connection remains ordinary HTTP and reaches its own upstream.
            client = socket.create_connection(("127.0.0.1", port), timeout=3)
            clients.append(client)
            client.sendall(ws_upgrade_request(None, connection=b"keep-alive"))
            denied = recv_http_response(client)
            if not denied.startswith(b"HTTP/1.1 403"):
                raise AssertionError(f"keepalive deny did not get 403: {denied!r}")
            client.sendall(b"GET /next HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            normal_peer, _ = normal_backend.accept()
            peers.append(normal_peer)
            if not recv_until(normal_peer, b"\r\n\r\n").startswith(b"GET /next "):
                raise AssertionError("normal keepalive successor was not forwarded")
            normal_peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            response = recv_http_response(client)
            if not response.startswith(b"HTTP/1.1 200"):
                raise AssertionError(f"normal keepalive successor response was lost: {response!r}")
            client.close()
            clients.remove(client)

            # Correct Origin reaches the upstream, permits 101, drops one message,
            # and rewrites the next before forwarding it.
            client = socket.create_connection(("127.0.0.1", port), timeout=3)
            clients.append(client)
            client.sendall(
                b"GET /ws HTTP/1.1\r\nHost: test\r\nOrigin: https://allowed.example\r\n"
                b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
            peer, _ = ws_backend.accept()
            peers.append(peer)
            forwarded = recv_until(peer, b"\r\n\r\n")
            if b"Origin: https://allowed.example" not in forwarded:
                raise AssertionError("allowed Origin was not preserved to upstream")
            peer.sendall(WS_RESPONSE_HEADERS)
            headers = recv_until(client, b"\r\n\r\n")
            if not headers.startswith(b"HTTP/1.1 101"):
                raise AssertionError(f"allowed Origin did not receive 101: {headers!r}")
            client.sendall(masked_frame(1, b"DROP"))
            peer.settimeout(0.25)
            try:
                dropped = peer.recv(4096)
            except TimeoutError:
                dropped = b""
            if dropped:
                raise AssertionError(f"DROP message reached upstream: {dropped!r}")
            client.sendall(masked_frame(1, b"ALLOW"))
            peer.settimeout(3)
            opcode, payload, masked = recv_client_frame(peer)
            if opcode != 1 or payload != b"REWRITTEN" or not masked:
                raise AssertionError(
                    f"expected rewritten masked Text message; got {opcode=} {payload=!r} {masked=}")
        finally:
            for peer in peers:
                peer.close()
            for client in clients:
                client.close()
            ws_backend.close()
            normal_backend.close()
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return "pass", ""


def tls_passthrough_scenario(server, backend_kind):
    cert = os.path.join(os.path.dirname(__file__), "fixtures", "localhost_cert.pem")
    key = os.path.join(os.path.dirname(__file__), "fixtures", "localhost_key.pem")
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(8)
    errors = []

    def serve_backend():
        try:
            peer, _ = listener.accept()
            with peer:
                forwarded = recv_until(peer, b"\r\n\r\n", timeout=5)
                if not forwarded.startswith(b"GET /ws "):
                    raise AssertionError(f"TLS passthrough route sent unexpected request: {forwarded!r}")
                peer.sendall(RAW_RESPONSE)
        except Exception as error:  # report listener/thread failures in the main test
            errors.append(error)

    thread = threading.Thread(target=serve_backend, daemon=True)
    thread.start()
    source = (
        f'upstream ws at "127.0.0.1:{listener.getsockname()[1]}"\n'
        'route GET "/ws" { return websocket(ws) }\n'
    )
    with tempfile.TemporaryDirectory(prefix="rut-ws-tls-passthrough-") as temp:
        path = os.path.join(temp, "route.rut")
        with open(path, "w", encoding="utf-8") as route_file:
            route_file.write(source)
        process, port, diagnostic = launch(
            server, path, backend_kind, ("0", "--tls-cert", cert, "--tls-key", key))
        if process is None:
            listener.close()
            text = diagnostic.decode(errors="replace")
            if backend_kind == "io_uring" and \
                    "--backend io_uring requested, but io_uring is unavailable" in text:
                return "skip", text
            raise AssertionError(f"{backend_kind} TLS passthrough failed before listen:\n{text}")
        client = None
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(["http/1.1"])
            raw = socket.create_connection(("127.0.0.1", port), timeout=3)
            client = context.wrap_socket(raw, server_hostname="localhost")
            client.sendall(REQUEST)
            received = recv_until(client, b"UNINSPECTED-WIRE-MARKER", timeout=8)
            if not received.startswith(b"HTTP/1.1 101") or b"UNINSPECTED-WIRE-MARKER" not in received:
                raise AssertionError(f"generic TLS WebSocket tunnel altered the 101: {received!r}")
            thread.join(timeout=8)
            if errors:
                raise AssertionError(f"TLS backend failed: {errors[0]}")
        finally:
            if client is not None:
                client.close()
            listener.close()
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
        status, details = admission_scenario(args.server, backend)
        if status == "skip":
            print(f"SKIP {backend}: {details.strip()}")
        else:
            print(f"PASS {backend} HTTP admission / zero-connect / keepalive / message rewrite")
        status, details = tls_passthrough_scenario(args.server, backend)
        if status == "skip":
            print(f"SKIP {backend}: {details.strip()}")
        else:
            print(f"PASS {backend} TLS passthrough")
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
