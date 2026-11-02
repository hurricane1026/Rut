#!/usr/bin/env python3
"""End-to-end admission checks for terminate and generic Upgrade routes."""

import argparse
import os
import select
import shutil
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
WS_RESPONSE_HEADERS = (
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: WebSocket\r\n"
    b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
)
BAD_ACCEPT_RESPONSE = (
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
    b"Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n"
)
UNSOLICITED_PROTOCOL_RESPONSE = (
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
    b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
    b"Sec-WebSocket-Protocol: chat\r\n\r\n"
)


def masked_frame(opcode, payload):
    key = b"\x12\x34\x56\x78"
    masked = bytes(value ^ key[index & 3] for index, value in enumerate(payload))
    return bytes((0x80 | opcode, 0x80 | len(payload))) + key + masked


BINARY_HANDLER = r'''
return websocket(ws) { message in
    guard message.len != 0 else { message.forward(b"") }
    guard message.text != "TEXT" else { message.forward("OK") }
    guard message.text != "PASS" else { message.forward() }
    guard message.text != "CLOSE" else { message.close(1000) }
    message.forward(b"\x00\xff\x80")
}
'''


def binary_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"binary replacement: {actual=!r}, {expected=!r}")

    first = bytearray(masked_frame(2, b"\xff"))
    first[0] &= 0x7F
    client.sendall(first + masked_frame(9, b"PING") + masked_frame(0, b"\x80"))
    expect(peer, (9, b"PING", True))
    expect(peer, (2, b"\0\xff\x80", True))
    client.sendall(masked_frame(1, b"") + masked_frame(1, b"TEXT") + masked_frame(1, b"PASS"))
    expect(peer, (2, b"", True))
    expect(peer, (1, b"OK", True))
    expect(peer, (1, b"PASS", True))
    peer.sendall(b"\x01\x01a\x8a\x01p\x80\x01b")
    expect(client, (10, b"p", False))
    expect(client, (2, b"\0\xff\x80", False))
    peer.sendall(b"\x82\x04TEXT\x82\x04PASS")
    expect(client, (1, b"OK", False))
    expect(client, (2, b"PASS", False))
    client.sendall(masked_frame(1, b"CLOSE"))
    expect(peer, (8, b"\x03\xe8", True))
    expect(client, (8, b"\x03\xe8", False))


NESTED_JSON_HANDLER = r"""
return websocket(ws) { message in
    guard let document = json.parse(message.text) else { message.close(1007) }
    guard let parent = json.get(document, "/payload") else { message.close(1008) }
    guard let child = json.get(parent, "/name") else { message.close(1008) }
    guard let text = json.string(child) else { message.close(1003) }
    message.forward("[" + text + "]")
}
"""


def nested_json_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"nested JSON projection: {actual=!r}, {expected=!r}")

    payload = b'{"payload":{"name":"hello"}}'
    first = bytearray(masked_frame(1, payload[:13]))
    first[0] &= 0x7F
    client.sendall(first + masked_frame(9, b"PING") + masked_frame(0, payload[13:]))
    expect(peer, (9, b"PING", True))
    expect(peer, (1, b"[hello]", True))
    client.sendall(masked_frame(2, b'{"payload":{"name":""}}') +
                   masked_frame(1, b'{"payload":{"name":"x\\u0000\\u20ac"}}'))
    expect(peer, (1, b"[]", True))
    expect(peer, (1, b"[x\0\xe2\x82\xac]", True))
    peer.sendall(bytes((0x02, 13)) + payload[:13] + b"\x8a\x01p" +
                 bytes((0x80, len(payload) - 13)) + payload[13:])
    expect(client, (10, b"p", False))
    expect(client, (1, b"[hello]", False))
    client.sendall(masked_frame(1, b'{"payload":{"name":false}}'))
    expect(peer, (8, b"\x03\xeb", True))
    expect(client, (8, b"\x03\xeb", False))


def binary_replacement_scenario(server, backend_kind, handler=BINARY_HANDLER, exchange=binary_exchange):
    with socket.socket() as upstream, tempfile.TemporaryDirectory(prefix="rut-ws-binary-") as temp:
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        upstream.settimeout(3)
        path = os.path.join(temp, "route.rut")
        with open(path, "w", encoding="utf-8") as route_file:
            route_file.write(
                f'listen 127.0.0.1:0\n'
                f'upstream ws at "127.0.0.1:{upstream.getsockname()[1]}"\n'
                'route GET "/ws" {\n' + handler + '}\n')
        process, port, diagnostic = launch(server, path, backend_kind)
        if process is None:
            text = diagnostic.decode(errors="replace")
            if backend_kind == "io_uring" and \
                    "--backend io_uring requested, but io_uring is unavailable" in text:
                return "skip", text
            raise AssertionError(f"{backend_kind} binary replacement server failed:\n{text}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.sendall(REQUEST)
                with upstream.accept()[0] as peer:
                    peer.settimeout(3)
                    recv_until(peer, b"\r\n\r\n")
                    peer.sendall(WS_RESPONSE_HEADERS)
                    if not recv_until(client, b"\r\n\r\n").startswith(b"HTTP/1.1 101"):
                        raise AssertionError("binary replacement handshake failed")
                    exchange(client, peer)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return "pass", ""


def native_binary_source_removal_scenario(server, compiler, backend_kind,
                                         handler=BINARY_HANDLER, exchange=binary_exchange):
    with socket.socket() as upstream, tempfile.TemporaryDirectory(prefix="rut-ws-native-") as temp:
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        upstream.settimeout(3)
        source = os.path.join(temp, "route.rut")
        artifact = os.path.join(temp, "route.native")
        with open(source, "w", encoding="utf-8") as route_file:
            route_file.write(
                f'listen 127.0.0.1:0\nupstream ws at "127.0.0.1:{upstream.getsockname()[1]}"\n'
                'route GET "/ws" { ' + handler + '}\n')
        emitted = subprocess.run([compiler, source, "2"], capture_output=True, check=True, timeout=30)
        with open(artifact, "wb") as artifact_file:
            artifact_file.write(emitted.stdout)
        os.unlink(source)
        native_server = os.path.join(temp, "rut")
        shutil.copy2(server, native_server)
        wrapper = os.path.join(temp, "rut-compile")
        with open(wrapper, "w", encoding="utf-8") as wrapper_file:
            wrapper_file.write(
                "#!/usr/bin/env python3\nimport os\n"
                "fd=os.open(" + repr(artifact) + ", os.O_RDONLY)\n"
                "try:\n"
                "    while True:\n"
                "        chunk=os.read(fd,65536)\n"
                "        if not chunk: break\n"
                "        view=memoryview(chunk)\n"
                "        while view:\n"
                "            n=os.write(1,view)\n"
                "            view=view[n:]\n"
                "finally:\n"
                "    os.close(fd)\n")
        os.chmod(wrapper, 0o700)
        process, port, diagnostic = launch(native_server, os.path.join(temp, "deleted.rut"), backend_kind)
        if process is None:
            text = diagnostic.decode(errors="replace")
            if backend_kind == "io_uring" and "--backend io_uring requested, but io_uring is unavailable" in text:
                return "skip", text
            raise AssertionError(f"{backend_kind} native binary artifact failed:\n{text}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.sendall(REQUEST.replace(b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", b"") + masked_frame(1, b"TAIL"))
                if not recv_http_response(client).startswith(b"HTTP/1.1 400"):
                    raise AssertionError("native source-removed artifact accepted malformed handshake")
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.sendall(REQUEST)
                with upstream.accept()[0] as peer:
                    peer.settimeout(3)
                    if not recv_until(peer, b"\r\n\r\n").startswith(b"GET /ws "):
                        raise AssertionError("native artifact did not forward valid handshake")
                    peer.sendall(WS_RESPONSE_HEADERS)
                    if not recv_until(client, b"\r\n\r\n").startswith(b"HTTP/1.1 101"):
                        raise AssertionError("native artifact did not relay valid 101")
                    exchange(client, peer)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return "pass", ""


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
            if expected == "reject":
                client.sendall(REQUEST + CLIENT_TAIL)
            elif expected == "drop":
                client.sendall(REQUEST + masked_frame(1, b"DROP"))
            else:
                client.sendall(REQUEST)
            peer, _ = upstream.accept()
            forwarded_request = recv_until(peer, b"\r\n\r\n")
            if expected == "reject" and CLIENT_TAIL in forwarded_request:
                raise AssertionError("client pipeline tail was forwarded before terminate admission")
            if expected == "drop" and masked_frame(1, b"DROP") in forwarded_request:
                raise AssertionError("coalesced WebSocket frame was forwarded before the 101")
            split = max(1, len(response) // 2)
            peer.sendall(response[:split])
            time.sleep(0.01)
            peer.sendall(response[split:])
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

            # A valid terminate request may receive an ordinary HTTP response.
            # Completing that response retires handshake scratch before the same
            # keepalive connection takes the next ordinary forwarding route.
            client = socket.create_connection(("127.0.0.1", port), timeout=3)
            clients.append(client)
            client.sendall(ws_upgrade_request(
                b"Origin: https://allowed.example\r\n", connection=b"Upgrade, keep-alive"))
            ws_peer, _ = ws_backend.accept()
            peers.append(ws_peer)
            recv_until(ws_peer, b"\r\n\r\n")
            ws_peer.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK")
            ordinary = recv_http_response(client)
            if not ordinary.startswith(b"HTTP/1.1 200") or not ordinary.endswith(b"OK"):
                raise AssertionError(f"non-101 terminate response was not ordinary HTTP: {ordinary!r}")
            ws_peer.close()
            peers.remove(ws_peer)
            client.sendall(b"GET /next HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            normal_peer, _ = normal_backend.accept()
            peers.append(normal_peer)
            if not recv_until(normal_peer, b"\r\n\r\n").startswith(b"GET /next "):
                raise AssertionError("ordinary route after terminate non-101 was not forwarded")
            normal_peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            ordinary = recv_http_response(client)
            if not ordinary.startswith(b"HTTP/1.1 200"):
                raise AssertionError("keepalive successor after terminate non-101 was lost")
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


def handshake_request_scenario(server, backend_kind):
    upstream = socket.socket()
    upstream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(4)
    upstream.settimeout(0.25)
    source = (
        f'listen 127.0.0.1:0\n'
        f'upstream ws at "127.0.0.1:{upstream.getsockname()[1]}"\n'
        'route GET "/ws" { return websocket(ws) { message in message.drop() } }\n'
    )
    with tempfile.TemporaryDirectory(prefix="rut-ws-handshake-") as temp:
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

        cases = (
            (b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", b"", 400, "missing Version"),
            (b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
             b"Sec-WebSocket-Version: 12\r\n", b"", 426, "wrong Version"),
            (b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
             b"Sec-WebSocket-Version: nope\r\n", b"", 400, "nonnumeric Version"),
            (b"Sec-WebSocket-Version: 13\r\n", b"", 400, "missing Key"),
            (b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
             b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
             b"Sec-WebSocket-Version: 13\r\n", b"", 400, "duplicate Key"),
        )
        try:
            for fields, tail, status, label in cases:
                client = socket.create_connection(("127.0.0.1", port), timeout=3)
                try:
                    request = (
                        b"GET /ws HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\n"
                        b"Connection: Upgrade\r\n" + fields + b"\r\n" + tail)
                    client.sendall(request + masked_frame(1, b"COALESCED-TAIL"))
                    response = recv_http_response(client)
                    if not response.startswith(f"HTTP/1.1 {status} ".encode()):
                        raise AssertionError(f"{label} got unexpected response: {response!r}")
                    if status == 426 and b"Sec-WebSocket-Version: 13\r\n" not in response:
                        raise AssertionError("426 did not advertise the supported WebSocket version")
                    if status == 426 and (
                        b"Upgrade: websocket\r\n" not in response
                        or b"Connection: Upgrade\r\n" not in response
                        or b"Connection: close\r\n" not in response
                    ):
                        raise AssertionError("426 omitted upgrade challenge or close headers")
                    try:
                        peer, _ = upstream.accept()
                    except TimeoutError:
                        pass
                    else:
                        peer.close()
                        raise AssertionError(f"{label} connected to the WebSocket upstream")
                finally:
                    client.close()
        finally:
            upstream.close()
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


def tls_terminate_handshake_scenario(server, backend_kind):
    cert = os.path.join(os.path.dirname(__file__), "fixtures", "localhost_cert.pem")
    key = os.path.join(os.path.dirname(__file__), "fixtures", "localhost_key.pem")
    backend = socket.socket()
    backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    backend.bind(("127.0.0.1", 0))
    backend.listen(1)
    backend.settimeout(0.5)
    source = (
        f'upstream ws at "127.0.0.1:{backend.getsockname()[1]}"\n'
        'route GET "/ws" { return websocket(ws) { message in message.drop() } }\n'
    )
    with tempfile.TemporaryDirectory(prefix="rut-ws-tls-terminate-") as temp:
        path = os.path.join(temp, "route.rut")
        with open(path, "w", encoding="utf-8") as route_file:
            route_file.write(source)
        process, port, diagnostic = launch(
            server, path, backend_kind, ("0", "--tls-cert", cert, "--tls-key", key))
        if process is None:
            backend.close()
            text = diagnostic.decode(errors="replace")
            if backend_kind == "io_uring" and \
                    "--backend io_uring requested, but io_uring is unavailable" in text:
                return "skip", text
            raise AssertionError(f"{backend_kind} TLS terminate failed before listen:\n{text}")

        clients = []
        peer = None
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(["http/1.1"])

            raw = socket.create_connection(("127.0.0.1", port), timeout=3)
            invalid_client = context.wrap_socket(raw, server_hostname="localhost")
            clients.append(invalid_client)
            invalid_client.sendall(
                b"GET /ws HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n"
                + masked_frame(1, b"COALESCED-TAIL"))
            denied = recv_http_response(invalid_client)
            if not denied.startswith(b"HTTP/1.1 400"):
                raise AssertionError(f"TLS malformed handshake did not get 400: {denied!r}")
            try:
                peer, _ = backend.accept()
            except TimeoutError:
                pass
            else:
                raise AssertionError("TLS malformed handshake connected upstream")
            invalid_client.close()
            clients.remove(invalid_client)

            raw = socket.create_connection(("127.0.0.1", port), timeout=3)
            valid_client = context.wrap_socket(raw, server_hostname="localhost")
            clients.append(valid_client)
            valid_client.sendall(REQUEST)
            peer, _ = backend.accept()
            peer.settimeout(3)
            if not recv_until(peer, b"\r\n\r\n").startswith(b"GET /ws "):
                raise AssertionError("TLS valid handshake request was not forwarded")
            peer.sendall(WS_RESPONSE_HEADERS)
            response = recv_until(valid_client, b"\r\n\r\n")
            if not response.startswith(b"HTTP/1.1 101"):
                raise AssertionError(f"TLS valid terminate handshake failed: {response!r}")
            valid_client.sendall(masked_frame(1, b"DROP"))
            peer.settimeout(0.25)
            try:
                leaked = peer.recv(4096)
            except TimeoutError:
                leaked = b""
            if leaked:
                raise AssertionError(f"TLS terminate DROP reached backend: {leaked!r}")
        finally:
            if peer is not None:
                peer.close()
            for client in clients:
                client.close()
            backend.close()
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return "pass", ""


def native_source_removal_scenario(server, compiler, backend_kind):
    upstream = socket.socket()
    upstream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(1)
    upstream.settimeout(0.5)
    with tempfile.TemporaryDirectory(prefix="rut-ws-native-handshake-") as temp:
        source = os.path.join(temp, "route.rut")
        artifact = os.path.join(temp, "route.native")
        with open(source, "w", encoding="utf-8") as route_file:
            route_file.write(
                f'listen 127.0.0.1:0\n'
                f'upstream ws at "127.0.0.1:{upstream.getsockname()[1]}"\n'
                'route GET "/ws" { return websocket(ws, subprotocol: "chat") { message in message.drop() } }\n'
            )
        emitted = subprocess.run([compiler, source, "2"], capture_output=True, check=True, timeout=30)
        with open(artifact, "wb") as artifact_file:
            artifact_file.write(emitted.stdout)
        os.unlink(source)
        native_server = os.path.join(temp, "rut")
        compiler_wrapper = os.path.join(temp, "rut-compile")
        shutil.copy2(server, native_server)
        with open(compiler_wrapper, "w", encoding="utf-8") as wrapper:
            wrapper.write(
                "#!/usr/bin/env python3\n"
                "import os\n"
                f"path = {artifact!r}\n"
                "fd = os.open(path, os.O_RDONLY)\n"
                "try:\n"
                "    while True:\n"
                "        chunk = os.read(fd, 65536)\n"
                "        if not chunk:\n"
                "            break\n"
                "        view = memoryview(chunk)\n"
                "        while view:\n"
                "            count = os.write(1, view)\n"
                "            view = view[count:]\n"
                "finally:\n"
                "    os.close(fd)\n"
            )
        os.chmod(compiler_wrapper, 0o700)
        missing_source = os.path.join(temp, "deleted-source.rut")
        process, port, diagnostic = launch(native_server, missing_source, backend_kind)
        if process is None:
            upstream.close()
            text = diagnostic.decode(errors="replace")
            if backend_kind == "io_uring" and \
                    "--backend io_uring requested, but io_uring is unavailable" in text:
                return "skip", text
            raise AssertionError(f"{backend_kind} native WebSocket artifact failed:\n{text}")

        client = None
        peer = None
        try:
            client = socket.create_connection(("127.0.0.1", port), timeout=3)
            client.sendall(
                b"GET /ws HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n"
                + masked_frame(1, b"COALESCED-TAIL"))
            rejected = recv_http_response(client)
            if not rejected.startswith(b"HTTP/1.1 400"):
                raise AssertionError(f"native missing-Key request did not get 400: {rejected!r}")
            try:
                peer, _ = upstream.accept()
            except TimeoutError:
                pass
            else:
                raise AssertionError("native missing-Key request connected upstream")
            client.close()

            client = socket.create_connection(("127.0.0.1", port), timeout=3)
            client.sendall(REQUEST[:-2] + b"Sec-WebSocket-Protocol: other, chat\r\n\r\n")
            peer, _ = upstream.accept()
            peer.settimeout(3)
            if not recv_until(peer, b"\r\n\r\n").startswith(b"GET /ws "):
                raise AssertionError("native valid opening handshake was not forwarded")
            peer.sendall(WS_RESPONSE_HEADERS[:-2] + b"Sec-WebSocket-Protocol: chat\r\n\r\n")
            accepted = recv_until(client, b"\r\n\r\n")
            if not accepted.startswith(b"HTTP/1.1 101"):
                raise AssertionError(f"native valid handshake did not receive 101: {accepted!r}")
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


def incomplete_upstream_101_header_close_scenario(server, backend_kind):
    backend = socket.socket()
    backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    backend.bind(("127.0.0.1", 0))
    backend.listen(2)
    backend.settimeout(2)
    source = (
        f'listen 127.0.0.1:0\n'
        f'upstream ws at "127.0.0.1:{backend.getsockname()[1]}"\n'
        'route GET "/ws" { return websocket(ws) { message in message.drop() } }\n'
    )
    with tempfile.TemporaryDirectory(prefix="rut-ws-partial-101-") as temp:
        path = os.path.join(temp, "route.rut")
        with open(path, "w", encoding="utf-8") as route_file:
            route_file.write(source)
        process, port, diagnostic = launch(server, path, backend_kind)
        if process is None:
            backend.close()
            text = diagnostic.decode(errors="replace")
            if backend_kind == "io_uring" and \
                    "--backend io_uring requested, but io_uring is unavailable" in text:
                return "skip", text
            raise AssertionError(f"{backend_kind} partial-101 server failed:\n{text}")
        client = None
        peer = None
        try:
            client = socket.create_connection(("127.0.0.1", port), timeout=3)
            client.sendall(REQUEST)
            peer, _ = backend.accept()
            recv_until(peer, b"\r\n\r\n")
            response = WS_RESPONSE_HEADERS
            split = response.find(b"\r\n\r\n") // 2
            peer.sendall(response[:split])
            time.sleep(0.02)
            client.close()
            client = None
            peer.sendall(response[split:])
            peer.settimeout(3)
            while peer.recv(4096):
                pass

            client = socket.create_connection(("127.0.0.1", port), timeout=3)
            client.sendall(
                b"GET /ws HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n")
            response = recv_http_response(client)
            if not response.startswith(b"HTTP/1.1 400"):
                raise AssertionError(f"slot after partial 101 close was not reusable: {response!r}")
        finally:
            if peer is not None:
                peer.close()
            if client is not None:
                client.close()
            backend.close()
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return "pass", ""


def subprotocol_scenario(server, backend_kind):
    upstream = socket.socket()
    upstream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(4)
    upstream.settimeout(0.25)
    with tempfile.TemporaryDirectory(prefix="rut-ws-subprotocol-") as temp:
        path = os.path.join(temp, "route.rut")
        with open(path, "w", encoding="utf-8") as source:
            source.write(
                f'listen 127.0.0.1:0\nupstream backend at "127.0.0.1:{upstream.getsockname()[1]}"\n'
                'route GET "/ws" { return websocket(backend, subprotocol: "chat") '
                '{ message in message.forward() } }\n')
        process, port, diagnostic = launch(server, path, backend_kind)
        if process is None:
            upstream.close()
            text = diagnostic.decode(errors="replace")
            if backend_kind == "io_uring" and "io_uring is unavailable" in text:
                return "skip", text
            raise AssertionError(f"subprotocol server failed: {text}")
        try:
            for offer in (b"", b"Sec-WebSocket-Protocol: Chat\r\n"):
                with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                    client.sendall(REQUEST[:-2] + offer + b"\r\n")
                    if not recv_http_response(client).startswith(b"HTTP/1.1 400 "):
                        raise AssertionError("missing/case-mismatched required offer was accepted")
                    try:
                        peer, _ = upstream.accept()
                    except TimeoutError:
                        pass
                    else:
                        peer.close()
                        raise AssertionError("missing required subprotocol connected upstream")
            for selection in (None, b"other", b"Chat", b"chat"):
                with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                    payload = b"COALESCED-SUBPROTOCOL-TAIL"
                    request = (REQUEST[:-2] + b"Sec-WebSocket-Protocol: other\r\n"
                               b"sec-websocket-protocol: chat, third\r\n\r\n")
                    client.sendall(request + masked_frame(1, payload))
                    peer, _ = upstream.accept()
                    with peer:
                        forwarded = recv_until(peer, b"\r\n\r\n")
                        protocol_fields = [line.split(b":", 1)[1].strip()
                                           for line in forwarded.split(b"\r\n")
                                           if line.lower().startswith(b"sec-websocket-protocol:")]
                        if protocol_fields != [b"chat"]:
                            raise AssertionError(f"backend offer was not restricted: {forwarded!r}")
                        if masked_frame(1, payload) in forwarded:
                            raise AssertionError("coalesced data forwarded before validated 101")
                        response = WS_RESPONSE_HEADERS[:-2]
                        if selection is not None:
                            response += b"Sec-WebSocket-Protocol: " + selection + b"\r\n"
                        peer.sendall(response + b"\r\n")
                        if selection != b"chat":
                            client.settimeout(3)
                            if client.recv(4096):
                                raise AssertionError("mismatched backend 101 escaped")
                            continue
                        response = recv_http_response(client)
                        if not response.startswith(b"HTTP/1.1 101 ") or \
                                b"Sec-WebSocket-Protocol: chat\r\n" not in response:
                            raise AssertionError(f"valid protocol not negotiated: {response!r}")
                        if recv_client_frame(peer) != (1, payload, True):
                            raise AssertionError("coalesced first message changed during header compaction")
                        peer.sendall(b"\x81\x03ACK")
                        if recv_client_frame(client) != (1, b"ACK", False):
                            raise AssertionError("negotiated tunnel did not forward upstream message")
        finally:
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
    parser.add_argument("--compiler", required=True)
    args = parser.parse_args()
    for backend in ("epoll", "io_uring"):
        status, details = binary_replacement_scenario(args.server, backend)
        if status == "skip":
            print(f"SKIP {backend}: {details.strip()}")
        else:
            print(f"PASS {backend} binary message replacement")
        status, details = native_binary_source_removal_scenario(args.server, args.compiler, backend)
        if status == "skip":
            print(f"SKIP {backend}: {details.strip()}")
        else:
            print(f"PASS {backend} native source-removed binary artifact")
        for native in (False, True):
            if native:
                status, details = native_binary_source_removal_scenario(
                    args.server, args.compiler, backend, NESTED_JSON_HANDLER, nested_json_exchange)
            else:
                status, details = binary_replacement_scenario(
                    args.server, backend, NESTED_JSON_HANDLER, nested_json_exchange)
            if status == "skip":
                print(f"SKIP {backend}: {details.strip()}")
            else:
                print(f"PASS {backend} nested JSON projection native={native}")
        status, details = subprotocol_scenario(args.server, backend)
        if status == "skip":
            print(f"SKIP {backend}: {details.strip()}")
        else:
            print(f"PASS {backend} required subprotocol / zero-connect / offer restriction / 101 gate / tail")
        status, details = incomplete_upstream_101_header_close_scenario(args.server, backend)
        if status == "skip":
            print(f"SKIP {backend}: {details.strip()}")
        else:
            print(f"PASS {backend} incomplete 101-header client close / owner retirement / slot reuse")
        status, details = native_source_removal_scenario(args.server, args.compiler, backend)
        if status == "skip":
            print(f"SKIP {backend}: {details.strip()}")
        else:
            print(f"PASS {backend} native source-removed artifact malformed400/zero-connect + valid101")
        status, details = handshake_request_scenario(args.server, backend)
        if status == "skip":
            print(f"SKIP {backend}: {details.strip()}")
        else:
            print(f"PASS {backend} strict request shape / 400 / 426 / zero-connect")
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
        status, details = tls_terminate_handshake_scenario(args.server, backend)
        if status == "skip":
            print(f"SKIP {backend}: {details.strip()}")
        else:
            print(f"PASS {backend} TLS terminate bad-request/zero-connect + valid-101/drop")
        for terminate, response, expected in (
            (True, RAW_RESPONSE, "reject"),
            (True, MISSING_CONNECTION_RESPONSE, "reject"),
            (True, BAD_ACCEPT_RESPONSE, "reject"),
            (True, UNSOLICITED_PROTOCOL_RESPONSE, "reject"),
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
