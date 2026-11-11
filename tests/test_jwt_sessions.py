#!/usr/bin/env python3
"""Online JWT permits through native-loaded Rut and an independent RESP2/TLS peer."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid

KEY = "jwt-session-fixture-key-0123456789abcdefghijklmnopqrstuvwxyz"
NAMESPACE = "rut:issuer:orders"
ISSUE_KEY = "session-control-fixture-0123456789abcdefghijklmnopqrstuvwxyz"


def signed(claims, key=KEY, algorithm="HS256"):
    encode = lambda data: base64.urlsafe_b64encode(data).rstrip(b"=")
    header = encode(json.dumps(dict(alg=algorithm, typ="JWT")).encode())
    payload = encode(claims.encode() if isinstance(claims, str) else json.dumps(claims).encode())
    message = header + b"." + payload
    return (message + b"." + encode(hmac.new(key.encode(), message, hashlib.sha384 if algorithm == "HS384" else hashlib.sha256).digest())).decode()


def permit_key(token):
    return (NAMESPACE + ":" + hashlib.sha256(token.encode()).hexdigest()).encode()


class Peer:
    def __init__(self, certificates, tls):
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.mode = "normal"
        self.store = {}
        self.expiries = {}
        self.commands = []
        self.errors = []
        self.workers = []
        self.connections = set()
        self.accepted = 0
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.context = None
        if tls:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(str(certificates / "localhost_cert.pem"),
                                         str(certificates / "localhost_key.pem"))
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                self.accepted += 1
            worker = threading.Thread(target=self.serve, args=(connection,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def serve(self, connection):
        try:
            connection.settimeout(3)
            if self.context:
                connection = self.context.wrap_socket(connection, server_side=True)
            with self.lock:
                self.connections.add(connection)
            stream = connection.makefile("rb")
            user, database = None, 0
            try:
                while not self.stop.is_set():
                    line = stream.readline(64)
                    if not line:
                        break
                    assert re.fullmatch(rb"\*[1-9][0-9]*\r\n", line), line
                    count = int(line[1:])
                    assert 1 <= count <= 6, count
                    arguments = []
                    for _ in range(count):
                        line = stream.readline(64)
                        assert re.fullmatch(rb"\$[0-9]+\r\n", line), line
                        size = int(line[1:])
                        assert size <= 8192
                        value = stream.read(size)
                        assert len(value) == size and stream.read(2) == b"\r\n"
                        arguments.append(value)
                    with self.lock:
                        mode = self.mode
                        self.commands.append(tuple(arguments))
                    command = arguments[0]
                    if command == b"AUTH":
                        assert arguments == [b"AUTH", b"gateway", b"service-password"]
                        user = "gateway" if mode != "auth-error" else None
                        reply = b"+OK\r\n" if user else b"-WRONGPASS fixture\r\n"
                    elif command == b"SELECT":
                        assert arguments == [b"SELECT", b"1"]
                        database = 1 if user and mode != "select-error" else 0
                        reply = b"+OK\r\n" if database else b"-ERR database fixture\r\n"
                    elif command == b"GET":
                        assert user == "gateway" and database == 1
                        assert len(arguments) == 2 and arguments[1].startswith(NAMESPACE.encode() + b":")
                        assert re.fullmatch(rb"[0-9a-f]{64}", arguments[1][-64:])
                        with self.lock:
                            if self.expiries.get(arguments[1], time.time() + 1) <= time.time():
                                self.store.pop(arguments[1], None)
                            value = self.store.get(arguments[1])
                        if mode == "get-error":
                            reply = b"-WRONGTYPE fixture\r\n"
                        elif mode == "wrong-shape":
                            reply = b"+active\r\n"
                        elif mode == "truncated":
                            connection.sendall(b"$6\r\nact")
                            return
                        elif mode == "timeout":
                            self.stop.wait(1.3)
                            return
                        else:
                            reply = b"$-1\r\n" if value is None else (
                                b"$" + str(len(value)).encode() + b"\r\n" + value + b"\r\n")
                        if mode == "fragmented":
                            connection.sendall(reply[:4])
                            time.sleep(.02)
                            reply = reply[4:]
                    elif command == b"SET":
                        assert user == "gateway" and database == 1
                        assert len(arguments) == 6 and arguments[2:5] == [b"active", b"NX", b"EXAT"]
                        assert arguments[1].startswith(NAMESPACE.encode() + b":")
                        assert re.fullmatch(rb"[0-9a-f]{64}", arguments[1][-64:])
                        assert re.fullmatch(rb"[1-9][0-9]*", arguments[5])
                        expires = int(arguments[5])
                        assert time.time() < expires <= time.time() + 301
                        if mode == "set-error":
                            reply = b"-ERR set fixture\r\n"
                        elif mode == "set-nx":
                            with self.lock:
                                self.store[arguments[1]] = b"reserved"
                            reply = b"$-1\r\n"
                        else:
                            with self.lock:
                                assert arguments[1] not in self.store, "NX must not overwrite an existing permit"
                                self.store[arguments[1]] = b"active"
                                self.expiries[arguments[1]] = expires
                            reply = b"+OK\r\n"
                            if mode == "set-bulk":
                                reply = b"$2\r\nOK\r\n"
                            elif mode == "set-integer":
                                reply = b":1\r\n"
                            elif mode == "set-trailing":
                                reply += b"+OK\r\n"
                            elif mode == "set-eof":
                                return
                            elif mode == "set-timeout":
                                self.stop.wait(1.3)
                                return
                            elif mode == "set-delayed":
                                self.stop.wait(.6)
                            elif mode == "set-fragmented":
                                connection.sendall(reply[:1])
                                time.sleep(.02)
                                reply = reply[1:]
                    elif command == b"DEL":
                        assert user == "gateway" and database == 1
                        assert len(arguments) == 2 and arguments[1].startswith(NAMESPACE.encode() + b":")
                        assert re.fullmatch(rb"[0-9a-f]{64}", arguments[1][-64:])
                        if mode == "del-error":
                            reply = b"-ERR delete fixture\r\n"
                        else:
                            with self.lock:
                                count = int(arguments[1] in self.store)
                                self.store.pop(arguments[1], None)
                            reply = b":" + str(count).encode() + b"\r\n"
                            if mode == "del-negative":
                                reply = b":-1\r\n"
                            elif mode == "del-large":
                                reply = b":2\r\n"
                            elif mode == "del-leading-zero":
                                reply = b":01\r\n"
                            elif mode == "del-plus":
                                reply = b":+1\r\n"
                            elif mode == "del-overflow":
                                reply = b":9223372036854775808\r\n"
                            elif mode == "del-wrong":
                                reply = b"$1\r\n1\r\n"
                            elif mode == "del-null":
                                reply = b"$-1\r\n"
                            elif mode == "del-trailing":
                                reply += b":0\r\n"
                            elif mode == "del-eof":
                                return
                            elif mode == "del-timeout":
                                self.stop.wait(1.3)
                                return
                            elif mode == "del-fragmented":
                                connection.sendall(reply[:1])
                                time.sleep(.02)
                                reply = reply[1:]
                    elif command == b"RESET":
                        assert arguments == [b"RESET"]
                        if mode == "set-delayed":
                            self.stop.wait(.6)
                        user, database = None, 0
                        reply = b"-ERR reset fixture\r\n" if mode == "reset-error" else (
                            b"+OK\r\n" if mode == "reset-wrong" else b"+RESET\r\n")
                    else:
                        raise AssertionError(arguments)
                    connection.sendall(reply)
            finally:
                stream.close()
        except (OSError, ssl.SSLError):
            # Deliberate reply/timeout failures make the runtime discard its lease.
            pass
        except Exception as error:
            with self.lock:
                self.errors.append(repr(error))
        finally:
            with self.lock:
                self.connections.discard(connection)
            connection.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        with self.lock:
            connections = list(self.connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.thread.join(timeout=2)
        for worker in self.workers:
            worker.join(timeout=4)
        assert not self.thread.is_alive() and not any(w.is_alive() for w in self.workers)
        assert not self.errors, self.errors


def exchange(port, version, token, duplicate=False, fallback_token="spoofed",
             method="GET", path="/private", source_ip="127.0.0.1"):
    fields = "" if token is None else f"Authorization: Bearer {token}\r\n"
    if duplicate:
        fields += fields
    # Valid query/body credentials cannot supply a missing or duplicated header.
    body = f"Authorization: Bearer {fallback_token}\r\nscope=orders:write".encode()
    wire = (f"{method} {path}?scope=orders:write&access_token={fallback_token} {version}\r\nHost: localhost\r\n"
            "Connection: close\r\nX-Consumer-ID: attacker\r\nX-Session-Status: active\r\nX-Scope: orders:write\r\n" +
            fields + f"Content-Length: {len(body)}\r\n\r\n").encode() + body
    with socket.create_connection(("127.0.0.1", port), timeout=8, source_address=(source_ip, 0)) as connection:
        connection.sendall(wire)
        response = b""
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            response += chunk
    head, body = response.split(b"\r\n\r\n", 1)
    lines = head.decode().split("\r\n")
    challenges = [line.split(":", 1)[1].strip() for line in lines[1:]
                  if line.lower().startswith("www-authenticate:")]
    cache_control = [line.split(":", 1)[1].strip() for line in lines[1:]
                     if line.lower().startswith("cache-control:")]
    status = int(lines[0].split()[1])
    if path == "/sessions" and status == 200:
        assert "Content-Type: application/jwt".lower() in head.decode().lower()
        assert "Pragma: no-cache".lower() in head.decode().lower()
        assert cache_control == ["no-store"]
    return status, body, challenges, cache_control


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--testdata", required=True)
    parser.add_argument("--backend", choices=("epoll", "io_uring"), required=True)
    parser.add_argument("--opt", choices=("0", "2"), default="2")
    parser.add_argument("--tls", action="store_true")
    args = parser.parse_args()
    original = Path(args.source).resolve()
    certificates = Path(args.testdata).resolve()
    peer = Peer(certificates, args.tls)
    checks = 0
    try:
        now = int(time.time())
        claims = dict(sub="alice", iss="issuer", aud="gateway", iat=now, exp=now + 600, jti="session-id")
        good = signed(claims)
        same_claims = signed(dict(claims, nonce="different-token-same-jti"))
        invalid = [None, "", "malformed", signed(claims, key="wrong"),
                   signed(dict(claims, exp=1)), signed(dict(claims, iss="other")),
                   signed(dict(claims, aud="other")), signed(dict(claims, sub="")),
                   signed(dict(claims, nbf=now + 600)), signed(claims, algorithm="HS384"),
                   signed(json.dumps(claims)[:-1] + ',"sub":"attacker"}')]
        with peer.lock:
            peer.store[permit_key(good)] = b"active"
        with tempfile.TemporaryDirectory(prefix="rut-jwt-sessions-") as directory:
            root = Path(directory)
            shutil.copytree(original.parent / "clients", root / "clients")
            (root / "middleware").mkdir()
            shutil.copyfile(original.parent / "middleware/jwt_session.rut",
                            root / "middleware/jwt_session.rut")
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            source = root / "session.rut"
            source.write_text(original.read_text().replace("listen :8080", f"listen :{port}"))
            endpoint = dict(address="127.0.0.1", port=peer.port, poolIdleMs=5000)
            if args.tls:
                endpoint.update(tls=True, caFile=str(certificates / "localhost_cert.pem"),
                                serverName="localhost")
            env = dict(os.environ, JWT_SECRET=KEY, JWT_PREVIOUS_SECRET="", JWT_ISSUER="issuer", JWT_AUDIENCE="gateway",
                       JWT_SESSION_NAMESPACE=NAMESPACE, REDIS_ENDPOINT=json.dumps(endpoint),
                       REDIS_USERNAME="gateway", REDIS_PASSWORD="service-password", REDIS_DATABASE="1",
                       SESSION_ISSUE_KEY=ISSUE_KEY, SESSION_SUBJECT="alice", SESSION_SCOPES="orders:read")
            log = root / "gateway.log"
            with log.open("w") as output:
                process = subprocess.Popen([args.server, str(source), "--backend", args.backend,
                                            "--opt", args.opt, "--no-pin", "--shards", "1",
                                            "--drain", "0", "--max-connections-per-shard", "128"],
                                           env=env, stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 60
                while True:
                    if process.poll() is not None:
                        data = log.read_text()
                        if args.backend == "io_uring" and "io_uring is unavailable" in data:
                            print("SKIP: io_uring unavailable")
                            return 77
                        raise AssertionError(data)
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.1):
                            break
                    except OSError:
                        assert time.monotonic() < deadline, log.read_text()
                        time.sleep(.025)
                # Requests below run from the loaded native artifact, without source files.
                source.unlink()
                shutil.rmtree(root / "clients")
                shutil.rmtree(root / "middleware")

                def check(value, expected, version="HTTP/1.1", duplicate=False, lookup=True,
                          method="GET", path="/private", source_ip="127.0.0.1"):
                    nonlocal checks
                    with peer.lock:
                        before = len(peer.commands)
                    status, body, challenges, cache_control = exchange(
                        port, version, value, duplicate,
                        fallback_token=same_claims if path == "/logout" else good,
                        method=method, path=path)
                    assert status == expected, (value, status, expected, body, log.read_text())
                    if status == 403:
                        assert challenges == ['Bearer error="insufficient_scope"'], challenges
                    else:
                        assert bool(challenges) == (status == 401), (status, challenges)
                    if status == 200:
                        assert body == b"alice", body
                    if status == 204:
                        assert body == b"" and cache_control == ["no-store"], (body, cache_control)
                    if not lookup:
                        with peer.lock:
                            assert len(peer.commands) == before, peer.commands[before:]
                    assert not peer.errors, peer.errors
                    checks += 1

                for version in ("HTTP/1.0", "HTTP/1.1"):
                    check(good, 200, version)
                    for value in invalid:
                        check(value, 401, version, lookup=False)
                    check(good, 401, version, duplicate=True, lookup=False)
                    check(same_claims, 401, version)
                    with peer.lock:
                        peer.store.pop(permit_key(good))
                    check(good, 401, version)  # Online deletion revokes the same signed token.
                    with peer.lock:
                        peer.store[permit_key(good)] = b"active"
                    check(good, 200, version)
                    for marker in (b"", b"ACTIVE", b"active\x00", b"inactive"):
                        with peer.lock:
                            peer.store[permit_key(good)] = marker
                        check(good, 401, version)
                    with peer.lock:
                        peer.store[permit_key(good)] = b"active"
                    for mode in ("get-error", "wrong-shape", "truncated", "timeout", "reset-error",
                                 "reset-wrong", "auth-error", "select-error", "fragmented", "normal"):
                        with peer.lock:
                            peer.mode = mode
                        check(good, 200 if mode in ("fragmented", "normal") else 503, version)
                # Independent signed scope fixtures all have active permits. The
                # original scope-less token remains valid only for identity routes.
                scope_cases = [
                    ({}, False, False), ({"scope": ""}, False, False),
                    ({"scope": "orders:read"}, True, False),
                    ({"scope": "orders:write"}, False, True),
                    ({"scope": "orders:write orders:read"}, True, True),
                    ({"scope": "orders:read orders:read"}, True, False),
                    ({"scope": "orders:reader"}, False, False),
                    ({"scope": "Orders:read"}, False, False),
                    ({"scope": "orders:read bad\t"}, False, False),
                    ({"scope": "orders:read  orders:write"}, False, False),
                    ({"scope": " orders:read"}, False, False),
                    ({"scope": "orders:read "}, False, False),
                    ({"scope": ["orders:read"]}, False, False),
                    ({"scope": None}, False, False),
                ]
                scoped_tokens = [(signed(dict(claims, **extra)), read, write)
                                 for extra, read, write in scope_cases]
                with peer.lock:
                    peer.mode = "normal"
                    for value, _, _ in scoped_tokens:
                        peer.store[permit_key(value)] = b"active"
                for version in ("HTTP/1.0", "HTTP/1.1"):
                    for value, read, write in scoped_tokens:
                        check(value, 204 if read else 403, version, path="/read")
                        check(value, 204 if write else 403, version, method="POST", path="/write")
                    for method, path in (("GET", "/read"), ("POST", "/write")):
                        for value in (None, signed(claims, key="wrong")):
                            check(value, 401, version, lookup=False, method=method, path=path)
                        check(good, 401, version, duplicate=True, lookup=False, method=method, path=path)
                    revoked = signed(dict(claims, scope="orders:read", jti="revoked-scope"))
                    check(revoked, 401, version, method="POST", path="/write")
                    with peer.lock:
                        peer.mode = "get-error"
                    check(good, 503, version, path="/read")
                    with peer.lock:
                        peer.mode = "normal"
                    # A scope in an otherwise valid signed JWT cannot skip cleanup.
                    readable = next(value for value, read, _ in scoped_tokens if read)
                    with peer.lock:
                        peer.mode = "reset-error"
                    check(readable, 503, version, path="/read")
                    with peer.lock:
                        peer.mode = "normal"
                # Self-service logout never accepts a target token from query/body.
                for version in ("HTTP/1.0", "HTTP/1.1"):
                    with peer.lock:
                        peer.mode = "normal"
                        peer.store[permit_key(good)] = b"active"
                        peer.store[permit_key(same_claims)] = b"active"
                    check(good, 404, version, lookup=False, path="/logout")
                    for value in invalid:
                        check(value, 401, version, lookup=False, method="POST", path="/logout")
                    check(good, 401, version, duplicate=True, lookup=False, method="POST", path="/logout")
                    check(good, 200, version)
                    check(good, 204, version, method="POST", path="/logout")
                    check(good, 401, version)
                    check(good, 204, version, method="POST", path="/logout")
                    check(same_claims, 200, version)  # Same subject/jti permit remains untouched.
                    for mode in ("auth-error", "select-error", "del-error", "del-negative", "del-large",
                                 "del-leading-zero", "del-plus", "del-overflow", "del-wrong", "del-null", "del-trailing", "del-eof",
                                 "del-timeout", "reset-error", "reset-wrong", "del-fragmented", "normal"):
                        with peer.lock:
                            peer.mode = mode
                            peer.store[permit_key(good)] = b"active"
                            before = len(peer.commands)
                        success = mode in ("del-fragmented", "normal")
                        check(good, 204 if success else 503, version, method="POST", path="/logout")
                        with peer.lock:
                            commands = [command[0] for command in peer.commands[before:]]
                            if mode.startswith("del-") and mode not in ("del-error", "del-fragmented"):
                                assert b"RESET" not in commands, (mode, commands)
                            if mode in ("auth-error", "select-error"):
                                assert b"DEL" not in commands, (mode, commands)
                            peer.mode = "normal"
                        # A failed acknowledgement may follow an applied delete.
                        still_active = mode in ("auth-error", "select-error", "del-error")
                        check(good, 200 if still_active else 401, version)
                        check(same_claims, 200, version)
                    check(good, 204, version, method="POST", path="/logout")
                    with peer.lock:
                        peer.store[permit_key(good)] = b"active"
                # The shipped five-attempt admission rule remains enabled. Fault
                # cases use distinct real loopback peer IPs, rather than spoofed headers.
                def issue(expected, credential=ISSUE_KEY, duplicate=False, source_ip="127.0.0.1"):
                    nonlocal checks
                    status, body, challenges, _ = exchange(
                        port, "HTTP/1.1", credential, method="POST", path="/sessions",
                        duplicate=duplicate, source_ip=source_ip,
                        fallback_token=ISSUE_KEY)
                    assert status == expected, (status, expected, body, log.read_text())
                    assert challenges == (["Bearer"] if status == 401 else []), challenges
                    if status != 200:
                        assert b"." not in body, "failure must not publish a compact token"
                    else:
                        parts = body.split(b".")
                        assert len(parts) == 3, body
                        decode = lambda part: base64.urlsafe_b64decode(part + b"=" * (-len(part) % 4))
                        header, payload = json.loads(decode(parts[0])), json.loads(decode(parts[1]))
                        assert header == dict(alg="HS256", typ="JWT")
                        assert hmac.compare_digest(decode(parts[2]), hmac.new(
                            KEY.encode(), parts[0] + b"." + parts[1], hashlib.sha256).digest())
                        assert set(payload) == {"sub", "iss", "aud", "iat", "exp", "jti", "scope"}
                        assert payload["scope"] == "orders:read"
                        assert (payload["sub"], payload["iss"], payload["aud"]) == ("alice", "issuer", "gateway")
                        assert payload["exp"] - payload["iat"] == 300
                        assert uuid.UUID(payload["jti"]).version == 4
                        with peer.lock:
                            key = permit_key(body.decode())
                            assert peer.store.get(key) == b"active", "returned token must match the enrolled permit"
                            assert peer.expiries[key] == payload["exp"]
                    checks += 1
                    return body.decode()

                with peer.lock:
                    peer.mode = "normal"
                    before = len(peer.commands)
                issue(401, credential="wrong")
                issue(401, duplicate=True)
                with peer.lock:
                    assert len(peer.commands) == before, "bad issuer credentials must not open a Redis session"
                first_issued = issue(200)
                second_issued = issue(200)
                assert first_issued != second_issued, "separate issuances need distinct UUID-backed tokens"
                check(first_issued, 200)
                check(first_issued, 204, path="/read")
                check(first_issued, 403, method="POST", path="/write")
                check(first_issued, 204, method="POST", path="/logout")
                check(first_issued, 401)
                check(first_issued, 401, path="/read")
                check(second_issued, 200)
                check(second_issued, 204, path="/read")
                with peer.lock:
                    peer.mode = "reset-error"
                issue(503)
                with peer.lock:
                    peer.mode = "normal"
                    before = len(peer.commands)
                issue(429)
                with peer.lock:
                    assert len(peer.commands) == before, "admission must precede Redis I/O"
                for i, mode in enumerate(("set-error", "set-nx", "set-bulk", "set-integer", "set-trailing",
                                          "set-eof", "set-timeout", "reset-wrong", "auth-error",
                                          "select-error", "set-fragmented", "set-delayed"), 2):
                    with peer.lock:
                        peer.mode = mode
                        before = len(peer.commands)
                    value = issue(200 if mode in ("set-fragmented", "set-delayed") else 503, source_ip=f"127.0.0.{i}")
                    with peer.lock:
                        commands = peer.commands[before:]
                        if mode in ("auth-error", "select-error"):
                            assert not any(command[0] == b"SET" for command in commands)
                        if mode == "set-nx":
                            key = next(command[1] for command in commands if command[0] == b"SET")
                            assert peer.store[key] == b"reserved"
                        peer.mode = "normal"
                    if value:
                        if mode in ("set-fragmented", "set-delayed"):
                            check(value, 200)
                # Only the explicit logout tests below may delete their presented token.
                with peer.lock:
                    deletes = [command[1] for command in peer.commands if command[0] == b"DEL"]
                    assert deletes and set(deletes) == {permit_key(good), permit_key(first_issued)}, deletes
                with peer.lock:
                    gets = [command[1] for command in peer.commands if command[0] == b"GET"]
                    assert {permit_key(good), permit_key(same_claims), permit_key(first_issued), permit_key(second_issued)} <= set(gets), gets
                    assert any(command == (b"RESET",) for command in peer.commands)
                    peer.store.clear()
                # Apply successive native configuration snapshots to the same
                # authoritative permit store. This is not an in-process RCU test.
                @contextmanager
                def snapshot(current, previous, issue_key=ISSUE_KEY, scopes="orders:read"):
                    with tempfile.TemporaryDirectory(prefix="rotation-", dir=root) as generation:
                        directory = Path(generation)
                        shutil.copytree(original.parent / "clients", directory / "clients")
                        (directory / "middleware").mkdir()
                        shutil.copyfile(original.parent / "middleware/jwt_session.rut",
                                        directory / "middleware/jwt_session.rut")
                        with socket.socket() as probe:
                            probe.bind(("127.0.0.1", 0))
                            rotated_port = probe.getsockname()[1]
                        program = directory / "session.rut"
                        program.write_text(original.read_text().replace("listen :8080", f"listen :{rotated_port}"))
                        configuration = dict(env, JWT_SECRET=current, JWT_PREVIOUS_SECRET=previous,
                                             SESSION_ISSUE_KEY=issue_key, SESSION_SCOPES=scopes)
                        rotated_log = directory / "gateway.log"
                        with rotated_log.open("w") as output:
                            rotated = subprocess.Popen(
                                [args.server, str(program), "--backend", args.backend, "--opt", args.opt,
                                 "--no-pin", "--shards", "1", "--drain", "0",
                                 "--max-connections-per-shard", "128"],
                                env=configuration, stdout=output, stderr=subprocess.STDOUT)
                        try:
                            deadline = time.monotonic() + 60
                            while True:
                                assert rotated.poll() is None, rotated_log.read_text()
                                try:
                                    with socket.create_connection(("127.0.0.1", rotated_port), timeout=.1):
                                        break
                                except OSError:
                                    assert time.monotonic() < deadline, rotated_log.read_text()
                                    time.sleep(.025)
                            program.unlink()
                            shutil.rmtree(directory / "clients")
                            shutil.rmtree(directory / "middleware")
                            yield rotated_port
                        finally:
                            if rotated.poll() is None:
                                rotated.terminate()
                            try:
                                rotated.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                rotated.kill()
                                rotated.wait(timeout=5)

                def rotation_check(rotated_port, value, expected, method="GET", path="/private", no_io=False):
                    nonlocal checks
                    with peer.lock:
                        before = len(peer.commands)
                    status, body, challenges, _ = exchange(
                        rotated_port, "HTTP/1.1", value, method=method, path=path)
                    assert status == expected, (status, expected, body)
                    if status == 403:
                        assert challenges == ['Bearer error="insufficient_scope"'], challenges
                    else:
                        assert bool(challenges) == (status == 401), (status, challenges)
                    if status == 200 and path == "/private":
                        assert body == b"alice", body
                    with peer.lock:
                        if no_io:
                            assert len(peer.commands) == before, peer.commands[before:]
                    checks += 1
                    return body

                new_secret = "replacement-jwt-secret-abcdefghijklmnopqrstuvwxyz-0123456789"
                old_token = signed(dict(claims, jti="old-generation", scope="orders:read"))
                old_logout = signed(dict(claims, jti="old-logout"))
                with peer.lock:
                    peer.store[permit_key(old_token)] = b"active"
                    peer.store[permit_key(old_logout)] = b"active"
                with snapshot(new_secret, KEY) as rotated_port:
                    rotation_check(rotated_port, old_token, 200)
                    rotation_check(rotated_port, old_token, 204, path="/read")
                    rotation_check(rotated_port, old_token, 403, method="POST", path="/write")
                    rotation_check(rotated_port, old_logout, 204, method="POST", path="/logout")
                    rotation_check(rotated_port, old_logout, 401)
                    issued = rotation_check(rotated_port, ISSUE_KEY, 200, method="POST", path="/sessions")
                    a, b, c = issued.split(b".")
                    decode = lambda data: base64.urlsafe_b64decode(data + b"=" * (-len(data) % 4))
                    assert hmac.compare_digest(decode(c), hmac.new(
                        new_secret.encode(), a + b"." + b, hashlib.sha256).digest())
                    assert not hmac.compare_digest(decode(c), hmac.new(
                        KEY.encode(), a + b"." + b, hashlib.sha256).digest())
                    payload = json.loads(decode(b))
                    with peer.lock:
                        assert peer.expiries[permit_key(issued.decode())] == payload["exp"]
                    rotation_check(rotated_port, issued.decode(), 200)
                    rotation_check(rotated_port, issued.decode(), 204, path="/read")
                with snapshot(new_secret, "") as rotated_port:
                    # The old permit still exists: key retirement alone must deny.
                    with peer.lock:
                        assert peer.store[permit_key(old_token)] == b"active"
                    rotation_check(rotated_port, old_token, 401, no_io=True)
                    rotation_check(rotated_port, old_token, 401, method="POST", path="/logout", no_io=True)
                    rotation_check(rotated_port, issued.decode(), 200)
                    rotation_check(rotated_port, issued.decode(), 204, method="POST", path="/logout")
                    rotation_check(rotated_port, issued.decode(), 401)
                with snapshot(new_secret, "short") as rotated_port:
                    rotation_check(rotated_port, old_token, 503, no_io=True)
                    rotation_check(rotated_port, ISSUE_KEY, 503, method="POST", path="/sessions", no_io=True)
                with snapshot("", KEY) as rotated_port:
                    rotation_check(rotated_port, old_token, 503, no_io=True)
                    rotation_check(rotated_port, ISSUE_KEY, 503, method="POST", path="/sessions", no_io=True)
                with snapshot(new_secret, KEY, scopes="orders:read  orders:write") as rotated_port:
                    rotation_check(rotated_port, ISSUE_KEY, 503, method="POST", path="/sessions", no_io=True)
                    rotation_check(rotated_port, old_token, 204, path="/read")
                with snapshot(new_secret, KEY, issue_key=KEY) as rotated_port:
                    rotation_check(rotated_port, KEY, 503, method="POST", path="/sessions", no_io=True)
                with peer.lock:
                    peer.store.clear()
                check(good, 401)  # Losing all permits cannot grant access.
                peer.close()
                check(good, 503)  # An unavailable authoritative service never falls back to JWT alone.
                check(good, 503, method="POST", path="/logout")
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    finally:
        peer.close()
    print(f"{args.backend} opt{args.opt} tls={args.tls}: {checks} native JWT session checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
