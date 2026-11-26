#!/usr/bin/env python3
"""Real gateway/native-artifact and local authenticated HTTPS JWKS regression."""
import argparse
import errno
import http.server
import json
import pathlib
import os
import re
import select
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from auth_h2_fixture import request as h2_request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--helper", required=True)
    parser.add_argument("--testdata", required=True)
    parser.add_argument("--backend", choices=("epoll", "io_uring"), required=True)
    parser.add_argument("--algorithm", choices=("RS256", "ES256"), default="RS256")
    parser.add_argument("--discovery-dns", action="store_true")
    parser.add_argument("--access-profile", action="store_true")
    parser.add_argument("--conditional", action="store_true")
    parser.add_argument("--dns-cache", action="store_true")
    parser.add_argument("--retry-after", action="store_true")
    parser.add_argument("--retry-backoff", action="store_true")
    parser.add_argument("--stage-timeout", action="store_true")
    parser.add_argument("--conditional-discovery", action="store_true")
    parser.add_argument("--discovery-cache", action="store_true")
    parser.add_argument("--require-non-empty-keys", action="store_true")
    parser.add_argument("--ipv6", action="store_true")
    parser.add_argument("--dual-stack", action="store_true")
    parser.add_argument("--admit-new-kids", action="store_true")
    parser.add_argument("--dns-tcp", action="store_true")
    parser.add_argument("--dns-tls", action="store_true")
    parser.add_argument("--dns-https", action="store_true")
    args = parser.parse_args()
    assert not (args.dual_stack and args.ipv6)
    if args.ipv6 or args.dual_stack:
        args.discovery_dns = True
    fixture_option = "--fixture-es256" if args.algorithm == "ES256" else "--fixture"
    if args.access_profile:
        fixture_option = "--fixture-es256-access" if args.algorithm == "ES256" else "--fixture-access"
    if args.discovery_dns: fixture_option += "-discovery"
    fixture = json.loads(subprocess.check_output([args.helper, fixture_option], timeout=10))
    lock = threading.Lock()
    release_response = threading.Event()
    state = {"body": json.dumps(fixture["first"]["jwks"]).encode(), "status": 200,
             "requests": 0, "locals": [], "dnsRequests": 0, "dnsTimes": [], "attempts": [], "delay": 0,
             "hold": "cold" if args.access_profile else False,
             "discovery": "valid", "dns": "valid",
             "etag": '"v1"', "conditionalMode": "force304" if args.conditional else "auto",
             "conditionalRequests": [], "discoveries": [], "discoveryDelay": 0}
    dns_types = []
    state.update(metadataTag='"metadata-v1"', metadataRequests=[])
    if args.conditional_discovery:
        state["discovery"] = "force304"
    state["retryAfter"] = () if args.retry_after else ("30",)
    cold_release = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            assert args.dns_https and self.server is https_dns and self.path == "/resolver"
            assert self.headers.get_all("Content-Type") == ["application/dns-message"]
            assert self.headers.get_all("Accept") == ["application/dns-message"]
            assert self.headers.get_all("Cache-Control") == ["no-cache"]
            assert self.headers.get_all("Host") == [f"localhost:{self.server.server_port}"]
            length = int(self.headers["Content-Length"])
            assert 17 <= length <= 272
            query = self.rfile.read(length)
            assert query == b"\0\0\1\0\0\1\0\0\0\0\0\0\x09localhost\0\0\1\0\1"
            with lock:
                mode = state["dns"]
            body = answer(query)
            if mode == "hold":
                release_response.wait(timeout=5)
            if body is None:
                self.close_connection = True
                return
            if mode == "oversized":
                body = body.ljust(513, b"\0")
            if mode == "wrong-id":
                body = b"\0\1" + body[2:]
            try:
                self.send_response(302 if mode == "redirect" else 200)
                if mode == "redirect":
                    self.send_header("Location", f"https://localhost:{origin.server_port}/keys")
                media_type = "application/json" if mode == "wrong-type" else "application/dns-message"
                self.send_header("Content-Type", media_type)
                if mode == "duplicate-type":
                    self.send_header("Content-Type", media_type)
                age = {"stale": "30", "invalid-age": "x"}.get(mode, "29")
                self.send_header("Age", age)
                self.send_header("Connection", "close")
                if mode == "cname-chunked":
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    for part in (body[:13], body[13:]):
                        self.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                    self.wfile.write(b"0\r\n\r\n")
                else:
                    self.send_header("Content-Length", str(len(body) + (mode == "short")))
                    self.end_headers()
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionError, ssl.SSLError):
                pass

        def do_GET(self):
            if self.path == "/.well-known/openid-configuration" and args.discovery_dns:
                with lock:
                    mode = state["discovery"]
                    discovery_delay = state["discoveryDelay"]
                    incoming = self.headers.get("If-None-Match")
                    state["discoveries"].append((incoming, discovery_delay))
                    tags = []
                    status = 302 if mode == "redirect" else 200
                    if args.conditional_discovery:
                        tag = state["metadataTag"]
                        if tag is not None:
                            tags = [tag]
                        if mode in ("force304", "mismatch304", "duplicate304") or (
                                mode == "valid" and tag is not None and incoming == tag):
                            status = 304
                        if mode == "mismatch304":
                            tags = ['"wrong"']
                        if mode == "duplicate304":
                            tags = [tag, tag]
                        state["metadataRequests"].append((incoming, status, mode, discovery_delay,
                                                          self.connection.getsockname()[0]))
                    if args.stage_timeout:
                        state.setdefault("discoveryTimes", []).append(time.monotonic())
                if discovery_delay:
                    time.sleep(discovery_delay)
                metadata = dict(issuer=fixture["first"]["issuer"],
                                jwks_uri=f"https://localhost:{origin.server_port}/keys")
                if mode == "issuer": metadata["issuer"] = "https://evil.example"
                if mode == "uri": metadata["jwks_uri"] = "https://127.0.0.2/keys"
                body = json.dumps(metadata).encode()
                self.send_response(status)
                if status == 304:
                    body = b""
                else:
                    self.send_header("Content-Type", "application/json")
                for tag in tags:
                    self.send_header("ETag", tag)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                try: self.wfile.write(body)
                except (BrokenPipeError, ConnectionError, ssl.SSLError): pass
                return
            if self.path != "/keys":
                self.send_error(404)
                return
            with lock:
                state["requests"] += 1
                state["locals"].append(self.connection.getsockname()[0])
                status, body, hold = state["status"], state["body"], state["hold"]
                delay = state["delay"]
                retry_after = state["retryAfter"]
                state["attempts"].append((time.monotonic(), status, delay))
                tags = []
                if args.conditional:
                    mode, tag = state["conditionalMode"], state["etag"]
                    incoming = self.headers.get("If-None-Match")
                    if mode == "force304" or mode in ("missing304", "mismatch304", "weak304", "duplicate304"):
                        status = 304
                    elif mode == "auto" and status == 200 and tag is not None and incoming == tag:
                        status = 304
                    if tag is not None:
                        tags = [tag]
                    if mode in ("weak200", "weak304"):
                        tags = ['W/"weak"']
                    if mode in ("duplicate200", "duplicate304"):
                        tags = [tag, tag]
                    if mode == "missing304":
                        tags = []
                    if mode == "mismatch304":
                        tags = ['"mismatch"']
                    if status == 304:
                        body = b""
                    state["conditionalRequests"].append(dict(
                        incoming=incoming, status=status, tag=tag, mode=mode,
                        address=self.connection.getsockname()[0], delay=delay))
            if delay:
                time.sleep(delay)
            if hold == "cold":
                cold_release.wait()
            elif hold:
                release_response.wait(timeout=5)
            try:
                self.send_response(status)
                if status != 304:
                    self.send_header("Content-Type", "application/jwk-set+json")
                for tag in tags:
                    self.send_header("ETag", tag)
                if status in (429, 503):
                    for value in retry_after:
                        self.send_header("Retry-After", value)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionError, ssl.SSLError):
                pass

        def log_message(self, *unused):
            pass

    family = socket.AF_INET6 if args.ipv6 else socket.AF_INET
    loopback = "::1" if args.ipv6 else "127.0.0.1"
    origin_type = type("JwksOrigin", (http.server.ThreadingHTTPServer,),
                       {"address_family": family})
    try:
        origin = origin_type((loopback, 0), Handler)
    except OSError as error:
        if args.ipv6 and error.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
            print("SKIP: IPv6 loopback unavailable")
            raise SystemExit(77)
        raise
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(pathlib.Path(args.testdata) / "localhost_cert.pem"),
                            str(pathlib.Path(args.testdata) / "localhost_key.pem"))
    origin.socket = context.wrap_socket(origin.socket, server_side=True)
    origin2 = worker2 = None
    if not args.ipv6:
        origin2 = origin_type(("127.0.0.2", origin.server_port), Handler)
        origin2.socket = context.wrap_socket(origin2.socket, server_side=True)
        worker2 = threading.Thread(target=origin2.serve_forever, daemon=True)
        worker2.start()
    worker = threading.Thread(target=origin.serve_forever, daemon=True)
    worker.start()
    dns_stop = threading.Event()
    def answer(query):
        with lock:
            mode = state["dns"]
            state["dnsRequests"] += 1
            if args.stage_timeout:
                state["dnsTimes"].append(time.monotonic())
        if mode == "timeout": return None
        target = "127.0.0.3" if mode == "rebind" else "127.0.0.2" if mode == "move" else "127.0.0.1"
        kind = 28 if args.ipv6 else 1
        answer_family = family
        if args.dual_stack:
            kind = int.from_bytes(query[-4:-2], "big")
            with lock:
                dns_types.append(kind)
            if kind == 28:
                target = "::1"
                answer_family = socket.AF_INET6
            elif kind != 1:
                return None
        if args.ipv6:
            if not query.endswith(b"\0\x1c\0\1"):
                return None
            target = "2001:db8::1" if mode == "rebind" else loopback
        address = socket.inet_pton(answer_family, target)
        def name(host):
            return b"".join(bytes((len(label),)) + label.encode() for label in host.split(".")) + b"\0"
        def record(owner, kind, data, ttl=30):
            return owner + kind.to_bytes(2, "big") + b"\0\1" + ttl.to_bytes(4, "big") + len(data).to_bytes(2, "big") + data
        records = [record(b"\xc0\x0c", kind, address)]
        if mode.startswith("cname"):
            alias = name("keys.example")
            records = [record(b"\xc0\x0c", 5, alias)]
            # The A owner points to the already decoded CNAME RDATA.
            alias_offset = len(query) + 12
            pointer = (0xc000 | alias_offset).to_bytes(2, "big")
            records.append(record(pointer, kind, address))
            if mode == "cname-reordered":
                records = [record(alias, kind, address), record(b"\xc0\x0c", 5, alias)]
            elif mode == "cname-failover":
                records[-1] = record(pointer, 1, socket.inet_aton("127.0.0.4"))
                records.append(record(pointer, 1, socket.inet_aton("127.0.0.2")))
            elif mode == "cname-poison":
                records.append(record(pointer, 1, socket.inet_aton("127.0.0.3")))
            elif mode == "cname-cycle":
                records[-1] = record(pointer, 5, b"\xc0\x0c")
            elif mode == "cname-zero-ttl":
                records[0] = record(b"\xc0\x0c", 5, alias, ttl=0)
            elif mode == "cname-unrelated":
                records.append(record(name("unrelated.example"), 1, address))
        return query[:2] + b"\x81\x80\0\1" + len(records).to_bytes(2, "big") + b"\0\0\0\0" + query[12:] + b"".join(records)

    dns = None
    tcp_dns = None
    https_dns = None
    dns_port = 0
    if args.dns_https:
        state["dns"] = "cname-chunked"
        https_dns = origin_type((loopback, 0), Handler)
        https_dns.socket = context.wrap_socket(https_dns.socket, server_side=True)
        dns_port = https_dns.server_port
        resolve = https_dns.serve_forever
    elif args.dns_tcp or args.dns_tls:
        tcp_dns = socket.socket(family, socket.SOCK_STREAM)
        tcp_dns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_dns.bind((loopback, 0))
        tcp_dns.listen(8)
        tcp_dns.settimeout(.1)
        dns_port = tcp_dns.getsockname()[1]
        def serve(connection):
            connection.settimeout(1)
            try:
                header = b""
                while len(header) < 2:
                    chunk = connection.recv(2 - len(header))
                    if not chunk: raise OSError
                    header += chunk
                length = int.from_bytes(header, "big")
                if length < 12 or length > 512: raise OSError
                query = b""
                while len(query) < length:
                    chunk = connection.recv(length - len(query))
                    if not chunk: raise OSError
                    query += chunk
                response = answer(query)
                if response is not None:
                    with lock:
                        mode = state["dns"]
                    if mode == "tcp-short":
                        connection.sendall((len(response) + 3).to_bytes(2, "big") + response)
                    else:
                        connection.sendall(len(response).to_bytes(2, "big") + response)
            except (OSError, TimeoutError):
                pass
        def resolve():
            while not dns_stop.is_set():
                try: connection, _ = tcp_dns.accept()
                except socket.timeout: continue
                except OSError: return
                if args.dns_tls:
                    try: connection = context.wrap_socket(connection, server_side=True)
                    except (OSError, ssl.SSLError):
                        connection.close()
                        continue
                with connection:
                    serve(connection)
    else:
        dns = socket.socket(family, socket.SOCK_DGRAM)
        dns.bind((loopback, 0))
        dns.settimeout(.1)
        dns_port = dns.getsockname()[1]
        def resolve():
            while not dns_stop.is_set():
                try: query, peer = dns.recvfrom(512)
                except socket.timeout: continue
                except OSError: return
                response = answer(query)
                if response is not None:
                    try: dns.sendto(response, peer)
                    except OSError: return
    dns_worker = threading.Thread(target=resolve, daemon=True)
    dns_worker.start()
    process = None
    refusing = None
    try:
        policy = fixture["first"]
        policy["remoteJwks"] = {"address": "127.0.0.1", "port": origin.server_port,
                                "serverName": "localhost", "path": "/keys",
                                "ca": str(pathlib.Path(args.testdata) / "localhost_cert.pem"),
                                "refreshSeconds": 1, "maxAgeSeconds": 3, "timeoutSeconds": 1}
        if args.admit_new_kids:
            policy["kids"] = []
            policy["jwks"] = {"keys": []}
            policy["remoteJwks"].update(admitNewKids=True)
        if args.require_non_empty_keys:
            policy["remoteJwks"].update(requireNonEmptyKeys=True, maxAgeSeconds=6)
        if args.conditional:
            policy["remoteJwks"].update(conditionalRequests=True, timeoutSeconds=5, retrySeconds=1)
        retry_profile = not args.discovery_dns and not args.access_profile and not args.conditional
        if retry_profile:
            policy["remoteJwks"].update(retrySeconds=2, timeoutSeconds=2)
        if args.retry_after:
            policy["remoteJwks"].update(retrySeconds=1, maxRetryAfterSeconds=3)
        if args.retry_backoff:
            policy["remoteJwks"].update(retrySeconds=1, maxRetrySeconds=3)
        if args.ipv6:
            state["dns"] = "cname"
            policy["remoteJwks"].update(
                address="127.0.0.1",  # A DNS failure must never use the fixed address.
                dnsRecordType="AAAA", dnsAddress="::1", dnsPort=dns_port,
                allowedAddresses=["0:0:0:0:0:0:0:1"], maxAgeSeconds=5,
                discoveryPath="/.well-known/openid-configuration",
                discoveryIssuer=policy["issuer"])
        elif args.dual_stack:
            try:
                refusing = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                refusing.bind(("::1", origin.server_port))
            except OSError as error:
                if error.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
                    raise SystemExit(77)
                raise
            policy["remoteJwks"].update(
                dnsRecordType="A+AAAA", dnsAddress="127.0.0.1", dnsPort=dns_port,
                allowedAddresses=["::1", "127.0.0.1"], maxAgeSeconds=5,
                discoveryPath="/.well-known/openid-configuration",
                discoveryIssuer=policy["issuer"])
        elif args.dns_tcp:
            policy["remoteJwks"].update(dnsAddress=loopback, dnsPort=dns_port,
                                        allowedAddresses=[loopback], dnsTransport="tcp")
        elif args.dns_tls:
            policy["remoteJwks"].update(
                dnsAddress=loopback, dnsTlsPort=dns_port, allowedAddresses=[loopback],
                dnsTransport="tls", dnsTlsServerName="localhost",
                dnsTlsCa=str(pathlib.Path(args.testdata) / "localhost_cert.pem"))
        elif args.dns_https:
            policy["remoteJwks"].update(
                dnsAddress=loopback, dnsHttpsPort=dns_port, dnsHttpsPath="/resolver",
                allowedAddresses=[loopback], dnsTransport="https", dnsTlsServerName="localhost",
                dnsTlsCa=str(pathlib.Path(args.testdata) / "localhost_cert.pem"),
                timeoutSeconds=4, dnsTimeoutSeconds=2, retrySeconds=1, dnsCacheSeconds=20)
        elif args.discovery_dns:
            # Reserve the allowlisted first address without listening on it.
            refusing = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            refusing.bind(("127.0.0.4", origin.server_port))
            policy["remoteJwks"].update(dnsAddress="127.0.0.1", dnsPort=dns_port,
                                       allowedAddresses=["127.0.0.1", "127.0.0.2", "127.0.0.4"],
                                       discoveryPath="/.well-known/openid-configuration",
                                       discoveryIssuer=policy["issuer"])
        if args.discovery_cache:
            assert args.discovery_dns
            policy["remoteJwks"].update(maxAgeSeconds=8, discoveryCacheSeconds=5)
        if args.conditional_discovery:
            assert args.discovery_dns
            policy["remoteJwks"].update(conditionalDiscovery=True, timeoutSeconds=5)
        if args.stage_timeout:
            assert args.discovery_dns
            policy["remoteJwks"].update(timeoutSeconds=6, dnsTimeoutSeconds=1,
                                        discoveryTimeoutSeconds=1)
            state["dns"] = "timeout"
        if args.dns_cache:
            assert args.discovery_dns
            policy["remoteJwks"]["dnsCacheSeconds"] = 4
        literal = json.dumps(json.dumps(policy, separators=(",", ":")))
        if args.access_profile:
            policy["requiredType"] = "at+jwt"
            literal = json.dumps(json.dumps(policy, separators=(",", ":")))
            module = pathlib.Path(__file__).resolve().parent.parent / "examples/middleware/jwt_access.rut"
            example = pathlib.Path(__file__).resolve().parent.parent / "examples" / (
                "jwt-access-remote-es256-auth.rut" if args.algorithm == "ES256"
                else "jwt-access-remote-rs256-auth.rut")
        else:
            verifier = "jwtEs256" if args.algorithm == "ES256" else "jwtRs256"
            source = ('import Crypto\nroute GET "/" { guard let claims = Crypto.' + verifier + '('
                      'bearerToken(req.authorization.or("")).or(""), ' + literal +
                      ') else { return 401 } return 200 }\n')
        with tempfile.TemporaryDirectory(prefix="rut-remote-jwks-") as directory:
            source_path = pathlib.Path(directory) / "gateway.rut"
            if args.access_profile:
                with socket.socket() as probe:
                    probe.bind(("127.0.0.1", 0))
                    port = probe.getsockname()[1]
                source = example.read_text().replace("listen :8080", f"listen :{port}")
                source_path.write_text(source)
                (pathlib.Path(directory) / "middleware").mkdir()
                (pathlib.Path(directory) / "middleware/jwt_access.rut").write_bytes(module.read_bytes())
            else:
                port = 0
                source_path.write_text(source)
            env = dict(os.environ)
            if args.access_profile:
                policy_name = "JWT_ACCESS_ES256_POLICY" if args.algorithm == "ES256" else "JWT_ACCESS_RS256_POLICY"
                env.update(JWT_ACCESS_CLIENT_ID="orders-web", JWT_ACCESS_REQUIRED_SCOPE="orders:read")
                env[policy_name] = json.dumps(policy, separators=(",", ":"))
            command = [args.server, str(port), str(source_path), "--backend",
                                        args.backend, "--shards", "1", "--no-pin", "--drain", "0",
                                        "--max-connections-per-shard", "64"]
            process = subprocess.Popen(command, env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            # Observe the actual listener rather than assuming startup completed.
            startup = b""
            deadline = time.monotonic() + 12
            port = None
            while time.monotonic() < deadline:
                readable, _, _ = select.select([process.stdout], [], [], 0.05)
                if readable:
                    startup += os.read(process.stdout.fileno(), 4096)
                    match = re.search(rb"Listening on port ([0-9]+) with", startup)
                    if match:
                        port = int(match.group(1))
                        break
                if process.poll() is not None:
                    startup += process.communicate()[0]
                    output = startup.decode(errors="replace")
                    if args.backend == "io_uring" and "io_uring is unavailable" in output:
                        print("SKIP: kernel does not provide io_uring")
                        raise SystemExit(77)
                    raise AssertionError(f"gateway exited during startup: {output}")
            assert port is not None, f"gateway did not listen: {startup!r}"

            # The compiled native configuration owns the policy after source removal.
            source_path.unlink()
            if args.access_profile:
                (pathlib.Path(directory) / "middleware/jwt_access.rut").unlink()

            def request(token, path="/read" if args.access_profile else "/", with_body=False):
                if process.poll() is not None:
                    output = process.communicate()[0].decode(errors="replace")
                    if args.backend == "io_uring" and "io_uring is unavailable" in output:
                        print("SKIP: kernel does not provide io_uring")
                        raise SystemExit(77)
                    raise AssertionError(f"gateway exited: {output}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1) as connection:
                        connection.sendall((f"GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n"
                                            "Authorization: Bearer " + token + "\r\n\r\n").encode())
                        data = b""
                        while True:
                            chunk = connection.recv(4096)
                            if not chunk:
                                break
                            data += chunk
                        head, _, body = data.partition(b"\r\n\r\n")
                        status = int(head.split(b" ", 2)[1])
                        return (status, body) if with_body else status
                except (ConnectionError, TimeoutError):
                    return None

            def wait_status(token, expected, limit=12):
                deadline = time.monotonic() + limit
                while time.monotonic() < deadline:
                    status = request(token)
                    if status == expected:
                        return
                    assert status in (None, 200, 401), f"unexpected HTTP status: {status}"
                    time.sleep(0.025)
                raise AssertionError(f"expected status {expected}, last status {status}")

            def publish(body, status=200):
                with lock:
                    state.update(body=body, status=status)

            def wait_for_origin_request(previous, limit=4):
                deadline = time.monotonic() + limit
                while time.monotonic() < deadline:
                    with lock:
                        if state["requests"] > previous:
                            return
                    time.sleep(0.01)
                raise AssertionError("idle shard did not start the scheduled JWKS refresh")

            def wait_for_dns_request(previous, limit=5):
                deadline = time.monotonic() + limit
                while time.monotonic() < deadline:
                    with lock:
                        if state["dnsRequests"] > previous:
                            return
                    time.sleep(0.01)
                raise AssertionError("idle shard did not start the scheduled DNS refresh")

            def wait_for_origin_address(previous, target, limit=5):
                deadline = time.monotonic() + limit
                while time.monotonic() < deadline:
                    with lock:
                        if state["requests"] > previous and state["locals"][-1] == target:
                            return
                    time.sleep(0.01)
                raise AssertionError(f"JWKS request did not reach {target}; seen {state['locals']}")

            def assert_retry_interval(got, expected):
                # Idle maintenance runs on a one-second tick. A refresh can
                # finish just after the tick and miss the first eligible tick.
                assert expected - .15 <= got <= expected + 1.5, (got, expected)

            if args.dns_https:
                wait_status(fixture["a"], 200)
                with lock:
                    previous_origin = state["requests"]
                for mode in ("wrong-type", "duplicate-type", "short", "oversized", "wrong-id",
                             "redirect", "stale", "invalid-age", "rebind"):
                    with lock:
                        state["dns"] = mode
                        previous_dns = state["dnsRequests"]
                    wait_for_dns_request(previous_dns + 1, limit=8)
                    with lock:
                        assert state["requests"] == previous_origin, mode
                wait_status(fixture["a"], 401)
                with lock:
                    state["dns"] = "valid"
                publish(json.dumps(fixture["second"]["jwks"]).encode())
                wait_status(fixture["b"], 200)
                assert request(fixture["a"]) == 401
                assert h2_request(port, "/", [("authorization", "Bearer " + fixture["b"])])[0] == 200
            elif args.dns_tcp or args.dns_tls:
                wait_status(fixture["a"], 200)
                with lock:
                    state["dns"] = "tcp-short"
                    previous_dns = state["dnsRequests"]
                wait_for_dns_request(previous_dns)
                wait_status(fixture["a"], 401, limit=6)
                with lock:
                    state["dns"] = "valid"
                wait_status(fixture["a"], 200, limit=6)
                publish(json.dumps(fixture["second"]["jwks"]).encode())
                wait_status(fixture["a"], 401)
                wait_status(fixture["b"], 200)
            elif args.admit_new_kids:
                # No bootstrap keys: the first authenticated set installs trust.
                wait_status(fixture["a"], 200)
                mixed = list(fixture["second"]["jwks"]["keys"])
                mixed.append({"kid": "unrelated", "kty": "oct", "alg": "HS256", "k": "AA"})
                publish(json.dumps({"keys": mixed}).encode())
                wait_status(fixture["a"], 401)
                wait_status(fixture["b"], 200)
                publish(b'{"keys":[]}')
                wait_status(fixture["b"], 401)
            elif args.ipv6:
                wait_status(fixture["a"], 200)
                with lock:
                    assert state["locals"] and all(address == "::1" for address in state["locals"])
                    assert state["discoveries"]
                    state["dns"] = "rebind"
                    previous_dns = state["dnsRequests"]
                wait_for_dns_request(previous_dns)
                wait_status(fixture["a"], 401)
                with lock:
                    state.update(dns="cname", body=json.dumps(fixture["second"]["jwks"]).encode())
                wait_status(fixture["b"], 200)
                assert request(fixture["a"]) == 401
            elif args.dual_stack:
                wait_status(fixture["a"], 200)
                with lock:
                    assert dns_types[:2] == [28, 1], dns_types
                    assert state["locals"] and set(state["locals"]) == {"127.0.0.1"}
                    assert state["discoveries"]
                    state["dns"] = "rebind"
                    previous_dns = state["dnsRequests"]
                wait_for_dns_request(previous_dns)
                wait_status(fixture["a"], 401)
                with lock:
                    state.update(dns="cname", body=json.dumps(fixture["second"]["jwks"]).encode())
                wait_status(fixture["b"], 200)
                assert request(fixture["a"]) == 401
            elif args.require_non_empty_keys and args.conditional:
                with lock:
                    state.update(conditionalMode="auto")
                wait_status(fixture["a"], 200)
                with lock:
                    state.update(etag='"empty"', body=b'{"keys":[]}')
                    start = len(state["conditionalRequests"])
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    with lock:
                        rejected = [item for item in state["conditionalRequests"][start:]
                                    if item["tag"] == '"empty"' and item["status"] == 200]
                    if len(rejected) >= 2:
                        break
                    time.sleep(.025)
                assert len(rejected) >= 2, rejected
                assert all(item["incoming"] == '"v1"' for item in rejected), rejected
                assert request(fixture["a"]) == 200
                wait_status(fixture["a"], 401)
                with lock:
                    state.update(etag='"v2"', body=json.dumps(fixture["second"]["jwks"]).encode())
                wait_status(fixture["b"], 200)
            elif args.require_non_empty_keys:
                wait_status(fixture["a"], 200)
                publish(b'{"keys":[]}')
                with lock:
                    previous = state["requests"]
                wait_for_origin_request(previous)
                time.sleep(0.2)
                assert request(fixture["a"]) == 200, "empty response replaced fresh keys"
                wait_status(fixture["a"], 401)
                publish(json.dumps(fixture["second"]["jwks"]).encode())
                wait_status(fixture["b"], 200)
            elif args.discovery_cache:
                wait_status(fixture["a"], 200)
                with lock:
                    assert len(state["discoveries"]) == 1
                    state["body"] = json.dumps(fixture["second"]["jwks"]).encode()
                wait_status(fixture["b"], 200)
                with lock:
                    assert len(state["discoveries"]) == 1
                    state["dns"] = "move"
                    before_move = state["requests"]
                wait_for_origin_address(before_move, "127.0.0.2")
                with lock:
                    assert len(state["discoveries"]) == 2
                    state["discovery"] = "issuer"
                    before_skip = state["requests"]
                wait_for_origin_request(before_skip)
                with lock:
                    assert len(state["discoveries"]) == 2
                # Skipping discovery does not slide its expiry. Once a fresh
                # response is required, rejected metadata prevents any key GET.
                wait_status(fixture["b"], 401, limit=16)
                assert h2_request(port, "/", [("authorization", "Bearer " + fixture["b"])])[0] == 401
                with lock:
                    assert len(state["discoveries"]) > 2
                    last_keys = state["requests"]
                    retries = state["dnsRequests"]
                wait_for_dns_request(retries + 1)
                with lock:
                    assert state["requests"] == last_keys
                    state["discovery"] = "valid"
                wait_status(fixture["b"], 200)
            elif args.conditional_discovery:
                def metadata_seen(predicate, start=0, limit=10):
                    deadline = time.monotonic() + limit
                    while time.monotonic() < deadline:
                        with lock:
                            values = state["metadataRequests"][start:]
                            match = next((entry for entry in values if predicate(entry)), None)
                        if match is not None:
                            return match
                        time.sleep(.02)
                    raise AssertionError(f"missing metadata observation: {values}")

                def metadata_change(**changes):
                    with lock:
                        state.update(changes)
                        return len(state["metadataRequests"])

                metadata_seen(lambda entry: entry[1] == 304 and entry[0] is None)
                wait_status(fixture["a"], 401)
                with lock:
                    assert not state["requests"]
                start = metadata_change(discovery="valid")
                wait_status(fixture["a"], 200)
                metadata_seen(lambda entry: entry[0] == '"metadata-v1"' and entry[1] == 304, start)
                publish(json.dumps(fixture["second"]["jwks"]).encode())
                wait_status(fixture["b"], 200)
                assert h2_request(port, "/", [("authorization", "Bearer " + fixture["a"])])[0] == 401

                for mode in ("mismatch304", "duplicate304"):
                    start = metadata_change(discovery=mode)
                    metadata_seen(lambda entry: entry[2] == mode, start)
                    with lock:
                        prior = state["requests"]
                    wait_status(fixture["b"], 401)
                    with lock:
                        assert state["requests"] == prior
                    start = metadata_change(discovery="valid")
                    cold = metadata_seen(lambda entry: entry[2] == "valid", start)
                    assert cold[:2] == (None, 200), cold
                    wait_status(fixture["b"], 200)
                    metadata_seen(lambda entry: entry[1] == 304, start)

                start = metadata_change(discoveryDelay=3.2)
                metadata_seen(lambda entry: entry[1] == 304 and entry[3] == 3.2, start)
                with lock:
                    prior = state["requests"]
                start = metadata_change(discoveryDelay=0)
                wait_status(fixture["b"], 401)
                cold = metadata_seen(lambda entry: entry[3] == 0, start)
                assert cold[:2] == (None, 200), cold
                wait_status(fixture["b"], 200)
                with lock:
                    assert state["requests"] == prior + 1

                start = metadata_change(dns="move")
                changed = metadata_seen(lambda entry: entry[4] == "127.0.0.2", start)
                assert changed[:2] == (None, 200), changed
                metadata_seen(lambda entry: entry[1] == 304 and entry[4] == "127.0.0.2", start)
                start = metadata_change(dns="cname-failover")
                failover = metadata_seen(lambda entry: entry[4] == "127.0.0.2", start)
                assert failover[:2] == (None, 200), failover
            elif args.stage_timeout:
                # Each capped stage aborts and waits for the normal retry tick.
                # The six-second overall timeout alone cannot meet either bound.
                wait_for_dns_request(1)
                with lock:
                    dns_times = state["dnsTimes"]
                    assert 1.8 <= dns_times[1] - dns_times[0] < 5, dns_times
                    assert not state["discoveries"] and not state["requests"]
                    state.update(dns="valid", discoveryDelay=3)
                deadline = time.monotonic() + 11
                while time.monotonic() < deadline:
                    with lock:
                        discoveries = state.get("discoveryTimes", ())
                        if len(discoveries) >= 2:
                            assert 1.8 <= discoveries[1] - discoveries[0] < 5, discoveries
                            assert not state["requests"]
                            state.update(discoveryDelay=0)
                            break
                    time.sleep(.02)
                else:
                    raise AssertionError("metadata timeout did not retry")
                wait_status(fixture["a"], 200)
                assert h2_request(port, "/", [("authorization", "Bearer " + fixture["a"])])[0] == 200
            elif args.retry_backoff:
                def failures(expected, limit):
                    with lock:
                        begin = len(state["attempts"])
                        state["status"] = 503
                    deadline = time.monotonic() + limit
                    while time.monotonic() < deadline:
                        with lock:
                            times = [at for at, code, _ in state["attempts"][begin:] if code == 503]
                        if len(times) > len(expected):
                            intervals = [right - left for left, right in zip(times, times[1:])]
                            for got, want in zip(intervals, expected):
                                assert_retry_interval(got, want)
                            return
                        time.sleep(.02)
                    raise AssertionError(f"backoff retries {times} did not match {expected}")

                wait_status(fixture["a"], 200)
                failures((1, 2, 3, 3), 19)
                wait_status(fixture["a"], 401)
                assert h2_request(port, "/", [("authorization", "Bearer " + fixture["a"])])[0] == 401
                publish(json.dumps(fixture["first"]["jwks"]).encode())
                wait_status(fixture["a"], 200)
                failures((1,), 6)
                publish(json.dumps(fixture["first"]["jwks"]).encode())
                wait_status(fixture["a"], 200)
            elif args.retry_after:
                def delay_for(status, headers, expected, limit):
                    with lock:
                        begin = len(state["attempts"])
                        state.update(status=status, retryAfter=headers)
                    deadline = time.monotonic() + limit
                    while time.monotonic() < deadline:
                        with lock:
                            times = [at for at, code, _ in state["attempts"][begin:]
                                     if code == status]
                        if len(times) >= 2:
                            assert_retry_interval(times[1] - times[0], expected)
                            return
                        time.sleep(.02)
                    raise AssertionError(f"did not observe two HTTP {status} attempts: {times}")

                wait_status(fixture["a"], 200)
                delay_for(503, ("30",), 3, 9)
                wait_status(fixture["a"], 401)
                assert h2_request(port, "/", [("authorization", "Bearer " + fixture["a"])])[0] == 401
                delay_for(429, ("30", "30"), 1, 8)
                delay_for(503, ("0",), 1, 7)
                delay_for(429, ("2",), 2, 8)
                publish(json.dumps(fixture["first"]["jwks"]).encode())
                wait_status(fixture["a"], 200)
            elif args.dns_cache:
                wait_status(fixture["a"], 200)
                with lock:
                    initial_dns = state["dnsRequests"]
                    initial_keys = state["requests"]
                    state["dns"] = "timeout"
                assert initial_dns == 1
                wait_for_origin_request(initial_keys)
                with lock:
                    assert state["dnsRequests"] == initial_dns
                wait_for_dns_request(initial_dns, limit=8)
                wait_status(fixture["a"], 401)
                assert h2_request(port, "/", [("authorization", "Bearer " + fixture["a"])])[0] == 401
                with lock:
                    before_recovery = state["requests"]
                    state["dns"] = "move"
                wait_for_origin_address(before_recovery, "127.0.0.2")
                wait_status(fixture["a"], 200)
                assert h2_request(port, "/", [("authorization", "Bearer " + fixture["a"])])[0] == 200
            elif args.conditional:
                def observed(predicate, start=0, count=1, limit=12):
                    deadline = time.monotonic() + limit
                    while time.monotonic() < deadline:
                        with lock:
                            values = [item for item in state["conditionalRequests"][start:] if predicate(item)]
                        if len(values) >= count:
                            return values
                        request(fixture["a"])
                        time.sleep(.025)
                    raise AssertionError(f"missing conditional observation: {values}")

                def marker():
                    with lock:
                        return len(state["conditionalRequests"])

                def both(token, expected):
                    assert request(token) == expected
                    assert h2_request(port, "/", [("authorization", "Bearer " + token)])[0] == expected

                def configure(tag, body, mode="auto"):
                    with lock:
                        state.update(etag=tag, body=body, status=200, conditionalMode=mode)

                # A cold unsolicited304 cannot install even the configured initial keys.
                observed(lambda item: item["status"] == 304)
                both(fixture["a"], 401)
                configure('"v1"', json.dumps(fixture["first"]["jwks"]).encode())
                wait_status(fixture["a"], 200)
                start = marker()
                deadline = time.monotonic() + 4.2
                while time.monotonic() < deadline:
                    both(fixture["a"], 200)
                    time.sleep(.1)
                confirmations = observed(lambda item: item["status"] == 304, start, count=3)
                assert all(item["incoming"] == '"v1"' for item in confirmations)

                configure('"v2"', json.dumps(fixture["second"]["jwks"]).encode())
                wait_status(fixture["b"], 200)
                both(fixture["a"], 401)
                start = marker()
                observed(lambda item: item["incoming"] == '"v2"' and item["status"] == 304, start)
                configure('"empty"', b'{"keys":[]}')
                wait_status(fixture["b"], 401)
                start = marker()
                observed(lambda item: item["incoming"] == '"empty"' and item["status"] == 304, start, count=3)
                both(fixture["b"], 401)
                configure('"v3"', json.dumps(fixture["second"]["jwks"]).encode())
                wait_status(fixture["b"], 200)

                # Bad200 metadata/body must not replace the active validator or keys.
                invalid_key = json.loads(json.dumps(fixture["first"]["jwks"]))
                invalid_key["keys"][0]["n" if args.algorithm == "RS256" else "x"] = "bad"
                for mode, body in (("weak200", json.dumps(fixture["first"]["jwks"]).encode()),
                                   ("duplicate200", json.dumps(fixture["first"]["jwks"]).encode()),
                                   ("auto", b"{bad"),
                                   ("auto", json.dumps(invalid_key).encode())):
                    start = marker()
                    configure('"uncommitted"', body, mode)
                    attempts = observed(lambda item: item["tag"] == '"uncommitted"', start, count=2)
                    assert attempts[0]["incoming"] == '"v3"', attempts
                    assert all(item["incoming"] != '"uncommitted"' for item in attempts), attempts
                    both(fixture["a"], 401)
                    wait_status(fixture["b"], 401)
                    configure('"v3"', json.dumps(fixture["second"]["jwks"]).encode())
                    wait_status(fixture["b"], 200)
                for mode in ("missing304", "mismatch304", "weak304", "duplicate304"):
                    configure('"v3"', json.dumps(fixture["second"]["jwks"]).encode(), mode)
                    wait_status(fixture["b"], 401)
                    both(fixture["b"], 401)
                    configure('"v3"', json.dumps(fixture["second"]["jwks"]).encode())
                    wait_status(fixture["b"], 200)

                # Missing ETag on an accepted200 clears the previously committed validator.
                start = marker()
                configure(None, json.dumps(fixture["second"]["jwks"]).encode())
                observed(lambda item: item["tag"] is None, start)
                unconditional = observed(lambda item: item["tag"] is None and item["incoming"] is None,
                                          start, count=2)
                assert all(item["status"] == 200 for item in unconditional)
                configure('"v4"', json.dumps(fixture["second"]["jwks"]).encode())
                start = marker()
                observed(lambda item: item["incoming"] == '"v4"' and item["status"] == 304, start)

                # An already-sent conditional request cannot renew age after hard expiry.
                start = marker()
                with lock:
                    state["delay"] = 3.2
                observed(lambda item: item["delay"] == 3.2 and item["incoming"] == '"v4"', start)
                with lock:
                    state["delay"] = 0
                wait_status(fixture["b"], 401)
                both(fixture["b"], 401)
                late = observed(lambda item: item["delay"] == 0 and item["incoming"] is None, start)
                assert late[0]["status"] == 200
                wait_status(fixture["b"], 200)

                if args.discovery_dns:
                    # DNS/discovery time consumes validator freshness before the keysGET.
                    with lock:
                        discovery_start = len(state["discoveries"])
                        state["discoveryDelay"] = 3.2
                    deadline = time.monotonic() + 8
                    while True:
                        with lock:
                            delayed = any(delay == 3.2 for _, delay in state["discoveries"][discovery_start:])
                        if delayed:
                            break
                        assert time.monotonic() < deadline
                        request(fixture["b"])
                        time.sleep(.025)
                    start = marker()
                    with lock:
                        state["discoveryDelay"] = 0
                    wait_status(fixture["b"], 401)
                    item = observed(lambda item: True, start)[0]
                    assert item["incoming"] is None, item
                    wait_status(fixture["b"], 200)
                    # A changedIP and a failover onto the old boundIP both require a fullGET.
                    for mode in ("move", "cname-failover"):
                        start = marker()
                        with lock:
                            state["dns"] = mode
                        item = observed(lambda item: item["address"] == "127.0.0.2", start)[0]
                        assert item["incoming"] is None, item
                        both(fixture["b"], 200)
                        if mode == "move":
                            # Commit the newIP's validator before failing over onto that sameIP.
                            observed(lambda item: item["address"] == "127.0.0.2" and
                                     item["incoming"] == '"v4"' and item["status"] == 304, start)
                    with lock:
                        assert all(tag is None for tag, _ in state["discoveries"])
                        state["dns"] = "valid"
            else:
                if args.access_profile:
                    assert request(fixture["a"]) == 401, "remote access profile authenticated before cold fetch"
                    with lock: state["hold"] = False
                    cold_release.set()
                wait_status(fixture["a"], 200)
                if args.access_profile:
                    assert request(fixture["a"], with_body=True) == (200, b"alice")
                if retry_profile:
                    def failure_attempts(delay, count, limit=8):
                        deadline = time.monotonic() + limit
                        while time.monotonic() < deadline:
                            with lock:
                                times = [at for at, status, pause in state["attempts"]
                                         if status == 503 and pause == delay]
                            if len(times) >= count:
                                return times
                            time.sleep(.01)
                        raise AssertionError(f"missing failed refresh attempts: {delay}, {count}, {times}")

                    publish(b"unavailable", 503)
                    immediate = failure_attempts(0, 2)
                    assert immediate[1] - immediate[0] >= 1.8, immediate
                    publish(json.dumps(fixture["first"]["jwks"]).encode())
                    wait_status(fixture["a"], 200)
                    # Ensure recovery completed, rather than accepting an old fresh cache.
                    with lock:
                        previous = state["requests"]
                    wait_for_origin_request(previous)
                    with lock:
                        state["delay"] = 3
                    publish(b"unavailable", 503)
                    failure_attempts(3, 1)
                    wait_status(fixture["a"], 401)
                    assert h2_request(port, "/", [("authorization", "Bearer " + fixture["a"])])[0] == 401
                    delayed = failure_attempts(3, 2)
                    # timeoutSeconds=2 exceeds refreshSeconds=1: retries must wait
                    # two more seconds after timeout, not reconnect at completion.
                    assert delayed[1] - delayed[0] >= 3.8, delayed
                    with lock:
                        state["delay"] = 0
                    publish(json.dumps(fixture["first"]["jwks"]).encode())
                    wait_status(fixture["a"], 200)
                    assert h2_request(port, "/", [("authorization", "Bearer " + fixture["a"])])[0] == 200
                assert request(fixture["b"]) == 401
                if args.access_profile:
                    assert request(fixture["badClient"]) == 403, "signed wrong client must be forbidden"
                    assert request(fixture["badScope"]) == 403, "signed wrong scope must be forbidden"
                    for name in ("badIat", "badJti", "badKid", "badType"):
                        assert request(fixture[name]) == 401, f"{name} did not fail as invalid_token"
                with lock:
                    requests_before_refresh = state["requests"]
                publish(json.dumps(fixture["second"]["jwks"]).encode())
                # No gateway request is made while the one-second refresh becomes
                # due or while its TLS handshake/read advances on the idle shard.
                wait_for_origin_request(requests_before_refresh)
                time.sleep(0.1)
                assert request(fixture["b"]) == 200, "idle refresh did not install the rotated key"
                assert request(fixture["a"]) == 401, "replaced key still authenticates"
                publish(b'{"keys":[]}')
                wait_status(fixture["b"], 401)
                publish(json.dumps(fixture["second"]["jwks"]).encode())
                wait_status(fixture["b"], 200)
                publish(b"unavailable", 503)
                assert request(fixture["b"]) == 200, "fresh cache was discarded on outage"
                wait_status(fixture["b"], 401)
                publish(json.dumps(fixture["second"]["jwks"]).encode())
                wait_status(fixture["b"], 200)
                publish(b"{bad")
                wait_status(fixture["b"], 401)
                if args.discovery_dns:
                    publish(json.dumps(fixture["second"]["jwks"]).encode())
                    for kind, modes in [("discovery", ["issuer", "uri", "redirect"]),
                                        ("dns", ["rebind", "timeout"])]:
                        with lock: state[kind] = "valid"
                        wait_status(fixture["b"], 200)
                        for mode in modes:
                            with lock: state[kind] = mode
                            wait_status(fixture["b"], 401)
                            with lock: state[kind] = "valid"
                            wait_status(fixture["b"], 200)
                    def h2_status(token, expected):
                        status, _ = h2_request(port, "/read" if args.access_profile else "/",
                                               [("authorization", "Bearer " + token)])
                        assert status == expected, f"CNAME HTTP/2 expected {expected}, got {status}"

                    with lock:
                        state["dns"] = "cname"
                        requests_before_cname = state["requests"]
                    publish(json.dumps(fixture["first"]["jwks"]).encode())
                    wait_for_origin_request(requests_before_cname)
                    wait_status(fixture["a"], 200)
                    assert request(fixture["b"]) == 401
                    h2_status(fixture["a"], 200)
                    h2_status(fixture["b"], 401)
                    with lock:
                        state["dns"] = "cname-reordered"
                    publish(json.dumps(fixture["second"]["jwks"]).encode())
                    wait_status(fixture["b"], 200)
                    h2_status(fixture["b"], 200)
                    for mode in ("cname-poison", "cname-cycle", "cname-zero-ttl", "cname-unrelated"):
                        with lock:
                            state["dns"] = mode
                            dns_before_failure = state["dnsRequests"]
                        # A new DNS attempt follows completion of any previous fetch.
                        wait_for_dns_request(dns_before_failure)
                        with lock:
                            origin_before_failure = state["requests"]
                        # Failed DNS must not renew the last successful key age.
                        wait_status(fixture["b"], 401)
                        h2_status(fixture["b"], 401)
                        with lock:
                            assert state["requests"] == origin_before_failure, mode
                            state["dns"] = "cname"
                        wait_status(fixture["b"], 200)
                        h2_status(fixture["b"], 200)
                    with lock:
                        dns_before_move = state["dnsRequests"]
                        origin_before_move = state["requests"]
                        state["dns"] = "cname-failover"
                    wait_for_dns_request(dns_before_move)
                    wait_for_origin_address(origin_before_move, "127.0.0.2")
                    wait_status(fixture["b"], 200)
                    h2_status(fixture["b"], 200)
            # Leave an authenticated fetch waiting on an origin response while
            # retiring the gateway, exercising in-flight refresh cancellation.
            with lock:
                requests_before_shutdown = state["requests"]
                dns_before_shutdown = state["dnsRequests"]
                state["hold"] = True
                if args.dns_https:
                    state["dns"] = "hold"
            if args.dns_https:
                wait_for_dns_request(dns_before_shutdown)
            else:
                wait_for_origin_request(requests_before_shutdown)
            process.terminate()
            output = process.communicate(timeout=5)[0].decode(errors="replace")
            assert process.returncode == 0, output
            release_response.set()
            print(f"PASS: {args.algorithm} {args.backend} remote {'access-token ' if args.access_profile else ''}JWKS rotation, empty set, outage, malformed refresh and shutdown")
    finally:
        cold_release.set()
        release_response.set()
        if refusing is not None:
            refusing.close()
        dns_stop.set()
        if dns is not None: dns.close()
        if tcp_dns is not None: tcp_dns.close()
        if https_dns is not None:
            https_dns.shutdown()
            https_dns.server_close()
        dns_worker.join(timeout=2)
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
        origin.shutdown()
        origin.server_close()
        worker.join(timeout=5)
        if origin2 is not None:
            origin2.shutdown()
            origin2.server_close()
            worker2.join(timeout=5)


if __name__ == "__main__":
    main()
