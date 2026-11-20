import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from test_jwt_sessions import KEY, NAMESPACE, Peer, exchange, permit_key, signed

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--testdata", required=True)
    parser.add_argument("--backend", choices=("epoll", "io_uring"), required=True)
    parser.add_argument("--opt", choices=("0", "2"), default="2")
    args = parser.parse_args()
    original = Path(args.source).resolve()
    certificates = Path(args.testdata).resolve()
    peer = Peer(certificates, False)
    try:
        now = int(time.time())
        claims = dict(sub="alice", iss="issuer", aud="gateway", iat=now, exp=now + 600)
        good = signed(claims)
        invalid = [signed({k: v for k, v in claims.items() if k != "iat"}),
                   signed(dict(claims, iat=now - 301, exp=now + 120)),
                   signed(dict(claims, iat=now, exp=now + 601)),
                   signed(dict(claims, iat=now + 30, exp=now + 600)), signed(claims, key="wrong")]
        with peer.lock:
            peer.store[permit_key(good)] = b"active"
        with tempfile.TemporaryDirectory(prefix="rut-jwt-session-lifetime-") as directory:
            root = Path(directory)
            shutil.copytree(original.parent / "clients", root / "clients")
            (root / "middleware").mkdir()
            for name in ("jwt_session.rut",):
                shutil.copyfile(original.parent / "middleware" / name, root / "middleware" / name)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            source = root / "session.rut"
            source.write_text(original.read_text().replace("listen :8080", f"listen :{port}"))
            endpoint = dict(address="127.0.0.1", port=peer.port, poolIdleMs=5000)
            env = dict(os.environ, JWT_SECRET=KEY, JWT_PREVIOUS_SECRET="", JWT_ISSUER="issuer", JWT_AUDIENCE="gateway",
                       JWT_SESSION_NAMESPACE=NAMESPACE, REDIS_ENDPOINT=json.dumps(endpoint),
                       REDIS_USERNAME="gateway", REDIS_PASSWORD="service-password", REDIS_DATABASE="1")
            log = root / "gateway.log"
            with log.open("w") as output:
                process = subprocess.Popen([args.server, str(source), "--backend", args.backend, "--opt", args.opt,
                                            "--no-pin", "--shards", "1", "--drain", "0"],
                                           env=env, stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 60
                while True:
                    if process.poll() is not None:
                        data = log.read_text()
                        if args.backend == "io_uring" and "io_uring is unavailable" in data:
                            return 77
                        raise AssertionError(data)
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.1):
                            break
                    except OSError:
                        assert time.monotonic() < deadline, log.read_text()
                        time.sleep(.025)
                for version in ("HTTP/1.0", "HTTP/1.1"):
                    assert exchange(port, version, good)[0] == 204
                    for value in invalid:
                        with peer.lock:
                            before = (peer.accepted, len(peer.commands))
                        status, _, challenges, _ = exchange(port, version, value)
                        assert status == 401
                        assert challenges == (['Bearer'] if value in invalid[3:] else ['Bearer error="invalid_token"']), (invalid.index(value), challenges)
                        with peer.lock:
                            assert (peer.accepted, len(peer.commands)) == before
                    with peer.lock:
                        before = (peer.accepted, len(peer.commands))
                    assert exchange(port, version, good, duplicate=True)[0] == 401
                    with peer.lock:
                        assert (peer.accepted, len(peer.commands)) == before
            finally:
                process.terminate()
                process.wait(timeout=10)
        print("PASS bounded JWT session lifetime before Redis")
        return 0
    finally:
        peer.close()


if __name__ == "__main__":
    raise SystemExit(main())
