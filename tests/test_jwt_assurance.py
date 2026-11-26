#!/usr/bin/env python3
"""Exercise five assurance policies through a native-loaded gateway."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from auth_h2_fixture import request as h2_request
from test_jwt_scope_lists import KEY, request, token


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--backend", required=True)
    args = parser.parse_args()
    source = Path(args.source).resolve()
    now = int(time.time())
    base = dict(sub="alice", iss="https://issuer.example", aud="orders", iat=now, exp=now + 600)
    policies = {
        "/acr": ({'acr': 'assured'}, [{'acr': 'Assured'}, {'acr': ['assured']}]),
        "/amr": ({'amr': ['pwd', 'otp']}, [{'amr': ['otp', 7]}, {'amr': 'otp'}, {'amr': ['pwd']}]),
        "/auth-age": ({'auth_time': now - 10}, [{'auth_time': now + 1}, {'auth_time': now - 240},
                                               {'auth_time': str(now)}, {'auth_time': 0},
                                               {'auth_time': now, 'iat': now - 1}]),
        "/email": ({'email': 'alice@example.test', 'email_verified': True},
                   [{'email': 'Alice@example.test', 'email_verified': True},
                    {'email': 'alice@example.test', 'email_verified': 'true'},
                    {'email': 'alice@example.test', 'email_verified': False}]),
        "/session": ({'sid': 'session-one'}, [{'sid': 'session-two'}, {'sid': 1}]),
    }
    with tempfile.TemporaryDirectory(prefix="rut-jwt-assurance-") as directory:
        root = Path(directory)
        env = dict(os.environ, JWT_SECRET=KEY, JWT_REQUIRED_ACR="assured", JWT_REQUIRED_AMR="otp",
                   JWT_MAX_AUTH_AGE="120", JWT_VERIFIED_EMAIL="alice@example.test",
                   JWT_REQUIRED_SESSION="session-one")
        for configured in (True, False):
            (root / "middleware").mkdir()
            module = "middleware/jwt_assurance.rut"
            shutil.copyfile(source.parent / module, root / module)
            program = root / "assurance.rut"
            program.write_text(source.read_text().replace("listen :8080\n", ""))
            log_path = root / "gateway.log"
            if not configured:
                env.update(JWT_REQUIRED_ACR="", JWT_REQUIRED_AMR="", JWT_MAX_AUTH_AGE="0",
                           JWT_VERIFIED_EMAIL="", JWT_REQUIRED_SESSION="")
            with log_path.open("wb") as log:
                proc = subprocess.Popen([args.server, "0", str(program), "--backend", args.backend,
                                         "--shards", "1", "--no-pin", "--drain", "0"],
                                        env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 20
                while True:
                    startup = log_path.read_bytes()
                    matched = re.search(rb"Listening on port (\d+) with", startup)
                    if matched:
                        port = int(matched.group(1))
                        break
                    if proc.poll() is not None and b"io_uring is unavailable" in startup:
                        return 77
                    assert proc.poll() is None and time.monotonic() < deadline, startup.decode()
                    time.sleep(.025)
                program.unlink()
                shutil.rmtree(root / "middleware")
                for route, (good, bad) in policies.items():
                    credential = token(dict(base, **good))
                    expected = 204 if configured else 503
                    assert request(port, route, "HTTP/1.1", credential)[0] == expected, route
                    assert h2_request(port, route, [("authorization", "Bearer " + credential)])[0] == expected
                    assert request(port, route, "HTTP/1.1", credential, duplicate=True)[0] == 401
                    expired = token(dict(base, **good) | {"exp": now - 1})
                    assert request(port, route, "HTTP/1.1", expired)[0] == 401
                    if configured:
                        for rejection in [{}, *bad]:
                            assert request(port, route, "HTTP/1.1",
                                           token(base | rejection))[0] == 403, (route, rejection)
            finally:
                proc.terminate()
                proc.wait(timeout=10)
    print(f"{args.backend}: five JWT assurance policies passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
