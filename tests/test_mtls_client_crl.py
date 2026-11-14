#!/usr/bin/env python3
"""Pinned-OpenSSL CRLs, native mTLS identity and TLS1.2/1.3 H1/H2 boundaries."""
import argparse
from contextlib import contextmanager
import hashlib
import http.client
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

from auth_h2_fixture import request as h2_request


def context(args, root, name, version, h2=False):
    ctx = ssl.create_default_context(cafile=str(Path(args.testdata) / 'localhost_cert.pem'))
    ctx.minimum_version = ctx.maximum_version = version
    ctx.set_alpn_protocols(['h2' if h2 else 'http/1.1'])
    if name is not None:
        ctx.load_cert_chain(str(root / name), str(Path(args.testdata) / 'localhost_key.pem'))
    return ctx


def base_command(args, source, port):
    certs = Path(args.testdata)
    return [args.server, str(port), str(source), '--backend', args.backend,
            '--no-pin', '--shards', '2', '--drain', '0', '--h2',
            '--tls-cert', str(certs / 'localhost_cert.pem'), '--tls-key', str(certs / 'localhost_key.pem'),
            '--tls-client-ca', str(certs / 'localhost_cert.pem')]


@contextmanager
def gateway(args, root, crl, keep_file=False):
    folder = root / str(time.monotonic_ns())
    folder.mkdir()
    original = Path(args.source).resolve()
    (folder / 'middleware').mkdir()
    for name in ('auth.rut', 'mtls.rut'):
        shutil.copyfile(original.parent / 'middleware' / name, folder / 'middleware' / name)
    source = folder / 'auth.rut'
    source.write_text(original.read_text())
    snapshot = folder / 'clients.crl'
    shutil.copyfile(root / crl, snapshot)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    def pin(name):
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert((root / name).read_text())).hexdigest()
    env = dict(os.environ, MTLS_FIRST_CONSUMER='alice', MTLS_SECOND_CONSUMER='bob',
               MTLS_FIRST_PIN=pin('first.pem'), MTLS_SECOND_PIN=pin('second.pem'),
               MTLS_FIRST_ID='alice-cert', MTLS_SECOND_ID='bob-cert')
    log = folder / 'gateway.log'
    with log.open('w') as out:
        process = subprocess.Popen(base_command(args, source, port) + ['--tls-client-crl', str(snapshot)],
                                   env=env, stdout=out, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 60
        while True:
            if process.poll() is not None:
                if args.backend == 'io_uring' and 'io_uring is unavailable' in log.read_text():
                    raise SystemExit(77)
                raise AssertionError(log.read_text())
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1):
                    break
            except OSError:
                assert time.monotonic() < deadline, log.read_text()
                time.sleep(.025)
        source.unlink()
        shutil.rmtree(folder / 'middleware')
        if not keep_file:
            snapshot.unlink()  # Verification must use the owned, parsed CRL.
        yield port, snapshot
    finally:
        process.terminate()
        try:
            process.wait(5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        assert 'PRIVATE KEY' not in log.read_text()


def h1(connection, version='HTTP/1.1', close=True):
    connection.sendall((f'GET /private {version}\r\nHost: localhost\r\n' +
                        ('Connection: close\r\n' if close else '') +
                        'X-Client-Cert: trusted\r\nX-Consumer-ID: alice\r\n\r\n').encode())
    response = http.client.HTTPResponse(connection)
    response.begin()
    status, body = response.status, response.read()
    response.close()
    return status, body


def allowed(port, ctx, subject, version='HTTP/1.1'):
    with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname='localhost') as connection:
            assert not connection.session_reused
            assert h1(connection, version) == (200, subject)
            return connection.session


def denied(port, ctx, h2=False):
    try:
        if h2:
            h2_request(port, '/private', [], tls_context=ctx)
        else:
            with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
                with ctx.wrap_socket(raw, server_hostname='localhost') as connection:
                    h1(connection)
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected):
        return
    except AssertionError as error:
        if h2 and str(error) == 'HTTP/2 response closed early':
            return
        raise
    raise AssertionError('unverified client reached an HTTP response')


def startup_rejections(args, root):
    source = root / 'invalid.rut'
    source.write_text('route "/" { return 200 }\n')
    (root / 'empty.pem').write_bytes(b'')
    (root / 'garbage.pem').write_bytes(b'not a CRL')
    (root / 'trailing.pem').write_bytes((root / 'clear.pem').read_bytes() + b'junk')
    (root / 'multiple.pem').write_bytes((root / 'clear.pem').read_bytes() * 2)
    (root / 'ca-tail.pem').write_bytes((root / 'clear.pem').read_bytes() +
                                     (Path(args.testdata) / 'localhost_cert.pem').read_bytes())
    (root / 'oversized.pem').write_bytes((root / 'clear.pem').read_bytes() + b' ' * 65536)
    os.mkfifo(root / 'fifo.pem')
    for name in ('empty.pem', 'garbage.pem', 'trailing.pem', 'multiple.pem', 'ca-tail.pem',
                 'oversized.pem', 'expired.pem', 'future.pem', 'no-next.pem', 'delta.pem', 'indirect.pem',
                 'nonexistent.pem', 'fifo.pem'):
        result = subprocess.run(base_command(args, source, 0) + ['--tls-client-crl', str(root / name)],
                                capture_output=True, timeout=10)
        if args.backend == 'io_uring' and b'io_uring is unavailable' in result.stderr + result.stdout:
            raise SystemExit(77)
        assert result.returncode == 1 and b'Failed to initialize TLS' in result.stderr + result.stdout, (name, result)
    bundle = root / 'ca-with-crl.pem'
    bundle.write_bytes((Path(args.testdata) / 'localhost_cert.pem').read_bytes() +
                       (root / 'clear.pem').read_bytes())
    command = base_command(args, source, 0)
    command[command.index('--tls-client-ca') + 1] = str(bundle)
    result = subprocess.run(command + ['--tls-client-crl', str(root / 'revoked.pem')],
                            capture_output=True, timeout=10)
    assert result.returncode == 1 and b'Failed to initialize TLS' in result.stderr + result.stdout, result
    for tail in (['--tls-client-crl'], ['--tls-client-crl', '--no-pin'],
                 ['--tls-client-crl', str(root / 'clear.pem')]):
        result = subprocess.run([args.server, '0', str(source), *tail], capture_output=True, timeout=10)
        assert result.returncode == 1 and b'--tls-client-crl requires' in result.stderr + result.stdout, result


def exercise(args, root):
    subprocess.run([args.helper, args.testdata, str(root)], check=True, timeout=10)
    startup_rejections(args, root)
    for profile in ('revoked.pem', 'bad-signature.pem', 'wrong-issuer.pem'):
        with gateway(args, root, profile) as (port, _):
            for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                for h2 in (False, True):
                    denied(port, context(args, root, 'first.pem', version, h2), h2)
                    denied(port, context(args, root, None, version, h2), h2)
                    if profile == 'revoked.pem':
                        if h2:
                            assert h2_request(port, '/private', [], tls_context=context(
                                args, root, 'second.pem', version, True)) == (200, b'bob')
                        else:
                            for http_version in ('HTTP/1.0', 'HTTP/1.1'):
                                ctx = context(args, root, 'second.pem', version)
                                previous = allowed(port, ctx, b'bob', http_version)
                                with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
                                    with ctx.wrap_socket(raw, server_hostname='localhost', session=previous) as resumed:
                                        assert not resumed.session_reused
                                        assert h1(resumed) == (200, b'bob')
                    else:
                        denied(port, context(args, root, 'second.pem', version, h2), h2)
    # The exact input limit remains usable, including a long whitespace tail.
    (root / 'boundary.pem').write_bytes((root / 'clear.pem').read_bytes().ljust(65536, b' '))
    with gateway(args, root, 'boundary.pem') as (port, _):
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            allowed(port, context(args, root, 'first.pem', version), b'alice')
            assert h2_request(port, '/private', [], tls_context=context(
                args, root, 'second.pem', version, True)) == (200, b'bob')
    # File replacement does not mutate an installed listener trust snapshot.
    # Old established work continues; a replacement listener checks the new CRL.
    with gateway(args, root, 'clear.pem', keep_file=True) as (old_port, snapshot):
        ctx = context(args, root, 'first.pem', ssl.TLSVersion.TLSv1_3)
        with socket.create_connection(('127.0.0.1', old_port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname='localhost') as existing:
                assert h1(existing, close=False) == (200, b'alice')
                snapshot.write_bytes((root / 'revoked.pem').read_bytes())
                assert h1(existing, close=False) == (200, b'alice')
                allowed(old_port, ctx, b'alice')
                with gateway(args, root, 'revoked.pem') as (new_port, _):
                    denied(new_port, ctx)
                    allowed(new_port, context(args, root, 'second.pem', ssl.TLSVersion.TLSv1_3), b'bob')
                    assert h1(existing) == (200, b'alice')
    # A fresh full handshake must fail after nextUpdate, even though the CRL
    # was current at listener creation. Existing TLS connections remain usable.
    deadline = int(subprocess.check_output([args.helper, args.testdata, str(root), '--short'], timeout=10))
    with gateway(args, root, 'short.pem') as (port, _):
        ctx = context(args, root, 'first.pem', ssl.TLSVersion.TLSv1_3)
        with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname='localhost') as existing:
                assert h1(existing, close=False) == (200, b'alice')
                while time.time() < deadline + 1:
                    # Keep the authenticated connection active: ordinary idle
                    # retirement is independent of CRL expiry on either backend.
                    assert h1(existing, close=False) == (200, b'alice')
                    time.sleep(min(.25, max(0, deadline - time.time() + 1)))
                for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                    denied(port, context(args, root, 'first.pem', version))
                assert h1(existing) == (200, b'alice')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--helper', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='rut-mtls-crl-') as directory:
        exercise(args, Path(directory))
    print('PASS: leaf CRL verification, TLS1.2/1.3 HTTP1/2, expiry and snapshot/session boundaries')


if __name__ == '__main__':
    main()
