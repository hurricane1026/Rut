#!/usr/bin/env python3
"""OPA Data API protocol fixture through the native-loaded gateway, without OPA dependencies."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    args = parser.parse_args()
    records, forwarded = [], []
    record_lock = threading.Lock()

    class Policy(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            request = json.loads(raw)
            with record_lock:
                records.append((self.path, dict(self.headers), request))
            resource = request['input']['resource']
            time.sleep(.20 if resource == 'slow' else .02)
            status = {'redirect': 302, 'unauthorized': 401, 'forbidden': 403,
                      'error': 500}.get(resource, 200)
            body = {'deny': '{"result":false}', 'undefined': '{}',
                    'wrong-type': '{"result":"true"}', 'null': '{"result":null}',
                    'malformed': '{', 'duplicate': '{"result":false,"result":true}',
                    'alias': '{"result":false,"resul\\u0074":true}',
                    'large': 'x' * 9000}.get(resource, '{"result":true}')
            if self.path.endswith('/decision'):
                body = json.dumps(dict(result=dict(allow=resource != 'deny',
                                      tenant='tenant-' + resource, role='reader')))
            try:
                if resource == 'truncated':
                    self.connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}')
                    self.close_connection = True
                    return
                data = body.encode()
                self.send_response(status)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Content-Type', 'application/json')
                self.send_header('X-Consumer-ID', 'policy-must-not-replace-identity')
                self.send_header('Set-Cookie', 'policy-must-not-leak=1')
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(data)
            except (OSError, ssl.SSLError):
                pass

        def log_message(self, *unused):
            pass

    class Upstream(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            with record_lock:
                forwarded.append((self.path, dict(self.headers)))
            body = self.path.encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *unused):
            pass

    policy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Policy)
    upstream = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'),
                            str(Path(args.testdata) / 'localhost_key.pem'))
    policy.socket = context.wrap_socket(policy.socket, server_side=True)
    for service in (policy, upstream):
        threading.Thread(target=service.serve_forever, daemon=True).start()
    endpoint = dict(address='127.0.0.1', port=policy.server_port, serverName='localhost',
                    caFile=str(Path(args.testdata) / 'localhost_cert.pem'), path='/v1/data/rut/allow')
    examples = Path(__file__).resolve().parent.parent / 'examples'
    try:
        with tempfile.TemporaryDirectory(prefix='rut-opa-') as directory:
            root = Path(directory)
            (root / 'middleware').mkdir()
            for name in ('auth.rut', 'opa.rut'):
                (root / 'middleware' / name).write_bytes((examples / 'middleware' / name).read_bytes())
            source = (examples / 'opa-auth.rut').read_text().replace(':9000"', f':{upstream.server_port}"')
            source = source.replace('listen :8080\n', '')  # CLI selects an ephemeral port.
            source += '''
route GET "/ready" { return 204 }
route POST "/boolean" {
    guard let reply = json.parse(req.body) else { return 400 }
    let allowed = opa.requireAllow(reply)
    guard let body = json(allowed) else { return 503 }
    return response(200, body: body)
}
route POST "/decision" {
    guard let reply = json.parse(req.body) else { return 400 }
    let allowed = opa.requireDecision(reply)
    guard let body = json(allowed) else { return 503 }
    return response(200, body: body)
}
route POST "/build" {
    guard let input = json.parse(req.body) else { return 400 }
    guard let request = opa.request(input) else { return 503 }
    guard let body = json(request) else { return 503 }
    return response(200, body: body)
}
route GET "/mapped/:id" {
    let resource = req.param("id").or("")
    guard let input = json.value({subject: "verified", resource: resource}) else { return 503 }
    guard let request = opa.request(input) else { return 503 }
    let pending = httpCall(env("OPA_DECISION"), request, 1000)
    guard let reply = pending else { return 503 }
    let allowed = opa.requireDecision(reply)
    guard let body = json(allowed) else { return 503 }
    return response(200, body: body)
}
route GET "/timeout" {
    guard let input = json.parse("{\\"resource\\":\\"slow\\"}") else { return 503 }
    guard let request = opa.request(input) else { return 503 }
    let pending = httpCall(env("OPA_ENDPOINT"), request, 50)
    guard let reply = pending else { return 503 }
    let allowed = opa.requireAllow(reply)
    return 204
}
route GET "/untrusted" {
    guard let input = json.parse("{\\"resource\\":\\"allow\\"}") else { return 503 }
    guard let request = opa.request(input) else { return 503 }
    let pending = httpCall(env("OPA_UNTRUSTED"), request, 1000)
    guard let reply = pending else { return 503 }
    let allowed = opa.requireAllow(reply)
    return 204
}
'''
            program, log = root / 'gateway.rut', root / 'gateway.log'
            program.write_text(source)
            env = dict(os.environ, RUT_API_KEY='local-secret', OPA_ENDPOINT=json.dumps(endpoint),
                       OPA_DECISION=json.dumps(dict(endpoint, path='/v1/data/rut/decision')),
                       OPA_UNTRUSTED=json.dumps(dict(endpoint, serverName='wrong.invalid')))
            with log.open('wb') as output:
                process = subprocess.Popen([args.server, '0', str(program), '--backend', args.backend,
                                            '--shards', '2', '--no-pin', '--drain', '0'],
                                           env=env, stdout=output, stderr=subprocess.STDOUT)
                try:
                    port = None
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        startup = log.read_bytes()
                        match = re.search(rb'Listening on port ([0-9]+) with', startup)
                        if match:
                            port = int(match.group(1))
                            break
                        if process.poll() is not None:
                            if args.backend == 'io_uring' and b'io_uring is unavailable' in startup:
                                return 77
                            raise AssertionError(startup.decode(errors='replace'))
                        time.sleep(.02)
                    assert port, log.read_text(errors='replace')
                    # Imports and policy bytes must survive compiler exit and source removal.
                    program.unlink()
                    for module in (root / 'middleware').iterdir():
                        module.unlink()

                    def request(path, body=None, authorization='Bearer local-secret'):
                        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
                        try:
                            connection.request('GET' if body is None else 'POST', path, body,
                                               {'Authorization': authorization, 'X-Consumer-ID': 'forged',
                                                'Cookie': 'private-client-cookie=1'})
                            response = connection.getresponse()
                            return response.status, dict(response.headers), response.read()
                        finally:
                            connection.close()

                    def envelope(body, **kwargs):
                        return json.dumps(dict(ok=True, status=200, body=body, **kwargs))

                    for raw, boolean, decision in [
                        ('{"result":true}', 200, 503), ('{"result":false}', 403, 503),
                        ('{}', 403, 403), ('{"decision_id":"undefined"}', 403, 403),
                        ('{"result":{"allow":true,"tenant":"t1","roles":["read"]}}', 503, 200),
                        ('{"result":{"allow":false}}', 503, 403),
                        ('{"result":{}}', 503, 503), ('{"result":{"allow":"true"}}', 503, 503),
                        ('{"result":null}', 503, 503), ('{"result":1}', 503, 503),
                        ('{"result":[]}', 503, 503), ('{"result":"true"}', 503, 503),
                        ('{"result":false,"result":true}', 503, 503),
                        ('{"result":true,"resul\\u0074":false}', 503, 503),
                        ('{"result":{"allow":true,"all\\u006fw":false}}', 503, 503),
                        ('{"result":true,"decision_id":"trace"}', 200, 503),
                        ('{"resul\\u0074":true}', 200, 503),
                        ('null', 503, 503), ('[]', 503, 503), ('true', 503, 503),
                        ('{"result":true} trailing', 503, 503), ('{', 503, 503)]:
                        for route, expected in (('/boolean', boolean), ('/decision', decision)):
                            status, _, data = request(route, envelope(raw))
                            assert status == expected, (route, raw, status, expected, data)
                            if status == 200:
                                parsed = json.loads(data)
                                assert parsed == (json.loads(raw) if route == '/boolean' else json.loads(raw)['result'])
                    for reply in ({}, {'ok': False, 'status': 200, 'body': '{"result":true}'},
                                  {'ok': 'true', 'status': 200, 'body': '{"result":true}'},
                                  {'ok': True, 'status': '200', 'body': '{"result":true}'},
                                  {'ok': True, 'status': 200, 'body': {'result': True}},
                                  {'ok': False, 'status': 0, 'error': 'timeout'}):
                        for route in ('/boolean', '/decision'):
                            assert request(route, json.dumps(reply))[0] == 503, reply
                    for status in (201, 204, 302, 401, 403, 500):
                        reply = json.dumps(dict(ok=True, status=status, body='{"result":true}'))
                        assert request('/boolean', reply)[0] == 503
                    for value in ({'subject': 'x"\\\n雪', 'items': [1, True, None, {'nested': 'y'}]},
                                  [False, 'text'], 'input', None):
                        status, _, data = request('/build', json.dumps(value))
                        assert status == 200, (value, status, data)
                        built = json.loads(data)
                        assert built['method'] == 'POST'
                        assert built['headers'] == {'Content-Type': 'application/json'}
                        assert json.loads(built['body']) == {'input': value}
                    before = len(records)
                    rejected = request('/reports/allow', authorization='Bearer wrong')
                    assert rejected[0] == 401, rejected
                    assert len(records) == before and not forwarded
                    status, headers, data = request('/reports/allow')
                    assert (status, data) == (200, b'/reports/allow'), (status, data)
                    assert 'Set-Cookie' not in headers and 'X-Consumer-ID' not in headers
                    assert len(records) == before + 1 and len(forwarded) == 1
                    assert forwarded[-1][1]['X-Consumer-ID'] == 'report-reader'
                    assert 'Authorization' not in forwarded[-1][1]
                    for mode, expected in (('deny', 403), ('undefined', 403), ('wrong-type', 503),
                                           ('null', 503), ('malformed', 503), ('duplicate', 503),
                                           ('alias', 503), ('redirect', 503), ('unauthorized', 503),
                                           ('forbidden', 503), ('error', 503), ('large', 503),
                                           ('truncated', 503)):
                        status, _, data = request('/reports/' + mode)
                        assert status == expected, (mode, status, data)
                        assert len(forwarded) == 1, (mode, forwarded)
                    assert request('/timeout')[0] == 503
                    before = len(records)
                    assert request('/untrusted')[0] == 503
                    assert len(records) == before  # Wrong TLS identity sends no HTTP request.
                    assert request('/mapped/deny')[0] == 403
                    with ThreadPoolExecutor(max_workers=4) as workers:
                        results = list(workers.map(lambda i: request('/mapped/' + str(i)), range(4)))
                    for i, (status, _, data) in enumerate(results):
                        assert status == 200 and json.loads(data) == dict(allow=True, tenant=f'tenant-{i}', role='reader'), (i, status, data)
                    # A body-less H2 request must retain its selected input and
                    # consume the decision only after the TLS call resumes.
                    def frame(kind, flags, stream, data=b''):
                        return len(data).to_bytes(3, 'big') + bytes((kind, flags)) + stream.to_bytes(4, 'big') + data

                    with socket.create_connection(('127.0.0.1', port), timeout=4) as sock:
                        block = b'\x82\x86\x04\x0a/mapped/h2\x01\x09localhost'
                        sock.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4, 0, 0) + frame(1, 5, 1, block))

                        def exact(length):
                            data = b''
                            while len(data) < length:
                                part = sock.recv(length - len(data))
                                assert part, 'HTTP/2 closed before decision'
                                data += part
                            return data

                        data = b''
                        while True:
                            header = exact(9)
                            payload = exact(int.from_bytes(header[:3], 'big'))
                            kind, flags = header[3], header[4]
                            stream = int.from_bytes(header[5:], 'big') & 0x7fffffff
                            if kind == 4 and not flags & 1:
                                sock.sendall(frame(4, 1, 0))
                            assert kind != 7, payload
                            if stream != 1:
                                continue
                            assert kind != 3, payload
                            if kind == 0:
                                data += payload
                            if kind in (0, 1) and flags & 1:
                                break
                        assert json.loads(data) == dict(allow=True, tenant='tenant-h2', role='reader'), data
                    for path, headers, message in records:
                        assert path in ('/v1/data/rut/allow', '/v1/data/rut/decision')
                        assert headers['Content-Type'] == 'application/json'
                        assert all(key.lower() not in ('authorization', 'cookie', 'x-consumer-id') for key in headers)
                        assert set(message) == {'input'}
                        if message['input']['resource'] == 'allow':
                            assert message['input']['subject'] == 'report-reader'
                    print(f'PASS: {args.backend} OPA Boolean/structured decisions, strict errors, TLS, authenticated proxy and isolation')
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        raise AssertionError('OPA callout worker shutdown timed out')
                    if process.returncode not in (0, 77):
                        raise AssertionError((process.returncode, log.read_text(errors='replace')))
    finally:
        for service in (policy, upstream):
            service.shutdown()
            service.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
