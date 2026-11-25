#!/usr/bin/env python3
"""Exercise bounded Memcached Meta mutations against wire fixtures and a real peer."""
import argparse
from pathlib import Path
import ssl
import time

from test_memcache_client import gateway, real_memcached
from test_client_read_control import connect
from test_redis_commands import Fixture


PROGRAM = r'''import "memcache-meta.rut"
func storeMode(_ name: str, _ cas: Bytes) -> MemcacheMetaStoreMode {
    match name {
        "add" => MemcacheMetaStoreMode.add
        "replace" => MemcacheMetaStoreMode.replace
        "append" => MemcacheMetaStoreMode.append
        "prepend" => MemcacheMetaStoreMode.prepend
        "cas" => MemcacheMetaStoreMode.compare(cas)
        _ => MemcacheMetaStoreMode.set
    }
}
func direction(_ name: str) -> MemcacheMetaArithmeticMode {
    if name == "decrement" { MemcacheMetaArithmeticMode.decrement }
    else { MemcacheMetaArithmeticMode.increment }
}
func counterPolicy(_ seed: str, _ cas: str) -> MemcacheMetaCounterPolicy {
    if seed != "" {
        MemcacheMetaCounterPolicy.create(MemcacheMetaCounterSeed(value: Bytes(seed),
            expiry: MemcacheExpiry.seconds(60)))
    } else {
        if cas != "" { MemcacheMetaCounterPolicy.compare(Bytes(cas)) }
        else { MemcacheMetaCounterPolicy.existing }
    }
}
func status(_ result: MemcacheMetaCommandResult) -> i32 {
    match result {
        .ok => 200
        .value(value) => 200
        .missing => 404
        .notStored => 412
        .exists => 409
        .serverError(message) => 422
        .requestFailure => 400
        _ => 502
    }
}
func data(_ result: MemcacheMetaCommandResult) -> Bytes {
    match result {
        .value(value) => value
        _ => b""
    }
}
'''
ROUTE = r'''route POST "/PATH" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let key = Bytes(req.header("X-Key").or("key"))
    let result = CALL
    let closed = connection.close()
    let code = status(result)
    guard closed == (code != 422 && code != 502) else { return 500 }
    guard code != 404 else { return 404 }
    guard code != 412 else { return 412 }
    guard code != 409 else { return 409 }
    guard code != 422 else { return 422 }
    guard code != 400 else { return 400 }
    guard code != 502 else { return 502 }
    let value = data(result)
    return response(200, body: value)
}
'''
CALLS = {
    'store': '''memcacheMetaStore(connection, key, req.bodyBytes,
        storeMode(req.header("X-Mode").or(""), Bytes(req.header("X-Cas").or(""))),
        Bytes(req.header("X-Flags").or("0")), MemcacheExpiry.seconds(60))''',
    'arithmetic': '''memcacheMetaArithmetic(connection, key,
        direction(req.header("X-Mode").or("")), Bytes(req.header("X-Delta").or("1")),
        counterPolicy(req.header("X-Seed").or(""), req.header("X-Cas").or("")))''',
    'delete': 'memcacheMetaDelete(connection, key)',
    'noop': 'memcacheMetaNoop(connection)',
    'debug': 'memcacheMetaDebug(connection, key)',
}


def program():
    return PROGRAM + ''.join(ROUTE.replace('/PATH', '/' + path).replace('CALL', call)
                             for path, call in CALLS.items())


class MetaPeer(Fixture):
    def __init__(self, tls_context):
        self.reply = b''
        super().__init__(tls_context)

    def serve(self, connection):
        try:
            if self.tls_context:
                connection = self.tls_context.wrap_socket(connection, server_side=True)
            with connection, connection.makefile('rb') as stream:
                line = stream.readline()
                if not line:
                    return
                payload = stream.read(int(line.split()[2]) + 2) if line.startswith(b'ms ') else b''
                self.observed.append(line + payload)
                for chunk in (self.reply,) if isinstance(self.reply, bytes) else self.reply:
                    connection.sendall(chunk)
                    time.sleep(.015)
                extra = stream.readline()
                assert not extra, extra
        except (EOFError, ConnectionError, ssl.SSLEOFError):
            pass
        except Exception as error:
            self.errors.append(error)


def fixture_checks(peer, request):
    def check(path, wire, reply, status, body=b'', headers=None, response=b''):
        peer.reply = reply
        before = len(peer.observed)
        result = request(path, body, headers)
        assert result[0] == status, (path, reply, status, result)
        if status == 200:
            assert result[1] == response, (path, result)
        assert peer.observed[before:] == [wire], peer.observed[before:]

    check('store', b'ms key 3 ME F4294967295 T60\r\n\0\xffx\r\n', (b'H', b'D\r\n'),
          200, b'\0\xffx', {'X-Mode': 'add', 'X-Flags': '4294967295'})
    check('store', b'ms key 0 MR F0 T60\r\n\r\n', b'NS\r\n', 412, headers={'X-Mode': 'replace'})
    check('store', b'ms key 0 MR F0 T60\r\n\r\n', b'HD\r\n', 200, headers={'X-Mode': 'replace'})
    check('store', b'ms key 1 C18446744073709551615 F0 T60\r\nx\r\n', b'EX\r\n',
          409, b'x', {'X-Mode': 'cas', 'X-Cas': '18446744073709551615'})
    check('store', b'ms key 1 MA\r\nx\r\n', b'HD\r\n', 200, b'x', {'X-Mode': 'append'})
    check('store', b'ms key 1 MP\r\nx\r\n', b'HD\r\n', 200, b'x', {'X-Mode': 'prepend'})
    check('arithmetic', b'ma key MI D1 C18446744073709551615 v\r\n', b'VA 1\r\n5\r\n',
          200, headers={'X-Cas': '18446744073709551615'}, response=b'5')
    check('arithmetic', b'ma key MI D1 C7 v\r\n', b'EX\r\n', 409, headers={'X-Cas': '7'})
    check('arithmetic', b'ma key MD D1 N60 J9 v\r\n',
          (b'VA 20\r\n1844', b'6744073709551615\r', b'\n'),
          200, headers={'X-Mode': 'decrement', 'X-Seed': '9'}, response=b'18446744073709551615')
    arith = b'ma key MI D1 v\r\n'
    for response in (b'VA 20\r\n18446744073709551616\r\n', b'VA 1\r\n1\r\nMN\r\n',
                     b'VA 2\r\n1\r\n', b'VA 1 c7\r\n1\r\n', b'HD\r\n'):
        check('arithmetic', arith, response, 502)
    check('arithmetic', arith, b'NF\r\n', 404)
    check('arithmetic', arith, b'SERVER_ERROR unavailable\r\n', 422)
    check('arithmetic', arith, b'', 502)
    check('delete', b'md key\r\n', b'HD\r\n', 200)
    check('delete', b'md key\r\n', b'EX\r\n', 502)
    check('noop', b'mn\r\n', b'MN\r\n', 200)
    check('noop', b'mn\r\n', b'HD\r\n', 502)
    check('debug', b'me key\r\n', b'ME key exp=9 cas=8\r\n', 200, response=b'exp=9 cas=8')
    check('debug', b'me key\r\n', b'ME other cas=8\r\n', 502)
    check('debug', b'me key\r\n', b'ME key \r\n', 502)
    check('debug', b'me key\r\n', b'EN\r\n', 404)

    before = len(peer.observed)
    for path, body, headers in (
        ('store', b'x', {'X-Key': 'two words'}),
        ('store', b'x', {'X-Flags': '4294967296'}),
        ('store', b'x', {'X-Mode': 'cas', 'X-Cas': '18446744073709551616'}),
        ('arithmetic', b'', {'X-Delta': '-1'}),
        ('arithmetic', b'', {'X-Seed': '18446744073709551616'}),
    ):
        assert request(path, body, headers)[0] == 400, (path, headers)
    assert len(peer.observed) == before
    assert not peer.errors, peer.errors


def live_checks(args, port, request):
    assert request('noop') == (200, b'')
    assert request('store', b'\0\xff', {'X-Mode': 'add', 'X-Flags': '4294967295'})[0] == 200
    assert request('store', b'ignored', {'X-Mode': 'add'})[0] == 412
    assert request('store', b'after', {'X-Mode': 'append'})[0] == 200
    assert request('store', b'before', {'X-Mode': 'prepend'})[0] == 200
    with connect(args, port) as connection, connection.makefile('rb') as reply:
        connection.sendall(b'gets key\r\n')
        name, key, flags, size, cas = reply.readline().split()
        assert (name, key, flags) == (b'VALUE', b'key', b'4294967295')
        assert reply.read(int(size) + 7) == b'before\0\xffafter\r\nEND\r\n'
    assert request('store', b'new', {'X-Mode': 'cas', 'X-Cas': cas.decode()})[0] == 200
    assert request('store', b'old', {'X-Mode': 'cas', 'X-Cas': cas.decode()})[0] == 409
    assert request('store', b'base', {'X-Key': 'replace-key'})[0] == 200
    assert request('store', b'changed', {'X-Key': 'replace-key', 'X-Mode': 'replace',
                                         'X-Flags': '7'})[0] == 200
    assert request('store', b'nope', {'X-Key': 'absent-replace', 'X-Mode': 'replace'})[0] == 412
    with connect(args, port) as connection, connection.makefile('rb') as reply:
        connection.sendall(b'gets replace-key\r\n')
        name, key, flags, size, _ = reply.readline().split()
        assert (name, key, flags) == (b'VALUE', b'replace-key', b'7')
        assert reply.read(int(size) + 2) == b'changed\r\n'
        assert reply.readline() == b'END\r\n'
    status, fields = request('debug')
    assert status == 200 and any(field.startswith(b'cas=') for field in fields.split()), (status, fields)
    assert request('delete')[0] == 200
    assert request('delete')[0] == 404
    assert request('debug')[0] == 404
    assert request('arithmetic')[0] == 404
    assert request('arithmetic', headers={'X-Seed': '9'}) == (200, b'9')
    assert request('arithmetic', headers={'X-Delta': '10'}) == (200, b'19')
    assert request('arithmetic', headers={'X-Mode': 'decrement', 'X-Delta': '20'}) == (200, b'0')
    status, fields = request('debug')
    assert status == 200, (status, fields)
    cas = next(field[4:] for field in fields.split() if field.startswith(b'cas='))
    assert request('arithmetic', headers={'X-Delta': '5', 'X-Cas': cas.decode()}) == (200, b'5')
    assert request('arithmetic', headers={'X-Delta': '5', 'X-Cas': cas.decode()})[0] == 409


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', choices=('0', '2'), required=True)
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--testdata', required=True)
    parser.add_argument('--real', action='store_true')
    args = parser.parse_args()

    def open_gateway(port):
        policy = dict(address='127.0.0.1', port=port)
        if args.tls:
            policy.update(tls=True, caFile=str(Path(args.testdata).resolve() / 'localhost_cert.pem'),
                          serverName='localhost')
        return gateway(args, policy, program_factory=program,
                       extra_libraries=('memcache-meta.rut',), entrypoint='memcache-meta.rut')

    if args.real:
        with real_memcached(args) as port, open_gateway(port) as request:
            live_checks(args, port, request)
    else:
        context = None
        if args.tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(Path(args.testdata) / 'localhost_cert.pem'),
                                    str(Path(args.testdata) / 'localhost_key.pem'))
        peer = MetaPeer(context)
        try:
            with open_gateway(peer.port) as request:
                fixture_checks(peer, request)
        finally:
            peer.close()


if __name__ == '__main__':
    main()
