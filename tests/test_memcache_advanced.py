#!/usr/bin/env python3
"""CAS, unsigned counters, append/prepend and bounded multi-key retrieval."""
import argparse
from pathlib import Path
import re
import socket
import socketserver
import ssl
import time

from test_memcache_client import PROGRAM as BASIC_PROGRAM, Peer, gateway, real_memcached


ADVANCED = r'''
func extMode(_ name: str) -> MemcacheRetrievalMode {
    match name {
        "gets" => MemcacheRetrievalMode.cas
        "gat" => MemcacheRetrievalMode.touching
        "gats" => MemcacheRetrievalMode.touchingCas
        _ => MemcacheRetrievalMode.plain
    }
}
func extCasStatus(_ result: MemcacheCasResult) -> i32 {
    match result {
        .stored => 200
        .exists => 409
        .missing => 404
        .notStored => 409
        .serverError(data) => 503
        .requestFailure => 400
        .transportFailure(code) => if code == -2 { 504 } else { 502 }
        .replyFailure => 502
    }
}
func extCasFinish(_ connection: TcpConnection, _ result: MemcacheCasResult) -> bool {
    match result {
        .serverError(data) => !connection.close()
        .transportFailure(code) => !connection.close()
        .replyFailure => !connection.close()
        _ => { let released = connection.release()
            true }
    }
}
func extCounterStatus(_ result: MemcacheCounterResult) -> i32 {
    match result {
        .value(number) => 200
        .missing => 404
        .serverError(data) => 503
        .requestFailure => 400
        .transportFailure(code) => if code == -2 { 504 } else { 502 }
        _ => 502
    }
}
func extCounterBody(_ result: MemcacheCounterResult) -> Bytes {
    match result { .value(number) => number _ => b"" }
}
func extCounterMustClose(_ result: MemcacheCounterResult) -> bool {
    match result {
        .value(number) => false
        .missing => false
        .requestFailure => false
        _ => true
    }
}
func extCounterFinish(_ connection: TcpConnection, _ result: MemcacheCounterResult) -> bool {
    if extCounterMustClose(result) { !connection.close() } else {
        let released = connection.release()
        true
    }
}
func extCounter(_ connection: TcpConnection, _ key: Bytes, _ amount: Bytes, _ decrement: bool) -> MemcacheCounterResult {
    if decrement { memcacheDecrement(connection, key, amount) } else { memcacheIncrement(connection, key, amount) }
}
func extAppend(_ connection: TcpConnection, _ key: Bytes, _ data: Bytes, _ front: bool) -> MemcacheStoreResult {
    if front { memcachePrepend(connection, key, data) } else { memcacheAppend(connection, key, data) }
}
func extManyStatus(_ result: MemcacheManyResult) -> i32 {
    match result {
        .values(reply) => 200
        .serverError(data) => 503
        .requestFailure => 400
        .transportFailure(code) => if code == -2 { 504 } else { 502 }
        _ => 502
    }
}
func extManyFinish(_ connection: TcpConnection, _ result: MemcacheManyResult) -> bool {
    match result {
        .values(reply) => { let released = connection.release()
            true }
        .requestFailure => { let released = connection.release()
            true }
        _ => !connection.close()
    }
}
func extPack(_ key: Bytes, _ flags: Bytes, _ cas: Bytes, _ data: Bytes) -> Bytes {
    guard let first = concatBytes(key, b"|", 8192) else { nil }
    guard let second = concatBytes(first, flags, 8192) else { nil }
    guard let third = concatBytes(second, b"|", 8192) else { nil }
    guard let fourth = concatBytes(third, cas, 8192) else { nil }
    guard let fifth = concatBytes(fourth, b"|", 8192) else { nil }
    concatBytes(fifth, data, 8192)
}
func extManyReplyBody(_ reply: MemcacheManyReply, _ index: i32) -> Bytes {
    guard let item = memcacheManyItem(reply, index) else { nil }
    extPack(item.key, item.flags, item.cas, item.data)
}
func extManyBody(_ result: MemcacheManyResult, _ index: i32) -> Bytes {
    match result {
        .values(reply) => extManyReplyBody(reply, index)
        _ => nil
    }
}
func extManyCount(_ result: MemcacheManyResult) -> i32 {
    match result { .values(reply) => reply.count _ => -1 }
}
func extManyOutput(_ result: MemcacheManyResult, _ index: i32, _ countOnly: bool) -> Bytes {
    if countOnly { Bytes(formatInt(extManyCount(result)).or("invalid")) }
    else { extManyBody(result, index) }
}
func extManyTriple(_ reply: MemcacheManyReply, _ index: i32) -> Bytes {
    guard let first = extManyReplyBody(reply, index) else { nil }
    guard let second = extManyReplyBody(reply, index) else { nil }
    guard let third = extManyReplyBody(reply, index) else { nil }
    guard let a = concatBytes(first, second, 8192) else { nil }
    concatBytes(a, third, 8192)
}
func extManyTripleResult(_ result: MemcacheManyResult, _ index: i32) -> Bytes {
    match result {
        .values(reply) => extManyTriple(reply, index)
        _ => nil
    }
}
func extGetsStatus(_ result: MemcacheGetsResult) -> i32 {
    match result {
        .value(item) => 200
        .missing => 404
        .serverError(data) => 503
        .requestFailure => 400
        .transportFailure(code) => if code == -2 { 504 } else { 502 }
        _ => 502
    }
}
func extGetsBody(_ result: MemcacheGetsResult) -> Bytes {
    match result { .value(item) => extPack(b"", item.flags, item.cas, item.data) _ => b"" }
}
func extGetsFinish(_ connection: TcpConnection, _ result: MemcacheGetsResult) -> bool {
    match result {
        .value(item) => { let released = connection.release()
            true }
        .missing => { let released = connection.release()
            true }
        .requestFailure => { let released = connection.release()
            true }
        _ => !connection.close()
    }
}
route POST "/unsigned" {
    guard memcacheUnsignedValid(req.bodyBytes) else { return 400 }
    return 204
}
route POST "/keys" {
    guard let body = memcacheManyRequest(MemcacheKeys(bytes: req.bodyBytes,
        count: parseInt(req.header("X-Count").or("2")).or(0)),
        extMode(req.header("X-Mode").or("get")), parseInt(req.header("X-TTL").or("0")).or(-1)) else { return 400 }
    return response(200, body: body)
}
route POST "/addkey" {
    guard let keys = memcacheKeysAdd(MemcacheKeys(bytes: Bytes(req.header("X-Keys").or("")),
        count: parseInt(req.header("X-Count").or("0")).or(-1)), req.bodyBytes) else { return 400 }
    guard let body = memcacheManyRequest(keys, MemcacheRetrievalMode.cas, 0) else { return 400 }
    return response(200, body: body)
}
route POST "/cas" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheCas(connection, Bytes(req.header("X-Key").or("key")), req.bodyBytes,
        MemcacheOptions(flags: Bytes(req.header("X-Flags").or("0")), expirySeconds: parseInt(req.header("X-TTL").or("0")).or(-1)),
        Bytes(req.header("X-CAS").or("0")))
    let finished = extCasFinish(connection, result)
    let stale = connection.send(b"ILLEGAL\r\n", 1000)
    guard finished && stale == nil && netError() == -4 else { return 500 }
    let status = extCasStatus(result)
    guard status != 400 else { return 400 }
    guard status != 404 else { return 404 }
    guard status != 409 else { return 409 }
    guard status != 503 else { return 503 }
    guard status != 504 else { return 504 }
    guard status == 200 else { return 502 }
    return 200
}
route POST "/counter" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = extCounter(connection, Bytes(req.header("X-Key").or("key")), req.bodyBytes, req.header("X-Decrement").or("") == "yes")
    let finished = extCounterFinish(connection, result)
    let stale = connection.send(b"ILLEGAL\r\n", 1000)
    guard finished && stale == nil && netError() == -4 else { return 500 }
    let status = extCounterStatus(result)
    guard status != 400 else { return 400 }
    guard status != 404 else { return 404 }
    guard status != 503 else { return 503 }
    guard status != 504 else { return 504 }
    guard status == 200 else { return 502 }
    let body = extCounterBody(result)
    return response(200, body: body)
}
route POST "/append" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = extAppend(connection, Bytes(req.header("X-Key").or("key")), req.bodyBytes, req.header("X-Front").or("") == "yes")
    let finished = finishStore(connection, result)
    let stale = connection.send(b"ILLEGAL\r\n", 1000)
    guard finished && stale == nil && netError() == -4 else { return 500 }
    let status = storeStatus(result)
    guard status != 400 else { return 400 }
    guard status != 409 else { return 409 }
    guard status != 504 else { return 504 }
    guard status == 200 else { return 502 }
    let body = storeBody(result)
    return response(200, body: body)
}
route POST "/many-triple" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheManyExecute(connection,
        MemcacheKeys(bytes: req.bodyBytes, count: parseInt(req.header("X-Count").or("0")).or(0)),
        extMode(req.header("X-Mode").or("get")), 0)
    let finished = extManyFinish(connection, result)
    guard finished else { return 500 }
    guard let body = extManyTripleResult(result, parseInt(req.header("X-Index").or("-1")).or(-1)) else { return 404 }
    return response(200, body: body)
}
route POST "/many" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheManyExecute(connection,
        MemcacheKeys(bytes: req.bodyBytes, count: parseInt(req.header("X-Count").or("2")).or(0)),
        extMode(req.header("X-Mode").or("get")), parseInt(req.header("X-TTL").or("0")).or(-1))
    let finished = extManyFinish(connection, result)
    let stale = connection.send(b"ILLEGAL\r\n", 1000)
    guard finished && stale == nil && netError() == -4 else { return 500 }
    let status = extManyStatus(result)
    guard status != 400 else { return 400 }
    guard status != 503 else { return 503 }
    guard status != 504 else { return 504 }
    guard status == 200 else { return 502 }
    guard let body = extManyOutput(result, parseInt(req.header("X-Index").or("0")).or(-1),
        req.header("X-Count-Only").or("") == "yes") else { return 404 }
    return response(200, body: body)
}
route POST "/gets" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheGets(connection, req.bodyBytes)
    let finished = extGetsFinish(connection, result)
    let stale = connection.send(b"ILLEGAL\r\n", 1000)
    guard finished && stale == nil && netError() == -4 else { return 500 }
    let status = extGetsStatus(result)
    guard status != 400 else { return 400 }
    guard status != 404 else { return 404 }
    guard status != 503 else { return 503 }
    guard status != 504 else { return 504 }
    guard status == 200 else { return 502 }
    guard let body = extGetsBody(result) else { return 502 }
    return response(200, body: body)
}
route POST "/gats" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheGats(connection, req.bodyBytes, parseInt(req.header("X-TTL").or("0")).or(-1))
    let finished = extGetsFinish(connection, result)
    let stale = connection.send(b"ILLEGAL\r\n", 1000)
    guard finished && stale == nil && netError() == -4 else { return 500 }
    let status = extGetsStatus(result)
    guard status != 400 else { return 400 }
    guard status != 404 else { return 404 }
    guard status != 503 else { return 503 }
    guard status != 504 else { return 504 }
    guard status == 200 else { return 502 }
    guard let body = extGetsBody(result) else { return 502 }
    return response(200, body: body)
}
route POST "/gat" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheGat(connection, req.bodyBytes, parseInt(req.header("X-TTL").or("0")).or(-1))
    let finished = finishGet(connection, result)
    let stale = connection.send(b"ILLEGAL\r\n", 1000)
    guard finished && stale == nil && netError() == -4 else { return 500 }
    let status = getStatus(result)
    guard status != 400 else { return 400 }
    guard status != 404 else { return 404 }
    guard status != 504 else { return 504 }
    guard status == 200 else { return 502 }
    let body = getBody(result)
    return response(200, body: body)
}
route POST "/retain" {
    let opening = tcp(env("MEMCACHE_ENDPOINT"), 1000)
    guard let connection = opening else { return 503 }
    let result = memcacheMultiGets(connection, MemcacheKeys(bytes: req.bodyBytes, count: 2))
    let later = memcacheGet(connection, b"key")
    let closed = connection.close()
    guard getStatus(later) == 200 else { return 500 }
    guard let body = extManyBody(result, 0) else { return 500 }
    return response(200, body: body)
}
'''


def program(reads):
    start = BASIC_PROGRAM.index('route POST ')
    base_routes = re.split(r'(?=^route POST )', BASIC_PROGRAM[start:], flags=re.M)
    base = BASIC_PROGRAM[:start] + ''.join(r for r in base_routes if r.startswith(('route POST "/store"', 'route POST "/get"')))
    start = ADVANCED.index('route POST ')
    routes = re.split(r'(?=^route POST )', ADVANCED[start:], flags=re.M)
    read_routes = ('many', 'many-triple', 'gets', 'gats', 'gat', 'retain', 'keys', 'addkey')
    return base + ADVANCED[:start] + ''.join(r for r in routes if r.startswith('route POST "/cas"') or any(r.startswith('route POST "/' + name + '"') for name in read_routes) == reads)


def value(key, data, flags=b'0', cas=None):
    suffix = b' ' + cas if cas is not None else b''
    return b'VALUE ' + key + b' ' + flags + b' %d' % len(data) + suffix + b'\r\n' + data + b'\r\n'


class AdvancedPeer(Peer):
    def __init__(self, context=None):
        self.versions = {}
        self.version = 2**63 + 100
        super().__init__(context)
        self.RequestHandlerClass = AdvancedHandler


class AdvancedHandler(socketserver.StreamRequestHandler):
    def handle(self):
        peer = self.server
        with peer.lock:
            peer.next_id += 1
            identity = peer.next_id
        self.connection.settimeout(10)
        try:
            while not peer.stopping.is_set():
                line = self.rfile.readline(8193)
                if not line:
                    return
                assert line.endswith(b'\r\n'), line
                parts = line[:-2].split(b' ')
                name = parts[0]
                data = None
                if name in (b'set', b'add', b'replace', b'append', b'prepend', b'cas'):
                    assert len(parts) == (6 if name == b'cas' else 5), parts
                    data = self.rfile.read(int(parts[4]))
                    assert len(data) == int(parts[4]) and self.rfile.read(2) == b'\r\n'
                with peer.lock:
                    peer.observed.append((identity, parts, data))
                keys = parts[2:] if name in (b'gat', b'gats') else parts[1:]
                key = keys[0]
                if key.startswith(b'fixture-'):
                    if not self.fixture(parts, data):
                        return
                    continue
                with peer.lock:
                    for candidate in list(peer.items):
                        if peer.items[candidate][2] and peer.items[candidate][2] <= time.monotonic():
                            del peer.items[candidate]
                    item = peer.items.get(key)
                    if name in (b'get', b'gets', b'gat', b'gats'):
                        reply = b''
                        for requested in keys:
                            found = peer.items.get(requested)
                            if found:
                                if name in (b'gat', b'gats'):
                                    ttl = int(parts[1])
                                    peer.items[requested] = (*found[:2], time.monotonic() + ttl if ttl else 0)
                                reply += value(requested, found[0], found[1], str(peer.versions[requested]).encode() if name in (b'gets', b'gats') else None)
                        reply += b'END\r\n'
                    elif name in (b'incr', b'decr'):
                        if item is None:
                            reply = b'NOT_FOUND\r\n'
                        elif not item[0].isdigit():
                            reply = b'CLIENT_ERROR non-numeric\r\n'
                        else:
                            number = max(0, int(item[0]) - int(parts[2])) if name == b'decr' else (int(item[0]) + int(parts[2])) % 2**64
                            reply = str(number).encode() + b'\r\n'
                            peer.items[key] = (str(number).encode(), *item[1:])
                            peer.version += 1
                            peer.versions[key] = peer.version
                    elif name in (b'set', b'add', b'replace', b'append', b'prepend', b'cas'):
                        if name == b'cas' and item is None:
                            reply = b'NOT_FOUND\r\n'
                        elif name == b'cas' and int(parts[5]) != peer.versions[key]:
                            reply = b'EXISTS\r\n'
                        elif (name == b'add' and item) or (name in (b'replace', b'append', b'prepend') and not item):
                            reply = b'NOT_STORED\r\n'
                        else:
                            if name in (b'append', b'prepend'):
                                assert parts[2:4] == [b'0', b'0']
                                peer.items[key] = (item[0] + data if name == b'append' else data + item[0], *item[1:])
                            else:
                                ttl = int(parts[3])
                                peer.items[key] = (data, parts[2], time.monotonic() + ttl if ttl else 0)
                            peer.version += 1
                            peer.versions[key] = peer.version
                            reply = b'STORED\r\n'
                    else:
                        raise AssertionError(parts)
                self.connection.sendall(reply)
        except (OSError, ssl.SSLError):
            pass
        except Exception as error:
            peer.errors.append(error)

    def fixture(self, parts, data):
        name = parts[0]
        keys = parts[2:] if name in (b'gat', b'gats') else parts[1:]
        key = keys[0]
        mode = b'reorder' if key.startswith(b'fixture-eight') else key.removeprefix(b'fixture-')
        if mode == b'timeout':
            self.server.stopping.wait(1.3)
            return True
        if mode == b'eof':
            return False
        cas = b'18446744073709551615' if name in (b'gets', b'gats') else None
        frame = value(key, b'a\x00\xff\r\nEND\r\nz', b'4294967295', cas)
        reply = frame + b'END\r\n'
        if name in (b'incr', b'decr'):
            reply = b'18446744073709551615\r\n'
        elif name == b'cas':
            reply = b'STORED\r\n'
        elif name in (b'append', b'prepend'):
            reply = b'STORED\r\n'
        if mode == b'wrong-key':
            reply = value(b'other', b'bad', cas=cas) + b'END\r\n'
        elif mode == b'duplicate':
            reply = frame + frame + b'END\r\n'
        elif mode == b'extra':
            reply += b'STORED\r\n'
        elif mode == b'missing-end':
            self.connection.sendall(frame)
            return False
        elif mode == b'cas-overflow':
            reply = value(key, b'v', cas=b'18446744073709551616') + b'END\r\n'
        elif mode == b'cas-missing':
            reply = value(key, b'v') + b'END\r\n'
        elif mode == b'cas-extra':
            reply = value(key, b'v', cas=b'1 2') + b'END\r\n'
        elif mode == b'wrong-cas-mode':
            reply = value(key, b'v', cas=None if cas is not None else b'1') + b'END\r\n'
        elif mode == b'flags-overflow':
            reply = value(key, b'v', flags=b'4294967296', cas=cas) + b'END\r\n'
        elif mode == b'bad-terminator':
            reply = frame[:-2] + b'XXEND\r\n'
        elif mode == b'bad-size':
            reply = b'VALUE ' + key + b' 0 2147483647' + (b' 1' if cas else b'') + b'\r\n'
        elif mode in (b'counter-overflow', b'counter-plus', b'counter-negative', b'counter-junk'):
            reply = {b'counter-overflow': b'18446744073709551616', b'counter-plus': b'+1', b'counter-negative': b'-1', b'counter-junk': b'1x'}[mode] + b'\r\n'
        elif mode == b'error':
            reply = b'SERVER_ERROR fixture\r\n'
        elif mode == b'wrong-type':
            reply = b'END\r\n' if name in (b'cas', b'incr', b'decr', b'append', b'prepend') else b'STORED\r\n'
        elif mode == b'partial-error':
            reply = frame + b'SERVER_ERROR fixture\r\n'
        elif mode == b'reorder':
            reply = b''.join(value(k, k + b'\x00\xff', cas=cas) for k in reversed(keys)) + b'END\r\n'
        elif mode in (b'max', b'too-large'):
            size = max(n for n in range(8193) if len(value(key, b'x' * n, cas=cas) + b'END\r\n') <= 8192)
            reply = value(key, b'x' * (size + (mode == b'too-large')), cas=cas) + b'END\r\n'
        if mode == b'fragments':
            for chunk in (reply[:3], reply[3:-5], reply[-5:]):
                self.connection.sendall(chunk)
                time.sleep(.04)
        elif mode == b'read-budget':
            for chunk in (b'V', b'A', b'L', b'U', reply[4:]):
                self.connection.sendall(chunk)
                time.sleep(.08)
        else:
            self.connection.sendall(reply)
        return True


def writes(request, peer):
    maximum = b'18446744073709551615'
    for good in (b'0', b'1', b'9223372036854775808', maximum, b'00000000000000000001'):
        assert request('unsigned', good)[0] == 204
    before = len(peer.observed) if peer else 0
    for bad in (b'', b'-1', b'+1', b'18446744073709551616', b'9'*21, b'1 2', b'1\x00', b'\xff', b'0x10'):
        assert request('unsigned', bad)[0] == 400, bad
        assert request('counter', bad)[0] == 400, bad
        if all(32 <= b < 127 for b in bad):
            assert request('cas', b'v', {'X-CAS': bad.decode()})[0] == 400
    if peer:
        assert len(peer.observed) == before, 'invalid unsigned argument sent bytes'
    assert request('counter', b'1', {'X-Key': 'absent'})[0] == 404
    assert request('store', maximum, {'X-Flags': '4294967295'})[0] == 200
    assert request('counter', b'1') == (200, b'0')
    assert request('counter', maximum) == (200, maximum)
    assert request('counter', maximum, {'X-Decrement': 'yes'}) == (200, b'0')
    assert request('counter', b'1', {'X-Decrement': 'yes'}) == (200, b'0')
    # Memcached may retain padding when a stored decimal shrinks. GET is
    # binary-preserving; the increment/decrement reply above is the number.
    status, stored = request('get')
    assert status == 200 and stored.rstrip(b' ') == b'4294967295:0', (status, stored)
    assert request('store', b'not-a-number')[0] == 200
    assert request('counter', b'1')[0] == 503
    assert request('append', b'tail', {'X-Key': 'absent'})[0] == 409
    assert request('store', b'center', {'X-Flags': '4294967295', 'X-TTL': '2592000'})[0] == 200
    assert request('append', b'\x00\xffEND\r\n')[0] == 200
    assert request('append', b'head\x00', {'X-Front': 'yes'})[0] == 200
    assert request('get') == (200, b'4294967295:head\x00center\x00\xffEND\r\n')
    assert request('store', b'v', {'X-Key':'append-expiry','X-TTL':'2','X-Flags':'42'})[0] == 200
    assert request('append', b'x', {'X-Key':'append-expiry'})[0] == 200
    assert request('append', b'y', {'X-Key':'append-expiry','X-Front':'yes'})[0] == 200
    assert request('get', headers={'X-Key':'append-expiry'}) == (200,b'42:yvx')
    time.sleep(3.1)
    assert request('get', headers={'X-Key':'append-expiry'})[0] == 404
    assert request('cas', b'x', {'X-Key': 'absent', 'X-CAS': maximum.decode()})[0] == 404
    assert request('cas', b'x', {'X-CAS': '0'})[0] == 409
    if peer:
        before = len(peer.observed)
        for route in ('cas', 'counter', 'append'):
            assert request(route, b'1', {'X-Key': 'fixture-error'})[0] == (200 if route == 'append' else 503)
            assert request(route, b'1', {'X-Key': 'fixture-wrong-type'})[0] == 502
        for key in ('fixture-counter-overflow', 'fixture-counter-plus', 'fixture-counter-negative', 'fixture-counter-junk'):
            assert request('counter', b'1', {'X-Key': key})[0] == 502
        for key in ('fixture-timeout', 'fixture-eof'):
            assert request('counter', b'1', {'X-Key': key})[0] == (504 if key.endswith('timeout') else 502)
        sent = peer.observed[before:]
        assert not any(parts[0] == b'ILLEGAL' for _, parts, _ in sent)
        assert all(sum(p == parts for _, p, _ in sent) == 1 for _, parts, _ in sent if parts[1].startswith(b'fixture-'))


def reads(request, peer):
    assert request('keys', b'one two') == (200, b'get one two\r\n')
    for mode in ('gets', 'gat', 'gats'):
        ttl = b' 30' if mode.startswith('gat') else b''
        assert request('keys', b'one two', {'X-Mode': mode, 'X-TTL': '30'}) == (200, mode.encode()+ttl+b' one two\r\n')
    assert request('addkey', b'one') == (200, b'gets one\r\n')
    assert request('addkey', b'two', {'X-Keys': 'one', 'X-Count': '1'}) == (200, b'gets one two\r\n')
    assert request('addkey', b'one', {'X-Keys': 'one', 'X-Count': '1'})[0] == 400
    keys = [bytes([65+i])*250 for i in range(8)]
    packed = b' '.join(keys)
    assert request('keys', packed, {'X-Count': '8'}) == (200, b'get '+packed+b'\r\n')
    for invalid, count in ((b'',1),(b'a a',2),(b' a',1),(b'a ',1),(b'a  b',2),(b'a b',1),(b'a',2),(b'x'*251,1),(packed+b' ninth',9)):
        assert request('keys', invalid, {'X-Count': str(count)})[0] == 400, (invalid,count)
    for octet in (*range(32),127):
        assert request('keys', b'one '+bytes([octet])+b'two')[0] == 400, octet
    before = len(peer.observed) if peer else 0
    for body, count in ((b'a a',2),(b'a b',1),(b'a\x00 b',2),(b'',0),(b'a',9)):
        assert request('many', body, {'X-Count':str(count)})[0] == 400
    if peer:
        assert len(peer.observed) == before, 'invalid key list sent bytes'
    for key in keys:
        assert request('store', b'v', {'X-Key':key.decode()})[0] == 200
    assert request('many', packed, {'X-Count':'8','X-Count-Only':'yes'}) == (200,b'8')
    long_fixture = b'fixture-eight' + b'X' * (250 - len(b'fixture-eight'))
    long_reply_keys = b' '.join([long_fixture] + keys[:7])
    for index, key in enumerate(list(reversed([long_fixture] + keys[:7]))):
        status, body = request('many-triple', long_reply_keys, {'X-Count':'8', 'X-Index':str(index)})
        assert status == 200 and body.count(b'|0|') == 3 and key in body, (index, status, body[:100])
    for key, data, flags in ((b'one',b'a\x00\xff\r\nEND\r\nz','4294967295'),(b'two',b'','0'),(b'key',b'present','0')):
        assert request('store', data, {'X-Key': key.decode(), 'X-Flags':flags})[0] == 200
    assert request('gets', b'absent')[0] == 404
    status, body = request('gets', b'one')
    assert status == 200 and body.startswith(b'|4294967295|') and body.endswith(b'|a\x00\xff\r\nEND\r\nz')
    cas = body.split(b'|',3)[2]
    # Mutation occurs on another physical lease. The stale version must fail,
    # then a fresh opaque unsigned version must be accepted.
    assert request('store', b'new', {'X-Key':'one'})[0] == 200
    assert request('cas', b'bad', {'X-Key':'one','X-CAS':cas.decode()})[0] == 409
    fresh = request('gets', b'one')[1].split(b'|',3)[2]
    assert request('cas', b'new', {'X-Key':'one','X-CAS':fresh.decode()})[0] == 200
    assert request('cas', b'bad', {'X-Key':'one','X-CAS':fresh.decode()})[0] == 409
    assert request('many', b'one absent', {'X-Count-Only':'yes'}) == (200,b'1')
    assert request('many', b'absent other', {'X-Count-Only':'yes'}) == (200,b'0')
    assert request('many', b'one two', {'X-Index':'1'}) == (200,b'two|0||')
    assert request('many', b'one two', {'X-Index':'-1'})[0] == 404
    assert request('many', b'one two', {'X-Index':'2'})[0] == 404
    status, kept = request('retain', b'one two')
    assert status == 200 and kept.startswith(b'one|0|') and kept.endswith(b'|new')
    assert request('gat', b'one', {'X-TTL':'30'}) == (200,b'new')
    assert request('gats', b'two', {'X-TTL':'30'})[0] == 200
    for mode in ('gat','gats'):
        for ttl in ('-1','2592001'):
            assert request(mode,b'one',{'X-TTL':ttl})[0] == 400
    for mode in ('get','gets','gat','gats'):
        assert request('many', b'one two', {'X-Mode':mode,'X-TTL':'30','X-Count-Only':'yes'}) == (200,b'2')
    assert request('gat', b'one', {'X-TTL':'2'})[0] == 200
    assert request('gats', b'two', {'X-TTL':'2'})[0] == 200
    time.sleep(3.1)
    assert request('gets', b'one')[0] == 404
    assert request('gets', b'two')[0] == 404
    if peer:
        for name in ('fragments','max'):
            status, body=request('gets', ('fixture-'+name).encode())
            assert status==200,(name,status,body[:100])
        for name in ('wrong-key','duplicate','extra','missing-end','cas-overflow','cas-missing','cas-extra','wrong-cas-mode','flags-overflow','bad-terminator','bad-size','partial-error','too-large','read-budget','eof','timeout','wrong-type','error'):
            key=('fixture-'+name).encode()
            assert request('gets',key)[0] == (504 if name=='timeout' else 503 if name=='error' else 502),name
        assert request('many',b'fixture-reorder second') == (200,b'second|0||second\x00\xff')
        assert not any(parts[0]==b'ILLEGAL' for _,parts,_ in peer.observed)
    return cas


def example_checks(request):
    assert request('gets', b'absent')[0] == 404
    status, body = request('gets', b'example-key')
    assert status == 200 and body.endswith(b'\r\nold\x00\xff')
    version = body.split(b'\r\n', 1)[0].decode()
    assert request('cas', b'new\x00\xff', {'X-CAS':version})[0] == 204
    assert request('cas', b'bad', {'X-CAS':version})[0] == 409
    assert request('cas', b'bad', {'X-Key':'absent','X-CAS':version})[0] == 404
    assert request('cas', b'bad', {'X-CAS':'18446744073709551616'})[0] == 400
    assert request('gets', b'example-key')[1].endswith(b'\r\nnew\x00\xff')
    assert request('gets', b'invalid key')[0] == 400
    assert request('gets', b'fixture-wrong-key')[0] == 502
    assert request('gets', b'fixture-error')[0] == 503


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--server',required=True)
    parser.add_argument('--library',required=True)
    parser.add_argument('--backend',choices=('epoll','io_uring'),required=True)
    parser.add_argument('--opt',choices=('0','2'),required=True)
    parser.add_argument('--tls',action='store_true')
    parser.add_argument('--testdata',required=True)
    parser.add_argument('--real-memcached',action='store_true')
    parser.add_argument('--example')
    args=parser.parse_args()
    def policy(port):
        result=dict(address='127.0.0.1',port=port,poolIdleMs=5000)
        if args.tls:
            result.update(tls=True,caFile=str(Path(args.testdata).resolve()/'localhost_cert.pem'),serverName='localhost')
        return result
    def run(port,peer):
        if args.example:
            context = ssl.create_default_context(cafile=str(Path(args.testdata)/'localhost_cert.pem')) if args.tls else None
            with socket.create_connection(('127.0.0.1',port),timeout=2) as raw:
                connection = context.wrap_socket(raw,server_hostname='localhost') if context else raw
                with connection, connection.makefile('rb') as stream:
                    connection.sendall(b'set example-key 0 0 5\r\nold\x00\xff\r\n')
                    assert stream.readline() == b'STORED\r\n'
            with gateway(args,policy(port)) as request:
                example_checks(request)
            return
        for reading in (False,True):
            with gateway(args,policy(port),lambda:program(reading)) as request:
                if reading: reads(request,peer)
                else: writes(request,peer)
    if args.real_memcached:
        with real_memcached(args) as port: run(port,None)
    else:
        context=None
        if args.tls:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(Path(args.testdata)/'localhost_cert.pem'),str(Path(args.testdata)/'localhost_key.pem'))
        peer=AdvancedPeer(context)
        try: run(peer.server_address[1],peer)
        finally: peer.close()
    print(f'Memcached advanced passed ({args.backend}, O{args.opt}, tls={args.tls}, real={args.real_memcached})')


if __name__=='__main__': main()
