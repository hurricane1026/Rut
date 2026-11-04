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


GENERAL_JSON_DECLARATIONS = r"""
func jsonPath(_ client: bool) -> str { if client { "/name" } else { "/reply" } }
struct JsonPayload { label: str count: i32 }
"""
GENERAL_JSON_HANDLER = r"""
return websocket(ws) { msg in
    let path = jsonPath(msg.fromClient)
    guard let root = json.parse(msg.text) else { msg.close(1007) }
    guard let selected = json.get(root, path) else { msg.close(1008) }
    guard let text = json.string(selected) else { msg.close(1003) }
    guard let metadata = json.value({ side: msg.fromClient, length: msg.len }) else { msg.close(1011) }
    guard let edited = json.member(root, "meta", metadata) else { msg.close(1008) }
    guard let output = json.stringify(edited) else { msg.close(1011) }
    if msg.isText { msg.forward(text) } else { msg.forward(output) }
}
"""


def general_json_exchange(client, peer):
    import json

    first_payload = b'{"name":"a\\u0000b"}'
    first = bytearray(masked_frame(2, first_payload[:7]))
    first[0] &= 0x7f
    client.sendall(first + masked_frame(9, b"p") + masked_frame(0, first_payload[7:]) +
                   masked_frame(1, b'{"name":"second"}'))
    if recv_client_frame(peer) != (9, b"p", True):
        raise AssertionError("general JSON handler consumed a control frame")
    opcode, payload, masked = recv_client_frame(peer)
    if opcode != 1 or not masked or json.loads(payload) != {
            "name": "a\0b", "meta": {"side": True, "length": len(first_payload)}}:
        raise AssertionError(f"dynamic JSON edit output changed: {payload!r}")
    if recv_client_frame(peer) != (1, b"second", True):
        raise AssertionError("dynamic JSON path selected the wrong client field")
    reply = b'{"reply":"back"}'
    peer.sendall(bytes((0x81, len(reply))) + reply)
    if recv_client_frame(client) != (1, b"back", False):
        raise AssertionError("dynamic JSON path selected the wrong server field")
    client.sendall(masked_frame(2, b"{"))
    if recv_client_frame(client) != (8, b"\x03\xef", False) or \
            recv_client_frame(peer) != (8, b"\x03\xef", True):
        raise AssertionError("malformed JSON did not run its explicit 1007 close")


GENERAL_REGEX_HANDLER = r"""
guard req.path.matches(re"/.*") else { return 403 }
return websocket(ws) { msg in
    let path = jsonPath(msg.fromClient)
    guard let root = json.parse(msg.text) else { msg.close(1007) }
    guard let selected = json.get(root, path) else { msg.drop() }
    guard let text = json.string(selected) else { msg.drop() }
    let allowed = text.matches(re"a.*")
    guard allowed else { msg.drop() }
    msg.forward(text)
}
"""


def general_regex_exchange(client, peer):
    first = b'{"name":"a\\u0000b"}'
    fragment = bytearray(masked_frame(2, first[:7]))
    fragment[0] &= 0x7f
    client.sendall(fragment + masked_frame(9, b"p") + masked_frame(0, first[7:]) +
                   masked_frame(1, b'{"name":"bad"}') + masked_frame(1, b'{"name":"answer"}'))
    for expected in ((9, b"p", True), (1, b"a\0b", True), (1, b"answer", True)):
        actual = recv_client_frame(peer)
        if actual != expected:
            raise AssertionError(f"general regex output: {actual=!r}, {expected=!r}")
    bad, good = b'{"reply":"bad"}', b'{"reply":"answer"}'
    peer.sendall(bytes((0x81, len(bad))) + bad + bytes((0x82, len(good))) + good)
    if recv_client_frame(client) != (1, b"answer", False):
        raise AssertionError("general regex selected the wrong upstream JSON text")
    client.sendall(masked_frame(1, b"{"))
    if recv_client_frame(client) != (8, b"\x03\xef", False) or \
            recv_client_frame(peer) != (8, b"\x03\xef", True):
        raise AssertionError("invalid JSON preceding general regex did not close")


TYPED_JSON_HANDLER = r"""
return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.close(1007) }
    guard let value = json.decode(JsonPayload, root) else { msg.close(1003) }
    guard value.count >= 0 else { msg.close(1008) }
    guard let encoded = json.value(value) else { msg.close(1011) }
    guard let output = json.stringify(encoded) else { msg.close(1011) }
    msg.forward(output)
}
"""


def typed_json_exchange(client, peer):
    import json

    payloads = (b'{"label":"a\\u0000b","count":3}', b'{"label":"second","count":0}')
    client.sendall(b"".join(masked_frame(2, payload) for payload in payloads))
    for expected in ({"label": "a\0b", "count": 3}, {"label": "second", "count": 0}):
        opcode, payload, masked = recv_client_frame(peer)
        if opcode != 1 or not masked or json.loads(payload) != expected:
            raise AssertionError(f"typed JSON round trip changed: {payload!r}")
    bad = b'{"label":true,"count":0}'
    peer.sendall(bytes((0x82, len(bad))) + bad)
    if recv_client_frame(client) != (8, b"\x03\xeb", False) or \
            recv_client_frame(peer) != (8, b"\x03\xeb", True):
        raise AssertionError("typed JSON failure did not run its explicit 1003 close")


JSON_LIFETIME_HANDLER = r"""
return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.close(1007) }
    guard let first = json.string(root) else { msg.close(1003) }
    guard let other = json.parse("\"other\"") else { msg.close(1011) }
    guard let second = json.string(other) else { msg.close(1011) }
    guard first != second else { msg.drop() }
    msg.forward(first)
}
"""


def json_lifetime_exchange(client, peer):
    messages = ((b'"a\\u0000b"', b"a\0b"), (b'"next"', b"next"))
    client.sendall(b"".join(masked_frame(2, encoded) for encoded, _ in messages))
    for _, expected in messages:
        if recv_client_frame(peer) != (1, expected, True):
            raise AssertionError("another JSON operation overwrote an earlier decoded value")
    peer.sendall(b'\x82\x07"reply"')
    if recv_client_frame(client) != (1, b"reply", False):
        raise AssertionError("server JSON scratch survived with stale data")
    client.sendall(masked_frame(8, b"\x03\xe8"))
    if recv_client_frame(peer) != (8, b"\x03\xe8", True):
        raise AssertionError("general JSON callback changed a close control")


HASH_OUTPUT_HANDLER = r"""
return websocket(ws) { msg in
    if msg.fromClient {
        guard let digest = sha256(msg.text) else { msg.close() }
        msg.forward(digest)
    } else {
        if let digest = hmacSha256("key", msg.text) { msg.forward(digest) }
        else { msg.close() }
    }
}
"""


def hash_output_exchange(client, peer):
    import hashlib
    import hmac

    messages = (b"a\0b", b"\xff", b"")
    client.sendall(b"".join(masked_frame(2, payload) for payload in messages))
    for payload in messages:
        expected = (1, hashlib.sha256(payload).hexdigest().encode(), True)
        actual = recv_client_frame(peer)
        if actual != expected:
            raise AssertionError(f"message hash: {actual=!r}, {expected=!r}")
    peer.sendall(b"\x82\x03a\0b" + b"\x89\x01p" + b"\x82\x00")
    for expected in (
            (1, hmac.new(b"key", b"a\0b", hashlib.sha256).hexdigest().encode(), False),
            (9, b"p", False),
            (1, hmac.new(b"key", b"", hashlib.sha256).hexdigest().encode(), False)):
        actual = recv_client_frame(client)
        if actual != expected:
            raise AssertionError(f"message HMAC: {actual=!r}, {expected=!r}")
    client.sendall(masked_frame(8, b"\x03\xe8"))
    if recv_client_frame(peer) != (8, b"\x03\xe8", True):
        raise AssertionError("hash callback altered control close")


DYNAMIC_OUTPUT_DECLARATIONS = r"""
func outputBytes(_ m: WebSocketMessage) -> Bytes {
    if m.len == 3 { m.payload } else { b"\x00\xff" }
}
func outputText(_ m: WebSocketMessage) -> str {
    if m.isBinary { m.text } else { "answer" }
}
"""
DYNAMIC_OUTPUT_HANDLER = r"""
return websocket(ws, maxMessageSize: 128b) { msg in
    let token = uuid()
    guard let value = token else { msg.close() }
    if msg.fromClient { msg.forward(outputBytes(msg)) }
    else {
        if msg.len == 3 { msg.close(1000 + msg.len, msg.text) }
        else { msg.forward(outputText(msg)) }
    }
}
"""


def dynamic_output_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"dynamic output: {actual=!r}, {expected=!r}")

    # Message outputs share callback scratch but must own separate send bytes.
    client.sendall(masked_frame(1, b"one") + masked_frame(2, b"four") + masked_frame(1, b"two"))
    for payload in (b"one", b"\0\xff", b"two"):
        expect(peer, (2, payload, True))
    fragment = bytearray(masked_frame(2, b"\xff"))
    fragment[0] &= 0x7f
    client.sendall(fragment + masked_frame(9, b"PING") + masked_frame(0, b"\0x"))
    expect(peer, (9, b"PING", True))
    expect(peer, (2, b"\xff\0x", True))
    peer.sendall(b"\x81\x04text" + b"\x82\x04a\0bc")
    expect(client, (1, b"answer", False))
    expect(client, (1, b"a\0bc", False))
    peer.sendall(b"\x82\x03bye")
    expect(client, (8, b"\x03\xebbye", False))
    expect(peer, (8, b"\x03\xebbye", True))


DYNAMIC_BOUND_HANDLER = r"""
return websocket(ws, maxMessageSize: 8b) { msg in
    let token = uuid()
    guard let value = token else { msg.close() }
    msg.forward(value)
}
"""


def dynamic_bound_exchange(client, peer):
    client.sendall(masked_frame(1, b"x"))
    if recv_client_frame(client) != (8, b"\x03\xf1", False):
        raise AssertionError("oversized dynamic output did not close with 1009")
    if recv_client_frame(peer) != (8, b"\x03\xf1", True):
        raise AssertionError("oversized dynamic output did not close upstream")


DYNAMIC_UTF8_HANDLER = r"""
return websocket(ws) { msg in
    let token = uuid()
    guard let value = token else { msg.close() }
    msg.forward(msg.text)
}
"""


def dynamic_utf8_exchange(client, peer):
    client.sendall(masked_frame(2, b"\xff"))
    if recv_client_frame(client) != (8, b"\x03\xf3", False):
        raise AssertionError("invalid dynamic Text output did not close with 1011")
    if recv_client_frame(peer) != (8, b"\x03\xf3", True):
        raise AssertionError("invalid dynamic Text output did not close upstream")


STRING_HELPER_DECLARATIONS = r"""
func decorated(_ text: str) -> str {
    let value = text + "!"
    value + value
}
func decodedText(_ text: str) -> str {
    guard let root = json.parse(text) else { nil }
    json.string(root)
}
"""
STRING_HELPER_HANDLER = r"""
return websocket(ws, maxMessageSize: 32b) { msg in
    if !msg.fromClient { msg.forward("skip") }
    guard let text = decodedText(msg.text) else { msg.close(1007) }
    guard text.hasPrefix("a") && text.hasSuffix("z") && text.contains("\0") else { msg.drop() }
    msg.forward(decorated(text))
}
"""


def string_helper_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"String helper: {actual=!r}, {expected=!r}")

    client.sendall(masked_frame(2, b'"a\\u0000z"') +
                   masked_frame(1, b'"drop"') + masked_frame(2, b'"ab\\u0000z"'))
    expect(peer, (1, b"a\0z!a\0z!", True))
    expect(peer, (1, b"ab\0z!ab\0z!", True))
    fragment = bytearray(masked_frame(2, b'"a'))
    fragment[0] &= 0x7f
    client.sendall(fragment + masked_frame(9, b"PING") + masked_frame(0, b'\\u0000z"'))
    expect(peer, (9, b"PING", True))
    expect(peer, (1, b"a\0z!a\0z!", True))
    # Early direction return must skip JSON parsing of invalid Binary data.
    peer.sendall(b"\x82\x01\xff\x81\x00")
    expect(client, (1, b"skip", False))
    expect(client, (1, b"skip", False))
    # Input fits; the repeated dynamic result exceeds the configured output bound.
    client.sendall(masked_frame(2, b'"a' + b'x' * 15 + b'\\u0000z"'))
    expect(client, (8, b"\x03\xf1", False))
    expect(peer, (8, b"\x03\xf1", True))


NOMINAL_MATCH_DECLARATIONS = r"""
func kindName(_ kind: WebSocketMessageKind) -> str {
    match kind {
        .text => "T"
        .binary => "B"
    }
}
func directionName(_ direction: WebSocketDirection) -> str {
    match direction {
        .clientToUpstream => "client"
        .upstreamToClient => "server"
    }
}
func classified(_ text: str) -> WebSocketMessageKind {
    let unused = sha256(text)
    if text == "t" { WebSocketMessageKind.text } else { WebSocketMessageKind.binary }
}
"""
NOMINAL_MATCH_HANDLER = r"""
return websocket(ws) { msg in
    match classified(msg.text) {
        .text => msg.forward(directionName(msg.direction) + kindName(msg.kind) + "T")
        .binary => msg.forward(directionName(msg.direction) + kindName(msg.kind) + "B")
    }
}
"""


def nominal_match_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"nominal match: {actual=!r}, {expected=!r}")

    client.sendall(masked_frame(1, b"t") + masked_frame(2, b"\xff"))
    expect(peer, (1, b"clientTT", True))
    expect(peer, (1, b"clientBB", True))
    fragment = bytearray(masked_frame(2, b""))
    fragment[0] &= 0x7f
    client.sendall(fragment + masked_frame(9, b"PING") + masked_frame(0, b"t"))
    expect(peer, (9, b"PING", True))
    expect(peer, (1, b"clientBT", True))
    peer.sendall(b"\x81\x01t\x82\x01t\x81\x00")
    expect(client, (1, b"serverTT", False))
    expect(client, (1, b"serverBT", False))
    expect(client, (1, b"serverTB", False))
    client.sendall(masked_frame(8, b"\x03\xe8"))
    expect(peer, (8, b"\x03\xe8", True))


CONNECTION_DECLARATIONS = r"""
func clientPeer(_ connection: WebSocketConnection) -> IP => connection.remoteAddr
func connectionLabel(_ connection: WebSocketConnection) -> str {
    if connection.isTls { "tls:" + connection.subprotocol }
    else { "plain:" + connection.subprotocol }
}
"""
CONNECTION_HANDLER = r"""
return websocket(ws) { msg in
    let connection = msg.connection
    guard connection.remotePort > 0 else { msg.close(1011) }
    guard clientPeer(connection) == clientPeer(msg.connection) else { msg.close(1011) }
    msg.forward(connectionLabel(connection))
}
"""


def connection_exchange(client, peer, expected=b"plain:"):
    for value in (b"one", b"two"):
        client.sendall(masked_frame(1, value))
        if recv_client_frame(peer) != (1, expected, True):
            raise AssertionError("message connection metadata changed after upgrade")
        peer.sendall(bytes((0x81, len(value))) + value)
        if recv_client_frame(client) != (1, expected, False):
            raise AssertionError("message direction changed downstream connection metadata")


ERROR_VALUE_DECLARATIONS = r"""
func resultValue(_ text: str) -> str {
    let unused = sha256(text)
    if text == "fail" { error(7) } else { if text == "nil" { nil } else { text } }
}
"""
ERROR_VALUE_HANDLER = r"""
return websocket(ws) { msg in
    let result = resultValue(msg.text)
    if msg.fromClient {
        guard let plain = result else { msg.forward("absent") }
        msg.forward(plain + "!")
    } else { msg.forward(result.or("upstream fallback")) }
}
"""


def error_value_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"error value: {actual=!r}, {expected=!r}")

    client.sendall(b"".join(masked_frame(2, data) for data in (b"", b"fail", b"nil", b"ok")))
    for expected in (b"!", b"absent", b"absent", b"ok!"):
        expect(peer, (1, expected, True))
    fragment = bytearray(masked_frame(2, b"f"))
    fragment[0] &= 0x7f
    client.sendall(fragment + masked_frame(9, b"PING") + masked_frame(0, b"ail"))
    expect(peer, (9, b"PING", True))
    expect(peer, (1, b"absent", True))
    peer.sendall(b"\x81\x04fail\x81\x03nil\x81\x00\x81\x05again")
    for expected in (b"upstream fallback", b"upstream fallback", b"", b"again"):
        expect(client, (1, expected, False))
    client.sendall(masked_frame(2, b"\xff"))
    expect(client, (8, b"\x03\xf3", False))
    expect(peer, (8, b"\x03\xf3", True))


ERROR_FIELDS_DECLARATIONS = r"""
func inspectedFields(_ input: str) -> str {
    if input == "bad" { error(7, "bad input") }
    else { if input == "nil" { nil } else { input } }
}
"""
ERROR_FIELDS_HANDLER = r"""
return websocket(ws) { msg in
    let result = inspectedFields(msg.text)
    let code = result.code
    let reason = result.msg
    if code == 7 {
        guard reason == "bad input" else { msg.close(1011) }
        msg.forward(reason)
    } else {
        guard let plain = result else { msg.forward("absent") }
        msg.forward(plain)
    }
}
"""


def error_fields_exchange(client, peer):
    for opcode, value, expected in ((2, b"bad", b"bad input"),
                                    (1, b"ok", b"ok"),
                                    (2, b"nil", b"absent"),
                                    (1, b"", b"")):
        client.sendall(masked_frame(opcode, value))
        if recv_client_frame(peer) != (1, expected, True):
            raise AssertionError("client error fields lost their carrier")
        peer.sendall(bytes((0x80 | opcode, len(value))) + value)
        if recv_client_frame(client) != (1, expected, False):
            raise AssertionError("upstream error fields lost their carrier")


ERROR_MATCH_DECLARATIONS = r"""
variant MessageError { bad, empty }
func inspected(_ input: str) -> str {
    let unused = sha256(input)
    if input == "bad" { error(MessageError.bad) }
    else { if input == "" { error(MessageError.empty) } else { input } }
}
"""
ERROR_MATCH_IMPLICIT_DECLARATIONS = ERROR_MATCH_DECLARATIONS.replace(
    "variant MessageError { bad, empty }", "").replace("MessageError.", ".")
ERROR_MATCH_HANDLER = r"""
return websocket(ws) { msg in
    let result = inspected(msg.text)
    guard match result else {
        .bad => msg.forward("bad input")
        .empty => msg.close(1008, "empty")
        _ => msg.close(1011)
    }
    guard let plain = result else { msg.close(1011) }
    msg.forward(plain + "!")
}
"""


def error_match_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"error match: {actual=!r}, {expected=!r}")

    client.sendall(b"".join(masked_frame(2, data) for data in (b"ok", b"bad", b"again")))
    for expected in (b"ok!", b"bad input", b"again!"):
        expect(peer, (1, expected, True))
    peer.sendall(b"\x81\x03bad\x81\x00")
    expect(client, (1, b"bad input", False))
    expect(client, (8, b"\x03\xf0empty", False))
    expect(peer, (8, b"\x03\xf0empty", True))


EAGER_BINDING_DECLARATIONS = r"""
func same<T: Eq>(_ a: T, _ b: T) -> bool => a == b
"""
EAGER_BINDING_HANDLER = r"""
return websocket(ws) { msg in
    let token = uuid()
    guard let first = token else { msg.close() }
    guard let second = token else { msg.close() }
    guard same(first, second) else { msg.drop() }
    msg.forward()
}
"""


def eager_binding_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"eager message binding: {actual=!r}, {expected=!r}")

    first = bytearray(masked_frame(2, b"\xff"))
    first[0] &= 0x7F
    client.sendall(first + masked_frame(9, b"PING") + masked_frame(0, b"\0"))
    expect(peer, (9, b"PING", True))
    expect(peer, (2, b"\xff\0", True))
    client.sendall(masked_frame(1, b"one") + masked_frame(2, b"two"))
    expect(peer, (1, b"one", True))
    expect(peer, (2, b"two", True))
    peer.sendall(b"\x81\x05reply")
    expect(client, (1, b"reply", False))
    client.sendall(masked_frame(8, b"\x03\xe8"))
    expect(peer, (8, b"\x03\xe8", True))


GENERAL_DECLARATIONS = r"""
func allowed(_ size: i32, _ client: bool) -> bool =>
    !client || bitwise.and(size, 3) == 2
"""
GENERAL_HANDLER = r"""
return websocket(ws) { msg in
    let size = msg.payload.count + 1
    guard size >= 1 else { msg.close() }
    guard size <= 12 else { msg.close() }
    guard allowed(size, msg.fromClient) else { msg.drop() }
    if msg.isText && msg.len == 5 { msg.drop() } else { msg.forward() }
}
"""


def general_expression_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"general message expression: {actual=!r}, {expected=!r}")

    first = bytearray(masked_frame(2, b"\xff"))
    first[0] &= 0x7F
    client.sendall(first + masked_frame(9, b"PING") + masked_frame(0, b""))
    expect(peer, (9, b"PING", True))
    expect(peer, (2, b"\xff", True))
    client.sendall(masked_frame(1, b"xx") + masked_frame(1, b"xxxxx") +
                   masked_frame(2, b"\0\xffabc") + masked_frame(9, b"END"))
    expect(peer, (2, b"\0\xffabc", True))
    expect(peer, (9, b"END", True))
    peer.sendall(b"\x82\x02\0\xff\x81\x05xxxxx\x8a\x03END")
    expect(client, (2, b"\0\xff", False))
    expect(client, (10, b"END", False))
    client.sendall(masked_frame(1, b"xxxxxxxxxxxx"))
    expect(peer, (8, b"\x03\xe8", True))
    expect(client, (8, b"\x03\xe8", False))


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



OPTIONAL_VALUE_DECLARATIONS = r"""
func safeName(_ msg: WebSocketMessage) -> str {
    guard let root = json.parse(msg.text) else { nil }
    json.string(root).or("fallback")
}
func bytesIfClient(_ msg: WebSocketMessage) -> Bytes {
    if msg.fromClient { b"\x00\xff" }
    else { if msg.isText { b"" } else { nil } }
}
"""

OPTIONAL_DEFAULT_HANDLER = r"""
return websocket(ws) { msg in
    guard let name = safeName(msg) else { msg.drop() }
    guard !name.isEmpty else { msg.forward("empty") }
    msg.forward("[" + name + "]")
}
"""

OPTIONAL_BYTES_HANDLER = r"""
return websocket(ws) { msg in
    guard let bytes = bytesIfClient(msg) else { msg.drop() }
    msg.forward(bytes)
}
"""


def optional_default_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"optional default: {actual=!r}, {expected=!r}")

    payload = b'"a\\u0000b"'
    first = bytearray(masked_frame(1, payload[:4]))
    first[0] &= 0x7F
    client.sendall(first + masked_frame(9, b"PING") + masked_frame(0, payload[4:]))
    expect(peer, (9, b"PING", True))
    expect(peer, (1, b"[a\0b]", True))
    client.sendall(masked_frame(1, b'""') + masked_frame(2, b"null") +
                   masked_frame(1, b"broken") + masked_frame(1, b"false"))
    expect(peer, (1, b"empty", True))
    expect(peer, (1, b"[fallback]", True))
    expect(peer, (1, b"[fallback]", True))
    peer.sendall(b'\x82\x02""\x81\x040.00\x81\x06broken\x81\x04"ok"')
    expect(client, (1, b"empty", False))
    expect(client, (1, b"[fallback]", False))
    expect(client, (1, b"[ok]", False))
    client.sendall(masked_frame(8, b"\x03\xe8"))
    expect(peer, (8, b"\x03\xe8", True))


def optional_bytes_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"optional Bytes: {actual=!r}, {expected=!r}")

    first = bytearray(masked_frame(2, b"\xff"))
    first[0] &= 0x7F
    client.sendall(first + masked_frame(9, b"PING") + masked_frame(0, b"\0"))
    expect(peer, (9, b"PING", True))
    expect(peer, (2, b"\0\xff", True))
    client.sendall(masked_frame(1, b"") + masked_frame(1, b"ok"))
    expect(peer, (2, b"\0\xff", True))
    expect(peer, (2, b"\0\xff", True))
    # Absent server Binary is dropped; present empty Bytes emits an empty Binary.
    peer.sendall(b"\x82\x01\xff\x81\x00\x81\x02ok")
    expect(client, (2, b"", False))
    expect(client, (2, b"", False))
    client.sendall(masked_frame(8, b"\x03\xe8"))
    expect(peer, (8, b"\x03\xe8", True))



BORROWED_BINARY_DECLARATIONS = r"""
func identity<T>(_ value: T) -> T => value
func payload(_ msg: WebSocketMessage) -> Bytes => msg.payload
func selectedBytes(_ msg: WebSocketMessage) -> Bytes {
    if msg.text == "DROP" { nil } else { payload(msg) }
}
"""
BORROWED_BINARY_HANDLER = r"""
return websocket(ws) { msg in
    guard msg.text != "CLOSE" else { msg.close(1000) }
    guard msg.text != "PASS" else { msg.forward() }
    guard let bytes = selectedBytes(msg) else { msg.drop() }
    msg.forward(identity(bytes))
}
"""


def borrowed_binary_exchange(client, peer):
    def expect(sock, expected):
        first, second = recv_exact(sock, 2)
        size = second & 0x7f
        if size == 126:
            size = int.from_bytes(recv_exact(sock, 2), "big")
        elif size == 127:
            size = int.from_bytes(recv_exact(sock, 8), "big")
        mask = recv_exact(sock, 4) if second & 0x80 else None
        data = recv_exact(sock, size)
        if mask:
            data = bytes(v ^ mask[i & 3] for i, v in enumerate(data))
        actual = (first & 0x0f, data, mask is not None)
        if not first & 0x80 or actual != expected:
            raise AssertionError(f"borrowed Binary: {actual=!r}, {expected=!r}")

    def frame(opcode, data, masked, fin=True):
        size = len(data)
        length = bytes((size,)) if size < 126 else b"\x7e" + size.to_bytes(2, "big")
        mask = b"\x12\x34\x56\x78" if masked else b""
        if masked:
            length = bytes((length[0] | 0x80,)) + length[1:]
            data = bytes(v ^ mask[i & 3] for i, v in enumerate(data))
        return bytes(((0x80 if fin else 0) | opcode,)) + length + mask + data

    payload = b"A\0\xc3\xa9"
    client.sendall(frame(1, payload[:2], True, False) + masked_frame(9, b"PING") +
                   frame(0, payload[2:], True))
    expect(peer, (9, b"PING", True))
    expect(peer, (2, payload, True))
    client.sendall(masked_frame(1, b"") + masked_frame(2, b"\xff\0") +
                   masked_frame(1, b"DROP") + masked_frame(1, b"PASS"))
    expect(peer, (2, b"", True))
    expect(peer, (2, b"\xff\0", True))
    expect(peer, (1, b"PASS", True))
    peer.sendall(frame(2, b"\xff", False, False) + frame(10, b"p", False) +
                 frame(0, b"\0", False))
    expect(client, (10, b"p", False))
    expect(client, (2, b"\xff\0", False))
    peer.sendall(frame(1, b"\xc3\xa9", False) + frame(1, b"DROP", False) +
                 frame(2, b"PASS", False))
    expect(client, (2, b"\xc3\xa9", False))
    expect(client, (2, b"PASS", False))
    # Max-size message crosses a receive slice and competes with a control frame
    # for output space. No borrowed input may survive the asynchronous send.
    large = b"\0\xff" * 8185
    client.sendall(frame(2, large[:5000], True, False) + masked_frame(9, b"p") +
                   frame(0, large[5000:], True))
    expect(peer, (9, b"p", True))
    expect(peer, (2, large, True))
    wire = frame(2, large, False)
    peer.sendall(wire[:5])
    peer.sendall(wire[5:8192])
    peer.sendall(wire[8192:])
    expect(client, (2, large, False))
    client.sendall(masked_frame(1, b"CLOSE"))
    expect(peer, (8, b"\x03\xe8", True))
    expect(client, (8, b"\x03\xe8", False))



BOOL_SELECT_DECLARATIONS = r"""
func accepted(_ client: bool, _ text: bool, _ size: i32) -> bool {
    if client { text && size <= 4 } else { !text || size == 0 }
}
func scanned(_ msg: WebSocketMessage) -> bool {
    if msg.fromClient { msg.text.matches(re"^ok$") }
    else { msg.text.matches(re"^server$") }
}
route POST "/shared" {
    guard accepted(true, req.bodyBytes.isEmpty, req.bodyBytes.count) else { return 403 }
    return 200
}
"""
BOOL_SELECT_HANDLER = r"""
return websocket(ws) { msg in
    guard msg.text != "CLOSE" else { msg.close(1000) }
    let allowed: bool = accepted(msg.fromClient, msg.isText, msg.payload.count)
    guard !allowed == false else { msg.drop() }
    msg.forward(msg.payload)
}
"""
BOOL_SELECT_REGEX_HANDLER = r"""
return websocket(ws) { msg in
    guard msg.text != "CLOSE" else { msg.close(1000) }
    guard scanned(msg) else { msg.drop() }
    msg.forward()
}
"""


def bool_select_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"Boolean selection: {actual=!r}, {expected=!r}")

    for data, status in ((b"", b"200"), (b"ok", b"403"), (b"\0\xff", b"403")):
        with socket.create_connection(client.getpeername(), timeout=3) as http:
            http.sendall(b"POST /shared HTTP/1.1\r\nHost: test\r\nConnection: close\r\nContent-Length: " +
                         str(len(data)).encode() + b"\r\n\r\n" + data)
            response = recv_http_response(http)
            if not response.startswith(b"HTTP/1.1 " + status):
                raise AssertionError(f"shared Boolean helper: {data=!r}, {response=!r}")
    first = bytearray(masked_frame(1, b"\xc3"))
    first[0] &= 0x7f
    client.sendall(first + masked_frame(9, b"PING") + masked_frame(0, b"\xa9"))
    expect(peer, (9, b"PING", True))
    expect(peer, (2, b"\xc3\xa9", True))
    client.sendall(masked_frame(1, b"longer") + masked_frame(2, b"\0\xff") +
                   masked_frame(1, b"") + masked_frame(1, b"ok"))
    expect(peer, (2, b"", True))
    expect(peer, (2, b"ok", True))
    peer.sendall(b"\x81\x06denied\x82\x02\0\xff\x81\x00")
    expect(client, (2, b"\0\xff", False))
    expect(client, (2, b"", False))
    client.sendall(masked_frame(1, b"CLOSE"))
    expect(peer, (8, b"\x03\xe8", True))
    expect(client, (8, b"\x03\xe8", False))


def bool_select_regex_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"Boolean regex selection: {actual=!r}, {expected=!r}")

    client.sendall(masked_frame(1, b"server") + masked_frame(2, b"\xff") + masked_frame(1, b"ok"))
    expect(peer, (1, b"ok", True))
    peer.sendall(b"\x82\x02ok\x81\x06server")
    expect(client, (1, b"server", False))
    first = bytearray(masked_frame(2, b"o"))
    first[0] &= 0x7f
    client.sendall(first + masked_frame(9, b"p") + masked_frame(0, b"k"))
    expect(peer, (9, b"p", True))
    expect(peer, (2, b"ok", True))
    client.sendall(masked_frame(1, b"CLOSE"))
    expect(peer, (8, b"\x03\xe8", True))
    expect(client, (8, b"\x03\xe8", False))



SCALAR_PREDICATE_DECLARATIONS = r"""
func same<T: Eq>(_ lhs: T, _ rhs: T) -> bool => lhs == rhs
func allowedName(_ value: str) -> bool => value.matches(re"^allow[0-9]+$") || same(value, "")
func boolPolicy(_ value: bool, _ client: bool) -> bool {
    if client { same(value, false) } else { value }
}
route POST "/scalar-shared" {
    guard allowedName(req.body) else { return 403 }
    return 200
}
"""
SCALAR_STRING_HANDLER = r"""
return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.drop() }
    guard let field = json.get(root, "/a~1b/~0") else { msg.drop() }
    guard let name = json.string(field) else { msg.drop() }
    guard allowedName(name) else { msg.drop() }
    msg.forward("<" + name + ">")
}
"""
SCALAR_BOOL_HANDLER = r"""
return websocket(ws) { msg in
    guard let root = json.parse(msg.text) else { msg.drop() }
    guard let field = json.get(root, "/flag") else { msg.drop() }
    guard let value = json.bool(field) else { msg.drop() }
    guard boolPolicy(value, msg.fromClient) else { msg.drop() }
    msg.forward()
}
"""


def scalar_string_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"scalar String helper: {actual=!r}, {expected=!r}")

    for data, status in ((b"allow7", b"200"), (b"", b"200"), (b"denied", b"403")):
        with socket.create_connection(client.getpeername(), timeout=3) as http:
            http.sendall(b"POST /scalar-shared HTTP/1.1\r\nHost: test\r\nConnection: close\r\nContent-Length: " +
                         str(len(data)).encode() + b"\r\n\r\n" + data)
            response = recv_http_response(http)
            if not response.startswith(b"HTTP/1.1 " + status):
                raise AssertionError(f"shared scalar predicate: {data=!r}, {response=!r}")
    payload = b'{"a/b":{"~":"allow\\u0037"}}'
    first = bytearray(masked_frame(1, payload[:14]))
    first[0] &= 0x7f
    client.sendall(first + masked_frame(9, b"PING") + masked_frame(0, payload[14:]))
    expect(peer, (9, b"PING", True))
    expect(peer, (1, b"<allow7>", True))
    client.sendall(masked_frame(1, b'{"a/b":{"~":"allow7\\u0000"}}') +
                   masked_frame(1, b'{"a/b":{"~":null}}') +
                   masked_frame(2, b'{"a/b":{"~":""}}'))
    expect(peer, (1, b"<>", True))
    payload = b'{"a/b":{"~":"allow9"}}'
    peer.sendall(bytes((0x82, len(payload))) + payload)
    expect(client, (1, b"<allow9>", False))
    bad = b'{"a/b":{"~":false}}'
    good = b'{"a/b":{"~":""}}'
    peer.sendall(bytes((0x81, len(bad))) + bad + bytes((0x82, len(good))) + good)
    expect(client, (1, b"<>", False))
    client.sendall(masked_frame(8, b"\x03\xe8"))
    expect(peer, (8, b"\x03\xe8", True))


def scalar_bool_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"scalar Bool helper: {actual=!r}, {expected=!r}")

    yes = b'{"flag":false}'
    client.sendall(masked_frame(1, b'{"flag":true}') + masked_frame(2, b'{"flag":null}') +
                   masked_frame(1, b"broken") + masked_frame(2, yes))
    expect(peer, (2, yes, True))
    yes = b'{"flag":true}'
    first = bytes((0x01, 7)) + yes[:7]
    peer.sendall(first + b"\x8a\x01p" + bytes((0x80, len(yes) - 7)) + yes[7:])
    expect(client, (10, b"p", False))
    expect(client, (1, yes, False))
    bad = b'{"flag":false}'
    peer.sendall(bytes((0x81, len(bad))) + bad + bytes((0x82, len(yes))) + yes)
    expect(client, (2, yes, False))
    client.sendall(masked_frame(8, b"\x03\xe8"))
    expect(peer, (8, b"\x03\xe8", True))


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


DIRECT_JSON_HANDLER = r"""
return websocket(ws) { message in
    guard let document = json.parse(message.text) else { message.close(1007) }
    guard let parent = json.get(document, "/payload") else { message.close(1008) }
    guard let field = json.get(parent, "/enabled") else { message.close(1008) }
    guard json.bool(field) == false || json.string(field) == "allow" || json.int(field) == -7 else {
        message.close(1008)
    }
    message.forward()
}
"""


def direct_json_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"direct JSON scalar guard: {actual=!r}, {expected=!r}")

    payload = b'{"payload":{"enabled":false}}'
    first = bytearray(masked_frame(1, payload[:14]))
    first[0] &= 0x7F
    client.sendall(first + masked_frame(9, b"PING") + masked_frame(0, payload[14:]))
    expect(peer, (9, b"PING", True))
    expect(peer, (1, payload, True))
    text = b'{"payload":{"enabled":"allow"}}'
    integer = b'{"payload":{"enabled":-7}}'
    client.sendall(masked_frame(2, text) + masked_frame(1, integer))
    expect(peer, (2, text, True))
    expect(peer, (1, integer, True))
    peer.sendall(bytes((0x02, 14)) + payload[:14] + b"\x8a\x01p" +
                 bytes((0x80, len(payload) - 14)) + payload[14:])
    expect(client, (10, b"p", False))
    expect(client, (2, payload, False))
    client.sendall(masked_frame(1, b'{"payload":{"enabled":null}}'))
    expect(peer, (8, b"\x03\xf0", True))
    expect(client, (8, b"\x03\xf0", False))


JSON_REGEX_HANDLER = r"""
return websocket(ws) { message in
    guard let document = json.parse(message.text) else { message.close(1007) }
    guard let field = json.get(document, "/name") else { message.close(1008) }
    guard let name = json.string(field) else { message.close(1003) }
    guard !name.matches(re"deny[0-9]+") else { message.drop() }
    message.forward("<" + name + ">")
}
"""


def json_regex_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"decoded JSON regex: {actual=!r}, {expected=!r}")

    denied = b'{"name":"deny\\u0037"}'
    first = bytearray(masked_frame(1, denied[:12]))
    first[0] &= 0x7F
    client.sendall(first + masked_frame(9, b"PING") + masked_frame(0, denied[12:]) +
                   masked_frame(2, b'{"name":"allow12"}'))
    expect(peer, (9, b"PING", True))
    expect(peer, (1, b"<allow12>", True))
    client.sendall(masked_frame(1, b'{"name":"xdeny7"}') +
                   masked_frame(1, b'{"name":"deny\\u0000"}'))
    expect(peer, (1, b"<xdeny7>", True))
    expect(peer, (1, b"<deny\0>", True))
    peer.sendall(bytes((0x02, 12)) + denied[:12] + b"\x8a\x01p" +
                 bytes((0x80, len(denied) - 12)) + denied[12:] +
                 b'\x82\x16{"name":"deny7suffix"}')
    expect(client, (10, b"p", False))
    expect(client, (1, b"<deny7suffix>", False))
    client.sendall(masked_frame(2, b'{"name":false}'))
    expect(peer, (8, b"\x03\xeb", True))
    expect(client, (8, b"\x03\xeb", False))


TYPED_MESSAGE_DECLARATIONS = r"""
func accepted(_ text: str) -> bool => text.matches(re"o.k")
func allowed(_ msg: WebSocketMessage) -> bool =>
    !msg.fromClient || (true == msg.isText && msg.len <= 3 && accepted(msg.text))
"""

TYPED_MESSAGE_HANDLER = r"""
return websocket(ws) { message in
    guard allowed(message) == true else { message.drop() }
    guard message.isText != message.isBinary else { message.close() }
    message.forward()
}
"""

DOMAIN_MESSAGE_DECLARATIONS = r"""
func same<T: Eq>(_ a: T, _ b: T) -> bool => a == b
func accepted(_ text: str) -> bool => text.matches(re"o.k")
func isText(_ kind: WebSocketMessageKind) -> bool => same(kind, WebSocketMessageKind.text)
func fromClient(_ direction: WebSocketDirection) -> bool =>
    same(direction, WebSocketDirection.clientToUpstream)
func allowed(_ msg: WebSocketMessage) -> bool =>
    !fromClient(msg.direction) || (isText(msg.kind) && msg.len <= 3 && accepted(msg.text))
func classify(_ kind: str) -> WebSocketMessageKind {
    if kind == "text" { WebSocketMessageKind.text } else { WebSocketMessageKind.binary }
}
route GET "/domain" {
    let kind = classify(req.header("X-Kind").or(""))
    guard isText(kind) else { return 403 }
    return 200
}
"""

PAYLOAD_BYTES_DECLARATIONS = r"""
func same<T: Eq>(_ a: T, _ b: T) -> bool => a == b
func allowed(_ bytes: Bytes) -> bool =>
    !bytes.isEmpty && bytes.count == 2 &&
    (same(bytes, b"\x00\xff") || bytes == b"\xc3\xa9")
func choose(_ marker: str) -> Bytes {
    if marker == "yes" { b"\x00\xff" } else { b"" }
}
route POST "/bytes" {
    guard allowed(req.bodyBytes) else { return 403 }
    return 200
}
"""

PAYLOAD_BYTES_HANDLER = r"""
return websocket(ws) { message in
    guard !message.fromClient || allowed(message.payload) else { message.drop() }
    message.forward()
}
"""


CALLBACK_SCOPE_DECLARATIONS = r"""
func identity<T>(_ value: T) -> T => value
"""

CALLBACK_BYTES_HANDLER = r"""
return websocket(ws) { packet in
    let msg: WebSocketMessage = identity(packet)
    let payload: Bytes = msg.payload
    let client = msg.direction == WebSocketDirection.clientToUpstream
    let count: i32 = payload.count
    guard !client || count == 2 else { msg.drop() }
    guard !client || allowed(payload) else { msg.drop() }
    msg.forward()
}
"""

CALLBACK_JSON_HANDLER = r"""
return websocket(ws) { event in
    let packet = identity(event)
    let payloadText: str = packet.text
    guard let document = json.parse(payloadText) else { packet.close(1007) }
    guard let parent = json.get(document, "/payload") else { packet.close(1008) }
    guard let child = json.get(parent, "/name") else { packet.close(1008) }
    guard let text = json.string(child) else { packet.close(1003) }
    packet.forward("[" + text + "]")
}
"""


IF_MESSAGE_HANDLER = r"""
return websocket(ws) { packet in
    let msg = identity(packet)
    if msg.payload.isEmpty { msg.drop() }
    if msg.fromClient && msg.isBinary { msg.forward(b"\x00\xff") }
    if msg.text == "CLOSE" { msg.close() }
    if msg.text.matches(re"allow[0-9]+") && msg.fromClient {
        let text = msg.text
        msg.forward("[" + text + "]")
    } else {
        msg.close(1008, "policy")
    }
}
"""


def if_message_exchange(client, peer, close_default=False):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"if verdict: {actual=!r}, {expected=!r}")

    first = bytearray(masked_frame(2, b"\xff"))
    first[0] &= 0x7F
    client.sendall(masked_frame(2, b"") + first + masked_frame(9, b"PING") +
                   masked_frame(0, b"\x00"))
    expect(peer, (9, b"PING", True))
    expect(peer, (2, b"\x00\xff", True))
    client.sendall(masked_frame(1, b"allow12"))
    expect(peer, (1, b"[allow12]", True))
    if close_default:
        peer.sendall(b"\x81\x04deny")
        expected = b"\x03\xf0policy"
    else:
        client.sendall(masked_frame(1, b"CLOSE"))
        expected = b"\x03\xe8"
    expect(peer, (8, expected, True))
    expect(client, (8, expected, False))


def if_default_exchange(client, peer):
    if_message_exchange(client, peer, close_default=True)


NESTED_IF_HANDLER = r"""
return websocket(ws) { packet in
    let msg = identity(packet)
    if msg.fromClient {
        if msg.payload.isEmpty { msg.drop() }
        else {
            if msg.kind == WebSocketMessageKind.binary { msg.forward(b"\xff\x00") }
            else { msg.forward("<" + msg.text + ">") }
        }
    } else {
        let prefix = "["
        if msg.payload.isEmpty { msg.close() }
        else { msg.forward(prefix + msg.text + "]") }
    }
}
"""

NESTED_EARLY_IF_HANDLER = r"""
return websocket(ws) { msg in
    if msg.fromClient {
        if msg.isBinary { msg.forward(b"\x00\xff") }
        else { msg.drop() }
    }
    guard let document = json.parse(msg.text) else { msg.close(1007) }
    guard let name = json.string(document) else { msg.close(1003) }
    msg.forward(name)
}
"""


def nested_if_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"nested if: {actual=!r}, {expected=!r}")
    first = bytearray(masked_frame(2, b"\xff"))
    first[0] &= 0x7F
    client.sendall(masked_frame(2, b"") + first + masked_frame(9, b"PING") +
                   masked_frame(0, b"\x00"))
    expect(peer, (9, b"PING", True))
    expect(peer, (2, b"\xff\x00", True))
    client.sendall(masked_frame(1, b"hello"))
    expect(peer, (1, b"<hello>", True))
    peer.sendall(b"\x81\x05world")
    expect(client, (1, b"[world]", False))
    peer.sendall(b"\x81\x00")
    expect(peer, (8, b"\x03\xe8", True))
    expect(client, (8, b"\x03\xe8", False))


def nested_early_if_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"nested early if: {actual=!r}, {expected=!r}")
    client.sendall(masked_frame(1, b"broken") + masked_frame(2, b"\xff\x00"))
    expect(peer, (2, b"\x00\xff", True))
    peer.sendall(b'\x81\x07"allow"')
    expect(client, (1, b"allow", False))
    peer.sendall(b"\x81\x06broken")
    expect(peer, (8, b"\x03\xef", True))
    expect(client, (8, b"\x03\xef", False))


BRANCH_GUARD_HANDLER = r"""
return websocket(ws) { msg in
    if msg.fromClient {
        guard let document = json.parse(msg.text) else { msg.close(1007) }
        guard let field = json.get(document, "/name") else { msg.close(1008) }
        guard let name = json.string(field) else { msg.close(1003) }
        msg.forward("<" + name + ">")
    } else { msg.forward() }
}
"""

IF_LET_HANDLER = r"""
return websocket(ws) { msg in
    if let document = json.parse(msg.text) {
        if let field = json.get(document, "/flag") {
            if let value = json.bool(field) {
                guard value == false else { msg.forward("true") }
                msg.forward("false")
            } else { msg.forward("wrong") }
        } else { msg.forward("missing") }
    } else { msg.close(1007) }
}
"""

BRANCH_CONTINUATION_HANDLER = r"""
return websocket(ws) { msg in
    if msg.fromClient {
        if let document = json.parse(msg.text) { msg.forward("json") }
        guard msg.isBinary else { msg.drop() }
        msg.forward(b"\x00\xff")
    } else { msg.forward("server") }
}
"""


JSON_HELPER_DECLARATIONS = r"""
func identity<T>(_ value: T) -> T => value
func readDocument(_ msg: WebSocketMessage) -> Json => json.parse(identity(msg).text)
func select(_ root: Json, _ pointer: str) -> Json => json.get(identity(root), pointer)
func stringValue(_ value: Json) -> str => json.string(value)
func flag(_ value: Json) -> bool => json.bool(value)
"""

HELPER_GUARD_HANDLER = (BRANCH_GUARD_HANDLER
                        .replace("json.parse(msg.text)", "readDocument(msg)")
                        .replace("json.get(document,", "select(document,")
                        .replace("json.string(field)", "stringValue(identity(field))"))
HELPER_IF_LET_HANDLER = (IF_LET_HANDLER
                         .replace("json.parse(msg.text)", "readDocument(msg)")
                         .replace("json.get(document,", "select(document,")
                         .replace("json.bool(field)", "flag(identity(field))"))


OPTIONAL_CONDITION_DECLARATIONS = r"""
func readClient(_ msg: WebSocketMessage) -> Json {
    guard msg.fromClient else { nil }
    if msg.isText { json.parse(msg.text) } else { nil }
}
"""

OPTIONAL_CONDITION_HANDLER = r"""
return websocket(ws) { msg in
    if let root = readClient(msg) {
        guard let field = json.get(root, "/name") else { msg.close(1008) }
        guard let text = json.string(field) else { msg.close(1003) }
        msg.forward("<" + text + ">")
    } else { msg.forward() }
}
"""


HELPER_BINDING_DECLARATIONS = r"""
func readSelected(_ msg: WebSocketMessage) -> str {
    guard let root = json.parse(msg.text) else { nil }
    guard let field = json.get(root, "/name") else { nil }
    guard let gate = json.get(root, "/gate") else { nil }
    if let text = json.string(field) { text } else { nil }
}
"""

HELPER_BINDING_HANDLER = r"""
return websocket(ws) { msg in
    if let text = readSelected(msg) { msg.forward("<" + text + ">") }
    else { msg.forward("absent") }
}
"""


CHOICE_DECLARATIONS = r"""
func pick(_ msg: WebSocketMessage, _ root: Json) -> Json {
    if msg.fromClient { json.get(root, "/a") } else { json.get(root, "/b") }
}
func readChoice(_ msg: WebSocketMessage) -> str {
    guard let root = json.parse(msg.text) else { nil }
    guard let field = pick(msg, root) else { nil }
    json.string(field)
}
func fallback(_ root: Json) -> Json {
    if let field = json.get(root, "/a") { field } else { json.get(root, "/b") }
}
func readFallback(_ msg: WebSocketMessage) -> str {
    guard let root = json.parse(msg.text) else { nil }
    guard let field = fallback(root) else { nil }
    json.string(field)
}
"""

CHOICE_GUARD_HANDLER = r"""
return websocket(ws) { msg in
    guard let text = readChoice(msg) else { msg.drop() }
    guard text.hasPrefix("ok") else { msg.close(1008) }
    msg.forward("<" + text + ">")
}
"""

CHOICE_EARLY_HANDLER = r"""
return websocket(ws) { msg in
    if msg.fromClient {
        if let text = readFallback(msg) { msg.forward(text) }
        guard msg.isBinary else { msg.drop() }
        msg.forward(b"\xff")
    } else { msg.forward("server") }
}
"""


def choice_guard_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"choice guard: {actual=!r}, {expected=!r}")
    data = b'{"a":"ok\\u0000A","b":false}'
    first = bytearray(masked_frame(1, data[:8]))
    first[0] &= 0x7F
    client.sendall(first + masked_frame(9, b"PING") + masked_frame(0, data[8:]))
    expect(peer, (9, b"PING", True))
    expect(peer, (1, b"<ok\0A>", True))
    client.sendall(masked_frame(2, b'{"b":"okB"}') +
                   masked_frame(2, b'{"a":"ok2","b":"ignored"}'))
    expect(peer, (1, b"<ok2>", True))
    for payload in (b'{"a":"okA"}', b'{"a":false,"b":"okB"}'):
        peer.sendall(bytes((0x81, len(payload))) + payload)
    expect(client, (1, b"<okB>", False))
    client.sendall(masked_frame(1, b'{"a":"blocked","b":"okB"}'))
    expect(peer, (8, b"\x03\xf0", True))
    expect(client, (8, b"\x03\xf0", False))


def choice_early_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"choice early: {actual=!r}, {expected=!r}")
    client.sendall(masked_frame(1, b'{"b":"B"}'))
    expect(peer, (1, b"B", True))
    client.sendall(masked_frame(1, b'{"a":null,"b":"B"}') +
                   masked_frame(2, b'{"a":false,"b":"B"}'))
    expect(peer, (2, b"\xff", True))
    for payload, expected in ((b'{"a":"A","b":"B"}', b"A"),
                              (b'{"a":"","b":"B"}', b"")):
        client.sendall(masked_frame(2, payload))
        expect(peer, (1, expected, True))
    peer.sendall(b"\x82\x02\xff\x00")
    expect(client, (1, b"server", False))
    client.sendall(masked_frame(8, b"\x03\xe8"))
    expect(peer, (8, b"\x03\xe8", True))


def helper_binding_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"helper binding: {actual=!r}, {expected=!r}")
    data = b'{"gate":null,"name":"a\\u0000b"}'
    first = bytearray(masked_frame(1, data[:13]))
    first[0] &= 0x7F
    client.sendall(first + masked_frame(9, b"PING") + masked_frame(0, data[13:]))
    expect(peer, (9, b"PING", True))
    expect(peer, (1, b"<a\0b>", True))
    for payload, expected in ((b'{"gate":false,"name":""}', b"<>"),
                              (b'{"name":"lost"}', b"absent"),
                              (b'{"gate":0,"name":false}', b"absent"),
                              (b"\xff\x00", b"absent")):
        client.sendall(masked_frame(2, payload))
        expect(peer, (1, expected, True))
    payload = b'{"gate":null,"name":"peer"}'
    peer.sendall(bytes((0x81, len(payload))) + payload)
    expect(client, (1, b"<peer>", False))
    client.sendall(masked_frame(8, b"\x03\xe8"))
    expect(peer, (8, b"\x03\xe8", True))


def optional_condition_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"optional condition: {actual=!r}, {expected=!r}")
    data = b'{"name":"a\\u0000b"}'
    first = bytearray(masked_frame(1, data[:9]))
    first[0] &= 0x7F
    client.sendall(first + masked_frame(9, b"PING") + masked_frame(0, data[9:]))
    expect(peer, (9, b"PING", True))
    expect(peer, (1, b"<a\0b>", True))
    client.sendall(masked_frame(1, b'{"name":""}'))
    expect(peer, (1, b"<>", True))
    client.sendall(masked_frame(2, b"\xff\x00"))
    expect(peer, (2, b"\xff\x00", True))
    client.sendall(masked_frame(1, b"broken"))
    expect(peer, (1, b"broken", True))
    peer.sendall(b"\x82\x02\xff\x00")
    expect(client, (2, b"\xff\x00", False))
    client.sendall(masked_frame(1, b'{"name":false}'))
    expect(peer, (8, b"\x03\xeb", True))
    expect(client, (8, b"\x03\xeb", False))


def branch_guard_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"branch guard: {actual=!r}, {expected=!r}")
    data = b'{"name":"a\\u0000b"}'
    first = bytearray(masked_frame(1, data[:9]))
    first[0] &= 0x7F
    client.sendall(first + masked_frame(9, b"PING") + masked_frame(0, data[9:]))
    expect(peer, (9, b"PING", True))
    expect(peer, (1, b"<a\0b>", True))
    client.sendall(masked_frame(1, b'{"name":""}'))
    expect(peer, (1, b"<>", True))
    peer.sendall(b"\x82\x02\xff\x00")
    expect(client, (2, b"\xff\x00", False))
    client.sendall(masked_frame(1, b"broken"))
    expect(peer, (8, b"\x03\xef", True))
    expect(client, (8, b"\x03\xef", False))


def if_let_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"if let: {actual=!r}, {expected=!r}")
    for payload, expected in ((b'{"flag":false}', b"false"),
                              (b'{"flag":true}', b"true"),
                              (b'{"flag":null}', b"wrong"), (b"{}", b"missing")):
        client.sendall(masked_frame(2, payload))
        expect(peer, (1, expected, True))
    peer.sendall(b'\x81\x0e{"flag":false}')
    expect(client, (1, b"false", False))
    client.sendall(masked_frame(1, b"broken"))
    expect(peer, (8, b"\x03\xef", True))
    expect(client, (8, b"\x03\xef", False))


def branch_continuation_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"branch continuation: {actual=!r}, {expected=!r}")
    client.sendall(masked_frame(1, b"broken") + masked_frame(2, b"\xff\x00"))
    expect(peer, (2, b"\x00\xff", True))
    client.sendall(masked_frame(1, b"null"))
    expect(peer, (1, b"json", True))
    peer.sendall(b"\x82\x02\xff\x00")
    expect(client, (1, b"server", False))
    client.sendall(masked_frame(8, b"\x03\xe8"))
    expect(peer, (8, b"\x03\xe8", True))


def payload_bytes_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"byte payload: {actual=!r}, {expected=!r}")

    for data, status in ((b"\0\xff", b"200"), (b"", b"403"), (b"\xc3\xa9", b"200")):
        with socket.create_connection(client.getpeername(), timeout=3) as http:
            headers = (b"POST /bytes HTTP/1.1\r\nHost: test\r\nConnection: close\r\nContent-Length: " +
                       str(len(data)).encode() + b"\r\n\r\n")
            http.sendall(headers + data[:1])
            if len(data) > 1:
                http.settimeout(0.1)
                try:
                    early = http.recv(1)
                except socket.timeout:
                    early = None
                if early is not None:
                    raise AssertionError(f"bodyBytes policy ran before body completion: {early=!r}")
                http.settimeout(3)
                http.sendall(data[1:])
            response = recv_http_response(http)
            if not response.startswith(b"HTTP/1.1 " + status):
                raise AssertionError(f"Bytes in HTTP: {data=!r}, {response=!r}")
    first = bytearray(masked_frame(2, b"\0"))
    first[0] &= 0x7F
    client.sendall(masked_frame(2, b"") + masked_frame(2, b"\xff\0") + first +
                   masked_frame(9, b"PING") + masked_frame(0, b"\xff"))
    expect(peer, (9, b"PING", True))
    expect(peer, (2, b"\0\xff", True))
    client.sendall(masked_frame(1, b"\xc3\xa9"))
    expect(peer, (1, b"\xc3\xa9", True))
    peer.sendall(b"\x82\x01\xff\x81\x00")
    expect(client, (2, b"\xff", False))
    expect(client, (1, b"", False))
    client.sendall(masked_frame(8, b"\x03\xe8"))
    expect(peer, (8, b"\x03\xe8", True))


def domain_message_exchange(client, peer):
    for kind, status in ((b"text", b"200"), (b"binary", b"403")):
        with socket.create_connection(client.getpeername(), timeout=3) as http:
            http.sendall(b"GET /domain HTTP/1.1\r\nHost: test\r\nConnection: close\r\nX-Kind: " +
                         kind + b"\r\n\r\n")
            response = recv_http_response(http)
            if not response.startswith(b"HTTP/1.1 " + status):
                raise AssertionError(f"domain enum in HTTP: {kind=!r}, {response=!r}")
    typed_message_exchange(client, peer)


def typed_message_exchange(client, peer):
    def expect(sock, expected):
        actual = recv_client_frame(sock)
        if actual != expected:
            raise AssertionError(f"typed message predicate: {actual=!r}, {expected=!r}")

    # Predicate sees the complete message, while Ping bypasses application inspection.
    first = bytearray(masked_frame(1, b"o"))
    first[0] &= 0x7F
    client.sendall(masked_frame(1, b"bad") + masked_frame(2, b"oak") + first +
                   masked_frame(9, b"PING") + masked_frame(0, b"ak"))
    expect(peer, (9, b"PING", True))
    expect(peer, (1, b"oak", True))
    client.sendall(masked_frame(1, b"o\0k"))
    expect(peer, (1, b"o\0k", True))
    # The same typed helper deliberately permits the upstream direction.
    peer.sendall(b"\x82\x03bad\x81\x00")
    expect(client, (2, b"bad", False))
    expect(client, (1, b"", False))
    client.sendall(masked_frame(8, b"\x03\xe8"))
    expect(peer, (8, b"\x03\xe8", True))


def binary_replacement_scenario(server, backend_kind, handler=BINARY_HANDLER,
                                exchange=binary_exchange, declarations="", request=REQUEST, response=WS_RESPONSE_HEADERS):
    with socket.socket() as upstream, tempfile.TemporaryDirectory(prefix="rut-ws-binary-") as temp:
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        upstream.settimeout(3)
        path = os.path.join(temp, "route.rut")
        with open(path, "w", encoding="utf-8") as route_file:
            route_file.write(
                f'listen 127.0.0.1:0\n'
                f'upstream ws at "127.0.0.1:{upstream.getsockname()[1]}"\n'
                + declarations + '\nroute GET "/ws" {\n' + handler + '}\n')
        process, port, diagnostic = launch(server, path, backend_kind)
        if process is None:
            text = diagnostic.decode(errors="replace")
            if backend_kind == "io_uring" and \
                    "--backend io_uring requested, but io_uring is unavailable" in text:
                return "skip", text
            raise AssertionError(f"{backend_kind} binary replacement server failed:\n{text}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.sendall(request)
                with upstream.accept()[0] as peer:
                    peer.settimeout(3)
                    recv_until(peer, b"\r\n\r\n")
                    peer.sendall(response)
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
                                         handler=BINARY_HANDLER, exchange=binary_exchange,
                                         declarations="", request=REQUEST, response=WS_RESPONSE_HEADERS):
    with socket.socket() as upstream, tempfile.TemporaryDirectory(prefix="rut-ws-native-") as temp:
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        upstream.settimeout(3)
        source = os.path.join(temp, "route.rut")
        artifact = os.path.join(temp, "route.native")
        with open(source, "w", encoding="utf-8") as route_file:
            route_file.write(
                f'listen 127.0.0.1:0\nupstream ws at "127.0.0.1:{upstream.getsockname()[1]}"\n'
                + declarations + '\nroute GET "/ws" { ' + handler + '}\n')
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
                client.sendall(request)
                with upstream.accept()[0] as peer:
                    peer.settimeout(3)
                    if not recv_until(peer, b"\r\n\r\n").startswith(b"GET /ws "):
                        raise AssertionError("native artifact did not forward valid handshake")
                    peer.sendall(response)
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


def chain_after_scenario(server, compiler, backend_kind, native, protected_header=None):
    with socket.socket() as upstream, tempfile.TemporaryDirectory(prefix="rut-ws-after-") as temp:
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(2)
        source = os.path.join(temp, "route.rut")
        effects = ('resp.set("X-After-Value", req.header("X-Value").or("missing"))\n'
                   'resp.add("X-Stage", "after")\n')
        if protected_header:
            effects += f'resp.set("{protected_header}", "broken")\n'
        with open(source, "w", encoding="utf-8") as route_file:
            route_file.write(
                f'listen 127.0.0.1:0\nupstream ws at "127.0.0.1:{upstream.getsockname()[1]}"\n'
                'func decorate(_ req: i32, _ resp: Response) -> i32 {\n' + effects + '0\n}\n'
                'chain headers { after decorate(req, resp) }\n'
                'route GET "/ws" use chain headers {\n'
                'req.set("X-Admission", "changed")\n'
                'guard req.header("X-Deny").or("") != "yes" else { return 403 }\n'
                'return websocket(ws) { msg in msg.forward(msg.text + "!") }\n}\n')
        selected_server = server
        selected_source = source
        if native:
            artifact = os.path.join(temp, "route.native")
            emitted = subprocess.run([compiler, source, "2"], capture_output=True,
                                     check=True, timeout=30)
            with open(artifact, "wb") as target:
                target.write(emitted.stdout)
            os.unlink(source)
            selected_server = os.path.join(temp, "rut")
            shutil.copy2(server, selected_server)
            wrapper = os.path.join(temp, "rut-compile")
            with open(wrapper, "w", encoding="utf-8") as target:
                target.write('#!/usr/bin/env python3\nimport sys\n'
                             f'with open({artifact!r}, "rb") as source:\n'
                             '    sys.stdout.buffer.write(source.read())\n')
            os.chmod(wrapper, 0o700)
            selected_source = os.path.join(temp, "deleted.rut")
        process, port, diagnostic = launch(selected_server, selected_source, backend_kind)
        if process is None:
            text = diagnostic.decode(errors="replace")
            if backend_kind == "io_uring" and "--backend io_uring requested, but io_uring is unavailable" in text:
                return "skip", text
            raise AssertionError(f"chain after server failed:\n{text}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                denied_request = REQUEST.replace(
                    b"Connection: Upgrade\r\n", b"Connection: keep-alive\r\n").replace(
                    b"\r\n\r\n", b"\r\nX-Deny: yes\r\nX-Value: denied-value\r\n\r\n")
                client.sendall(denied_request)
                denied = recv_http_response(client)
                if not denied.startswith(b"HTTP/1.1 403") or \
                        b"x-after-value: denied-value\r\n" not in denied.lower() or \
                        denied.lower().count(b"x-stage: after\r\n") != 1:
                    raise AssertionError(f"chain after denial effects lost: {denied!r}")
                upstream.settimeout(0.2)
                try:
                    unexpected, _ = upstream.accept()
                except TimeoutError:
                    pass
                else:
                    unexpected.close()
                    raise AssertionError("chain after denial opened an upstream")
                upstream.settimeout(3)
                # Reuse the denied keepalive connection; response values must be fresh.
                accepted = REQUEST.replace(b"\r\n\r\n", b"\r\nX-Value: allowed-value\r\n\r\n")
                client.sendall(accepted + masked_frame(1, b"first"))
                with upstream.accept()[0] as peer:
                    peer.settimeout(3)
                    forwarded = recv_until(peer, b"\r\n\r\n")
                    if b"x-admission: changed\r\n" not in forwarded.lower():
                        raise AssertionError(f"request rewrite was lost: {forwarded!r}")
                    peer.sendall(WS_RESPONSE_HEADERS + b"\x81\x06server")
                    if protected_header:
                        rejected = recv_until(client, b"\r\n\r\n")
                        if rejected:
                            raise AssertionError(f"modified handshake was published: {rejected!r}")
                        if peer.recv(4096):
                            raise AssertionError("protected handshake mutation leaked application data")
                    else:
                        response = recv_http_response(client)
                        if not response.startswith(b"HTTP/1.1 101") or \
                                b"x-after-value: allowed-value\r\n" not in response.lower() or \
                                response.lower().count(b"x-stage: after\r\n") != 1:
                            raise AssertionError(f"chain after 101 effects lost/stale: {response!r}")
                        if recv_client_frame(peer) != (1, b"first!", True):
                            raise AssertionError("client early message was lost after response rewrite")
                        if recv_client_frame(client) != (1, b"server!", False):
                            raise AssertionError("upstream early message was lost after response rewrite")
                        client.sendall(masked_frame(8, b"\x03\xe8"))
                        if recv_client_frame(peer) != (8, b"\x03\xe8", True):
                            raise AssertionError("chain after changed Close forwarding")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    return "pass", ""


def admission_scenario(server, backend_kind, prelude=""):
    """Admission may suspend before reaching the upgrade."""
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
        'func allowed(_ origin: str) -> bool => origin.matches(re"^https://allowed[.]example$")\n'
        'route GET "/ws" {\n'
        '  req.set("X-Admission", "checked")\n'
        '  let candidate = req.uniqueHeader("Origin")\n'
        '  guard let origin = candidate else { return response(403, body: "missing") }\n'
        '  let accepted = allowed(origin)\n'
        '  guard accepted else { return response(403, body: "denied") }\n'
        '  guard req.bodyBytes.isEmpty else { return 400 }\n'
        '  guard let doc = json.parse(req.query("policy").or("true")) else { return 400 }\n'
        '  guard json.bool(doc).or(false) else { return 403 }\n'
        + prelude +
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
                if label == "wrong Origin" and not denied.endswith(b"denied"):
                    raise AssertionError(f"denial body was lost: {denied!r}")
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
            if b"X-Admission: checked\r\n".lower() not in forwarded.lower():
                raise AssertionError(f"HTTP admission request mutation was lost: {forwarded!r}")
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


def tls_terminate_handshake_scenario(server, backend_kind, connection_context=False):
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
    if connection_context:
        source = (f'upstream ws at "127.0.0.1:{backend.getsockname()[1]}"\n'
                  + CONNECTION_DECLARATIONS + '\nroute GET "/ws" { ' + CONNECTION_HANDLER + '}\n')
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
            if connection_context:
                connection_exchange(valid_client, peer, b"tls:")
            else:
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
        for handler, exchange, declarations in (
                (GENERAL_JSON_HANDLER, general_json_exchange, GENERAL_JSON_DECLARATIONS),
                (GENERAL_REGEX_HANDLER, general_regex_exchange, GENERAL_JSON_DECLARATIONS),
                (TYPED_JSON_HANDLER, typed_json_exchange, GENERAL_JSON_DECLARATIONS),
                (JSON_LIFETIME_HANDLER, json_lifetime_exchange, ""),
                (HASH_OUTPUT_HANDLER, hash_output_exchange, ""),
                (STRING_HELPER_HANDLER, string_helper_exchange, STRING_HELPER_DECLARATIONS),
                (NOMINAL_MATCH_HANDLER, nominal_match_exchange, NOMINAL_MATCH_DECLARATIONS),
                (ERROR_VALUE_HANDLER, error_value_exchange, ERROR_VALUE_DECLARATIONS),
                (CONNECTION_HANDLER, connection_exchange, CONNECTION_DECLARATIONS),
                (ERROR_MATCH_HANDLER, error_match_exchange, ERROR_MATCH_DECLARATIONS),
                (ERROR_MATCH_HANDLER, error_match_exchange, ERROR_MATCH_IMPLICIT_DECLARATIONS),
                (ERROR_FIELDS_HANDLER, error_fields_exchange, ERROR_FIELDS_DECLARATIONS),
                (DYNAMIC_OUTPUT_HANDLER, dynamic_output_exchange, DYNAMIC_OUTPUT_DECLARATIONS),
                (DYNAMIC_BOUND_HANDLER, dynamic_bound_exchange, ""),
                (DYNAMIC_UTF8_HANDLER, dynamic_utf8_exchange, ""),
                (EAGER_BINDING_HANDLER, eager_binding_exchange, EAGER_BINDING_DECLARATIONS),
                (GENERAL_HANDLER, general_expression_exchange, GENERAL_DECLARATIONS),
                (SCALAR_STRING_HANDLER, scalar_string_exchange, SCALAR_PREDICATE_DECLARATIONS),
                (SCALAR_BOOL_HANDLER, scalar_bool_exchange, SCALAR_PREDICATE_DECLARATIONS),
                (BOOL_SELECT_HANDLER, bool_select_exchange, BOOL_SELECT_DECLARATIONS),
                (BOOL_SELECT_REGEX_HANDLER, bool_select_regex_exchange, BOOL_SELECT_DECLARATIONS),
                (BORROWED_BINARY_HANDLER, borrowed_binary_exchange, BORROWED_BINARY_DECLARATIONS),
                (OPTIONAL_DEFAULT_HANDLER, optional_default_exchange, OPTIONAL_VALUE_DECLARATIONS),
                (OPTIONAL_BYTES_HANDLER, optional_bytes_exchange, OPTIONAL_VALUE_DECLARATIONS),
                (CHOICE_GUARD_HANDLER, choice_guard_exchange, CHOICE_DECLARATIONS),
                (CHOICE_EARLY_HANDLER, choice_early_exchange, CHOICE_DECLARATIONS),
                (HELPER_BINDING_HANDLER, helper_binding_exchange, HELPER_BINDING_DECLARATIONS),
                (OPTIONAL_CONDITION_HANDLER, optional_condition_exchange,
                 OPTIONAL_CONDITION_DECLARATIONS),
                (HELPER_GUARD_HANDLER, branch_guard_exchange, JSON_HELPER_DECLARATIONS),
                (HELPER_IF_LET_HANDLER, if_let_exchange, JSON_HELPER_DECLARATIONS),
                (BRANCH_GUARD_HANDLER, branch_guard_exchange, ""),
                (IF_LET_HANDLER, if_let_exchange, ""),
                (BRANCH_CONTINUATION_HANDLER, branch_continuation_exchange, ""),
                (NESTED_IF_HANDLER, nested_if_exchange, CALLBACK_SCOPE_DECLARATIONS),
                (NESTED_EARLY_IF_HANDLER, nested_early_if_exchange, ""),
                (IF_MESSAGE_HANDLER, if_message_exchange, CALLBACK_SCOPE_DECLARATIONS),
                (IF_MESSAGE_HANDLER, if_default_exchange, CALLBACK_SCOPE_DECLARATIONS),
                (CALLBACK_BYTES_HANDLER, payload_bytes_exchange,
                 PAYLOAD_BYTES_DECLARATIONS + CALLBACK_SCOPE_DECLARATIONS),
                (CALLBACK_JSON_HANDLER, nested_json_exchange, CALLBACK_SCOPE_DECLARATIONS)):
            for native in (False, True):
                if native:
                    status, details = native_binary_source_removal_scenario(
                        args.server, args.compiler, backend, handler, exchange, declarations)
                else:
                    status, details = binary_replacement_scenario(
                        args.server, backend, handler, exchange, declarations)
                if status == "skip":
                    print(f"SKIP {backend}: {details.strip()}")
                else:
                    if status != "pass":
                        raise AssertionError(f"callback scope: {details}")
                    print(f"PASS {backend} {exchange.__name__} native={native}")
        for native in (False, True):
            handler = CONNECTION_HANDLER.replace("websocket(ws)", 'websocket(ws, subprotocol: "chat")')
            request = REQUEST[:-2] + b"Sec-WebSocket-Protocol: chat\r\n\r\n"
            response = WS_RESPONSE_HEADERS[:-2] + b"Sec-WebSocket-Protocol: chat\r\n\r\n"
            exchange = lambda client, peer: connection_exchange(client, peer, b"plain:chat")
            if native:
                status, details = native_binary_source_removal_scenario(
                    args.server, args.compiler, backend, handler, exchange, CONNECTION_DECLARATIONS,
                    request=request, response=response)
            else:
                status, details = binary_replacement_scenario(
                    args.server, backend, handler, exchange, CONNECTION_DECLARATIONS,
                    request=request, response=response)
            print(f"{status.upper()} {backend} connection negotiated subprotocol native={native}: {details}")
        for native in (False, True):
            if native:
                status, details = native_binary_source_removal_scenario(
                    args.server, args.compiler, backend, PAYLOAD_BYTES_HANDLER,
                    payload_bytes_exchange, PAYLOAD_BYTES_DECLARATIONS)
            else:
                status, details = binary_replacement_scenario(
                    args.server, backend, PAYLOAD_BYTES_HANDLER,
                    payload_bytes_exchange, PAYLOAD_BYTES_DECLARATIONS)
            if status == "skip":
                print(f"SKIP {backend}: {details.strip()}")
            else:
                print(f"PASS {backend} Bytes payload shared with HTTP native={native}")
        for native in (False, True):
            if native:
                status, details = native_binary_source_removal_scenario(
                    args.server, args.compiler, backend, TYPED_MESSAGE_HANDLER,
                    domain_message_exchange, DOMAIN_MESSAGE_DECLARATIONS)
            else:
                status, details = binary_replacement_scenario(
                    args.server, backend, TYPED_MESSAGE_HANDLER,
                    domain_message_exchange, DOMAIN_MESSAGE_DECLARATIONS)
            if status == "skip":
                print(f"SKIP {backend}: {details.strip()}")
            else:
                print(f"PASS {backend} domain enum predicates shared with HTTP native={native}")
        for native in (False, True):
            if native:
                status, details = native_binary_source_removal_scenario(
                    args.server, args.compiler, backend, TYPED_MESSAGE_HANDLER,
                    typed_message_exchange, TYPED_MESSAGE_DECLARATIONS)
            else:
                status, details = binary_replacement_scenario(
                    args.server, backend, TYPED_MESSAGE_HANDLER,
                    typed_message_exchange, TYPED_MESSAGE_DECLARATIONS)
            if status == "skip":
                print(f"SKIP {backend}: {details.strip()}")
            else:
                print(f"PASS {backend} typed message predicates native={native}")
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
        for native in (False, True):
            if native:
                status, details = native_binary_source_removal_scenario(
                    args.server, args.compiler, backend, DIRECT_JSON_HANDLER, direct_json_exchange)
            else:
                status, details = binary_replacement_scenario(
                    args.server, backend, DIRECT_JSON_HANDLER, direct_json_exchange)
            if status == "skip":
                print(f"SKIP {backend}: {details.strip()}")
            else:
                print(f"PASS {backend} direct JSON scalar guards native={native}")
        for native in (False, True):
            if native:
                status, details = native_binary_source_removal_scenario(
                    args.server, args.compiler, backend, JSON_REGEX_HANDLER, json_regex_exchange)
            else:
                status, details = binary_replacement_scenario(
                    args.server, backend, JSON_REGEX_HANDLER, json_regex_exchange)
            if status == "skip":
                print(f"SKIP {backend}: {details.strip()}")
            else:
                print(f"PASS {backend} decoded JSON regex native={native}")
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
        for prelude in ("", "wait(1)\n"):
            status, details = admission_scenario(args.server, backend, prelude)
            if status == "skip":
                print(f"SKIP {backend}: {details.strip()}")
            else:
                print(f"PASS {backend} HTTP admission / zero-connect / keepalive / "
                      f"message rewrite prelude={prelude.strip()!r}")
        for native in (False, True):
            for protected_header in (None, "Sec-WebSocket-Accept", "Sec-WebSocket-Protocol",
                                     "Sec-WebSocket-Extensions"):
                status, details = chain_after_scenario(args.server, args.compiler, backend,
                                                      native, protected_header)
                if status == "skip":
                    print(f"SKIP {backend}: {details.strip()}")
                else:
                    print(f"PASS {backend} HTTP chain after native={native} protected={protected_header}")
        status, details = tls_passthrough_scenario(args.server, backend)
        if status == "skip":
            print(f"SKIP {backend}: {details.strip()}")
        else:
            print(f"PASS {backend} TLS passthrough")
        status, details = tls_terminate_handshake_scenario(args.server, backend, connection_context=True)
        print(f"{status.upper()} {backend} TLS connection context: {details}")
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
