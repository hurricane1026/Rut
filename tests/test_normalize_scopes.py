#!/usr/bin/env python3
"""Local helper expansion must respect nested let and collector bindings."""
import argparse

from test_redis_commands import gateway


PROGRAM = r'''variant ScopeValue { bytes(Bytes) missing }
struct ScopeWindow { bytes: Bytes start: i32 }
func scopePair(_ bytes: Bytes, _ position: i32) -> Bytes {
    guard let pair = bytes.slice(position, position + 2) else { nil }
    guard pair.count == 2 else { nil }
    pair
}
func scopePositions(_ bytes: Bytes, _ position: i32) -> bool {
    guard let pair = scopePair(bytes, position) else { false }
    guard let first = pair[0] else { false }
    guard let second = pair[1] else { false }
    first == bytes[position] && second == bytes[position + 1]
}
func triple(_ bytes: Bytes, _ position: i32) -> Bytes {
    guard let one = bytes.slice(position, position + 1) else { nil }
    guard let two = concatBytes(one, one, 64) else { nil }
    guard let three = concatBytes(one, two, 64) else { nil }
    three
}
func repeated(_ bytes: Bytes, _ position: i32) -> Bytes {
    guard let first = triple(bytes, position) else { nil }
    guard let twice = concatBytes(first, first, 64) else { nil }
    guard let second = triple(bytes, position + 1) else { nil }
    concatBytes(twice, second, 64)
}
func scopeValue(_ bytes: Bytes, _ position: i32) -> ScopeValue {
    guard let value = repeated(bytes, position) else { ScopeValue.missing }
    ScopeValue.bytes(value)
}
func scopeBytes(_ value: ScopeValue) -> Bytes {
    match value { .bytes(bytes) => bytes _ => nil }
}
func scopeStep(_ bytes: Bytes, _ position: i32) -> (i32, Bytes, bool) {
    guard scopePositions(bytes, position) else { nil }
    guard let value = scopeBytes(scopeValue(bytes, position)) else { nil }
    (position + 1, value, position + 2 == bytes.count)
}
func scopeList(_ bytes: Bytes, _ start: i32) {
    guard let values = collectBytes(bytes, start, 8, scopeStep) else { nil }
    guard values.count > 0 else { nil }
    values
}
func scoped(_ bytes: Bytes, _ start: i32) -> Bytes {
    guard let values = scopeList(bytes, start) else { nil }
    guard let first = values.get(0) else { nil }
    guard let last = values.get(values.count - 1) else { nil }
    concatBytes(first, last, 64)
}
func scopeWindow(_ window: ScopeWindow) -> Bytes {
    scoped(window.bytes, window.start)
}
route POST "/scopes" {
    guard let first = scopeWindow(ScopeWindow(bytes: req.bodyBytes, start: 0)) else { return 400 }
    guard let second = scopeWindow(ScopeWindow(bytes: req.bodyBytes, start: 1)) else { return 400 }
    guard let body = concatBytes(first, second, 64) else { return 500 }
    return response(200, body: body)
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--library', required=True)
    parser.add_argument('--backend', choices=('epoll', 'io_uring'), required=True)
    parser.add_argument('--opt', choices=('0', '2'), required=True)
    args = parser.parse_args()
    args.real_redis = False
    def expected(data, start):
        def at(index):
            return data[index:index + 1] * 6 + data[index + 1:index + 2] * 3
        return at(start) + at(len(data) - 2)
    with gateway(args, dict(address='127.0.0.1', port=1), lambda real: PROGRAM) as request:
        for data in (b'abc', b'fedcba', b'\x00\xff\x80', b'abcdefghi'):
            assert request('scopes', data) == (200, expected(data, 0) + expected(data, 1))
        for invalid in (b'', b'x', b'xy', b'abcdefghijk'):
            assert request('scopes', invalid)[0] == 400
    print(f'Normalization scopes passed ({args.backend}, O{args.opt})')


if __name__ == '__main__':
    main()
