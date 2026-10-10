#!/usr/bin/env python3
"""Dependency-free WebSocket and chunked-stream origin/client fixtures.

Client metrics include the Python client ceiling. Compare against direct-origin
capacity before attributing differences to the gateway; this is not wrk RPS.
"""
import argparse
import ctypes
import asyncio
import base64
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import signal
import socket
import statistics
import struct
import time

GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
TABLES = [bytes(value ^ mask for value in range(256)) for mask in range(256)]
MASK_HELPER_MIN = int(os.environ.get('RUT_BENCH_WS_MASK_MIN', '4096'))
if MASK_HELPER_MIN < 0:
    raise ValueError('RUT_BENCH_WS_MASK_MIN must be nonnegative')
MASK_HELPER = None
if os.environ.get('RUT_BENCH_WS_MASK_HELPER'):
    MASK_HELPER = ctypes.CDLL(os.environ['RUT_BENCH_WS_MASK_HELPER']).rut_bench_ws_mask
    MASK_HELPER.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
    MASK_HELPER.restype = None


def masking(data, key):
    if len(key) != 4:
        raise ValueError('WebSocket mask key must have four bytes')
    output = bytearray(len(data))
    if MASK_HELPER is not None and len(data) >= MASK_HELPER_MIN:
        target = (ctypes.c_ubyte * len(data)).from_buffer(output)
        MASK_HELPER(target, data, len(data), key)
        return bytes(output)
    for offset in range(4):
        output[offset::4] = data[offset::4].translate(TABLES[key[offset]])
    return bytes(output)


def frame(data, opcode=2, masked=False, final=True):
    first = (128 if final else 0) | opcode
    flag = 128 if masked else 0
    length = len(data)
    header = bytes([first, flag | min(length, 126)]) if length < 126 else (
        bytes([first, flag | 126]) + struct.pack('!H', length) if length < 65536 else
        bytes([first, flag | 127]) + struct.pack('!Q', length))
    if masked:
        key = os.urandom(4)
        return header + key + masking(data, key)
    return header + data


async def read_frame(reader, require_mask):
    first, second = await reader.readexactly(2)
    if first & 0x70 or bool(second & 128) != require_mask:
        raise ValueError('invalid WebSocket RSV or masking')
    length = second & 127
    if length == 126:
        length = struct.unpack('!H', await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack('!Q', await reader.readexactly(8))[0]
    if length > 1048576:
        raise ValueError('oversized test frame')
    key = await reader.readexactly(4) if require_mask else None
    data = await reader.readexactly(length)
    return first & 15, bool(first & 128), masking(data, key) if key else data


async def stream_records(reader, size):
    # HTTP chunk boundaries are transport framing, not application records.
    # A proxy may legally split or coalesce them; consume incrementally so a
    # long physical chunk cannot artificially delay an already complete record.
    pending = bytearray()
    while True:
        line = await reader.readline()
        if not line.endswith(b'\r\n'):
            raise ValueError('incomplete chunk length')
        remaining = int(line.split(b';', 1)[0].strip(), 16)
        if remaining == 0:
            if await reader.readexactly(2) != b'\r\n' or pending:
                raise ValueError('invalid terminator or partial application record')
            return
        while remaining:
            take = min(remaining, size - len(pending))
            pending.extend(await reader.readexactly(take))
            remaining -= take
            if len(pending) == size:
                yield bytes(pending)
                pending.clear()
        if await reader.readexactly(2) != b'\r\n':
            raise ValueError('invalid chunk framing')


async def consume_stream(reader, size, fixed, chunks, began, measurement, deadline,
                         counts, first, delivery, gaps, source_gaps):
    sequence = 0
    previous = previous_source = None
    try:
        async with asyncio.timeout(max(0, deadline - time.monotonic())):
            async for body in stream_records(reader, size):
                ended = time.monotonic_ns()
                sent, index = struct.unpack('!QI', body[:12])
                if index != sequence or body[12:] != fixed[12:]:
                    raise ValueError('stream sequence or content mismatch')
                if ended / 1e9 >= measurement and ended / 1e9 <= deadline:
                    counts['messages'] += 1; counts['bytes'] += len(body)
                    delivery.append((ended - sent) / 1000)
                    if sequence == 0:
                        first.append((ended - began) / 1000)
                    if previous is not None:
                        gaps.append((ended - previous) / 1000)
                        source_gaps.append((sent - previous_source) / 1000)
                previous = ended; previous_source = sent; sequence += 1
    except TimeoutError:
        return True
    if sequence != chunks:
        raise ValueError('truncated stream')
    return False


def percentiles(values):
    if not values:
        return dict(p50_us=None, p95_us=None, p99_us=None, max_us=None)
    ordered = sorted(values)
    return {name: ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]
            for name, fraction in [('p50_us', .50), ('p95_us', .95), ('p99_us', .99), ('max_us', 1)]}


def origin_worker(cpu, port, size, delay_ms, chunks):
    # Forked workers must not run the parent's child-management handler.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    os.sched_setaffinity(0, {cpu})
    fixed = bytes((i * 29) & 255 for i in range(size))

    async def handle(reader, writer):
        writer.get_extra_info('socket').setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            while True:
                request = await reader.readuntil(b'\r\n\r\n')
                path = request.split(b' ', 2)[1]
                headers = {}
                for line in request.split(b'\r\n')[1:]:
                    if b':' in line:
                        key, value = line.split(b':', 1)
                        headers[key.lower()] = value.strip()
                if path == b'/ws':
                    accept = base64.b64encode(hashlib.sha1(headers[b'sec-websocket-key'] + GUID).digest())
                    writer.write(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                                 b'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n')
                    await writer.drain()
                    while True:
                        opcode, final, data = await read_frame(reader, True)
                        if opcode == 9:
                            writer.write(frame(data, 10))
                        elif opcode == 8:
                            writer.write(frame(data, 8))
                            await writer.drain()
                            return
                        elif opcode in (0, 1, 2):
                            writer.write(frame(data, opcode, final=final))
                        else:
                            raise ValueError('unsupported test opcode')
                        await writer.drain()
                elif path == b'/stream':
                    writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n'
                                 b'Transfer-Encoding: chunked\r\n\r\n')
                    for sequence in range(chunks):
                        if delay_ms:
                            await asyncio.sleep(delay_ms / 1000)
                        payload = struct.pack('!QI', time.monotonic_ns(), sequence) + fixed[12:]
                        writer.write(f'{len(payload):x}\r\n'.encode() + payload + b'\r\n')
                        await writer.drain()
                    writer.write(b'0\r\n\r\n')
                    await writer.drain()
                else:
                    raise ValueError('unknown fixture URL')
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def serve():
        server = await asyncio.start_server(handle, '127.0.0.1', port, reuse_port=True)
        print(f'PROTOCOL_READY pid={os.getpid()} cpu={cpu}', flush=True)
        async with server:
            await server.serve_forever()
    asyncio.run(serve())


async def connect_ws(port):
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    writer.get_extra_info('socket').setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    key = base64.b64encode(os.urandom(16))
    writer.write(b'GET /ws HTTP/1.1\r\nHost: fixture.example\r\nUpgrade: websocket\r\n'
                 b'Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ' + key + b'\r\n\r\n')
    await writer.drain()
    header = await reader.readuntil(b'\r\n\r\n')
    if not header.startswith(b'HTTP/1.1 101 '):
        raise ValueError('upgrade failed: ' + repr(header))
    expected = base64.b64encode(hashlib.sha1(key + GUID).digest())
    fields = {line.split(b':', 1)[0].lower(): line.split(b':', 1)[1].strip()
              for line in header.split(b'\r\n')[1:] if b':' in line}
    if fields.get(b'sec-websocket-accept') != expected:
        raise ValueError('invalid upgrade accept')
    if fields.get(b'upgrade', b'').lower() != b'websocket':
        raise ValueError('invalid upgrade header')
    connection_tokens = {token.strip().lower() for token in fields.get(b'connection', b'').split(b',')}
    if b'upgrade' not in connection_tokens:
        raise ValueError('invalid connection upgrade token')
    return reader, writer


async def ws_preflight(port):
    reader, writer = await connect_ws(port)
    writer.write(frame(b'probe', 9, True))
    await writer.drain()
    if await read_frame(reader, False) != (10, True, b'probe'):
        raise ValueError('ping/pong preflight failed')
    writer.write(frame(b'first', 2, True, False) + frame(b'second', 0, True))
    await writer.drain()
    if await read_frame(reader, False) != (2, False, b'first'):
        raise ValueError('fragment preflight failed')
    if await read_frame(reader, False) != (0, True, b'second'):
        raise ValueError('fragment continuation preflight failed')
    writer.write(frame(struct.pack('!H', 1000), 8, True))
    await writer.drain()
    if await read_frame(reader, False) != (8, True, struct.pack('!H', 1000)):
        raise ValueError('close preflight failed')
    writer.close()
    await writer.wait_closed()


def client_worker(cpu, args, output):
    os.sched_setaffinity(0, {cpu})
    cpu_started = time.process_time(); wall_started = time.monotonic()
    fixed = bytes((i * 29) & 255 for i in range(args.size))

    async def run():
        counts = dict(messages=0, bytes=0, connections=0, errors=0)
        latency = []; first = []; delivery = []; gaps = []; source_gaps = []
        deadline = time.monotonic() + args.warmup + args.duration
        measurement = deadline - args.duration

        async def session():
            reader = writer = None
            try:
                if args.kind == 'websocket':
                    reader, writer = await connect_ws(args.port)
                    counts['connections'] += 1
                    sequence = 0
                    while time.monotonic() < deadline:
                        expected = struct.pack('!Q', sequence) + fixed[8:] if len(fixed) >= 8 else fixed
                        outgoing = frame(expected, 2, True)
                        # Mask preparation remains a throughput cost, but RTT
                        # starts at socket publication, not payload construction.
                        began = time.monotonic_ns()
                        writer.write(outgoing)
                        await writer.drain()
                        try:
                            async with asyncio.timeout(max(0, deadline - time.monotonic())):
                                opcode, final, body = await read_frame(reader, False)
                        except TimeoutError:
                            break
                        if opcode != 2 or not final or body != expected:
                            raise ValueError('echo sequence or content mismatch')
                        sequence += 1
                        ended = time.monotonic_ns()
                        if began / 1e9 >= measurement and ended / 1e9 <= deadline:
                            counts['messages'] += 1; counts['bytes'] += len(body)
                            latency.append((ended - began) / 1000)
                else:
                    reader, writer = await asyncio.open_connection('127.0.0.1', args.port)
                    writer.get_extra_info('socket').setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    counts['connections'] += 1
                    while time.monotonic() < deadline:
                        began = time.monotonic_ns()
                        writer.write(b'GET /stream HTTP/1.1\r\nHost: fixture.example\r\n\r\n')
                        await writer.drain()
                        header = await reader.readuntil(b'\r\n\r\n')
                        if not header.startswith(b'HTTP/1.1 200 ') or b'transfer-encoding: chunked' not in header.lower():
                            raise ValueError('invalid chunked response: ' + repr(header))
                        await consume_stream(reader, args.size, fixed, args.chunks, began,
                                             measurement, deadline, counts, first, delivery,
                                             gaps, source_gaps)
                if args.kind == 'websocket' and time.monotonic() < deadline:
                    writer.write(frame(struct.pack('!H', 1000), 8, True))
                    await writer.drain()
                    opcode, _, _ = await read_frame(reader, False)
                    if opcode != 8:
                        raise ValueError('close handshake mismatch')
            except Exception as error:
                counts['errors'] += 1
                if counts['errors'] <= 4:
                    print('CLIENT_ERROR ' + repr(error), flush=True)
            finally:
                if writer:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except ConnectionError:
                        pass
        await asyncio.gather(*(session() for _ in range(args.connections)))
        return dict(counts=counts, rtt_us=latency, first_us=first, delivery_us=delivery,
                    gap_us=gaps, source_gap_us=source_gaps)
    sample = asyncio.run(run())
    sample['cpu_seconds'] = time.process_time() - cpu_started
    sample['observation_seconds'] = time.monotonic() - wall_started
    sample['cpu'] = cpu
    output.put(sample)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=['origin', 'client', 'preflight'])
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--cpus', default='3,4,8,9')
    parser.add_argument('--kind', choices=['websocket', 'streaming'], default='websocket')
    parser.add_argument('--size', type=int, default=64)
    parser.add_argument('--delay-ms', type=float, default=0)
    parser.add_argument('--chunks', type=int, default=16)
    parser.add_argument('--connections', type=int, default=64)
    parser.add_argument('--duration', type=int, default=8)
    parser.add_argument('--warmup', type=int, default=2)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.size < (12 if args.kind == 'streaming' else 0) or args.size > 1048576:
        parser.error('invalid payload size for protocol')
    if args.connections < 1 or args.duration < 1 or args.warmup < 0 or args.chunks < 1 or args.delay_ms < 0:
        parser.error('connections, duration and chunks must be positive; delays must be nonnegative')
    context = multiprocessing.get_context('fork')
    if args.role == 'preflight':
        if args.kind == 'websocket':
            asyncio.run(asyncio.wait_for(ws_preflight(args.port), timeout=5))
        return
    cpus = list(map(int, args.cpus.split(',')))
    if args.role == 'origin':
        children = [context.Process(target=origin_worker,
                                   args=(cpu, args.port, args.size, args.delay_ms, args.chunks)) for cpu in cpus]
        def stop(_signal=None, _frame=None):
            for child in children:
                child.terminate()
            for child in children:
                child.join(3)
            raise SystemExit(0)
        signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
        for child in children:
            child.start()
        while all(child.is_alive() for child in children):
            time.sleep(.1)
        stop()
    else:
        queue = context.Queue()
        children = [context.Process(target=client_worker, args=(cpu, args, queue)) for cpu in cpus]
        for child in children:
            child.start()
        samples = [queue.get(timeout=args.duration + args.warmup + 30) for _ in children]
        for child in children:
            child.join(5)
            if child.exitcode != 0:
                raise RuntimeError('client worker failed')
        counts = {key: sum(sample['counts'][key] for sample in samples) for key in samples[0]['counts']}
        result = dict(kind=args.kind, payload_bytes=args.size, concurrent_connections=args.connections * len(cpus),
                      duration_seconds=args.duration, **counts,
                      messages_per_second=counts['messages'] / args.duration,
                      received_mib_per_second=counts['bytes'] / args.duration / 1048576,
                      valid=counts['errors'] == 0 and counts['messages'] > 0,
                      client_workers=[dict(cpu=sample['cpu'], cpu_seconds=sample['cpu_seconds'],
                                           observation_seconds=sample['observation_seconds'],
                                           cpu_pct=100 * sample['cpu_seconds']/sample['observation_seconds']) for sample in samples])
        for metric in ['rtt_us', 'first_us', 'delivery_us', 'gap_us', 'source_gap_us']:
            result[metric] = percentiles([value for sample in samples for value in sample[metric]])
        if args.output:
            args.output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)
        if not result['valid']:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
