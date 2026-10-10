#!/usr/bin/env python3
"""Bounded HTTP/1 small-request probe with planned arrivals and verified bodies.

One outstanding request per connection. Queueing before transmission is included
in arrival latency; unissued planned requests remain visible in the result.
"""
import argparse
import asyncio
import json
import math
import time


class ResponseFailure(Exception):
    def __init__(self, kind):
        self.kind = kind
        super().__init__(kind)


async def read_response(reader, expected):
    header = await reader.readuntil(b"\r\n\r\n")
    lines = header[:-4].split(b"\r\n")
    if not lines[0].startswith(b"HTTP/1.1 200 "):
        raise ResponseFailure("status")
    fields = [line.split(b":", 1) for line in lines[1:]]
    lengths = [value.strip() for key, value in fields if key.lower() == b"content-length"]
    if len(lengths) != 1 or lengths[0] != str(len(expected)).encode():
        raise ResponseFailure("read")
    if any(key.lower() == b"transfer-encoding" for key, _ in fields):
        raise ResponseFailure("read")
    if await reader.readexactly(len(expected)) != expected:
        raise ResponseFailure("read")


def percentile(values, percent):
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * percent / 100) - 1)]


def result_is_complete(result):
    return (result["planned_requests"] > 0
            and result["issued_requests"] == result["planned_requests"]
            and result["requests"] == result["planned_requests"]
            and result["unissued_requests"] == 0 and result["unfinished_requests"] == 0
            and not any(result["errors"].values()))


async def run(args):
    errors = dict(connect=0, read=0, write=0, status=0, timeout=0)
    expected = b"Z" * args.body_size
    request = (f"GET {args.path} HTTP/1.1\r\nHost: client.example\r\n"
               "X-Payload: small\r\n\r\n").encode()
    target = int(args.rate * args.duration)
    latencies, service, lag = [], [], []
    issued = 0

    async def connect():
        try:
            return await asyncio.wait_for(asyncio.open_connection(args.host, args.port, limit=65536), 3)
        except (OSError, asyncio.TimeoutError):
            errors['connect'] += 1
            return None

    connections = await asyncio.gather(*(connect() for _ in range(args.connections)))
    started = time.perf_counter()
    end = started + args.duration

    async def worker(index, connection):
        nonlocal issued
        if connection is None:
            return
        reader, writer = connection
        try:
            for ordinal in range(index, target, args.connections):
                deadline = started + ordinal / args.rate
                remaining = deadline - time.perf_counter()
                if remaining > 0:
                    await asyncio.sleep(remaining)
                sent = time.perf_counter()
                if sent >= end:
                    break
                issued += 1
                writer.write(request)
                try:
                    await writer.drain()
                except OSError:
                    errors['write'] += 1
                    break
                try:
                    await asyncio.wait_for(read_response(reader, expected), 2)
                except ResponseFailure as error:
                    errors[error.kind] += 1
                    break
                except asyncio.TimeoutError:
                    errors['timeout'] += 1
                    break
                except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                    errors['read'] += 1
                    break
                finished = time.perf_counter()
                latencies.append((finished - deadline) * 1e6)
                service.append((finished - sent) * 1e6)
                lag.append(max(0, sent - deadline) * 1e6)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    await asyncio.gather(*(worker(i, connection) for i, connection in enumerate(connections)))
    remaining = end - time.perf_counter()
    if remaining > 0:
        await asyncio.sleep(remaining)
    count = len(latencies)
    result = dict(requests=count, seconds=args.duration, elapsed_seconds=time.perf_counter() - started,
                rps=count / args.duration, offered_rps=args.rate, planned_requests=target,
                issued_requests=issued, unissued_requests=target - issued,
                unfinished_requests=issued - count, delivered_fraction=count / target if target else 0,
                p50_us=percentile(latencies, 50), p95_us=percentile(latencies, 95),
                p99_us=percentile(latencies, 99), service_p99_us=percentile(service, 99),
                scheduling_lag_p99_us=percentile(lag, 99), errors=errors,
                latency_basis="planned arrival to response completion; one outstanding per connection")
    result["valid"] = result_is_complete(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--path', choices=('/small', '/proxy'), default='/small')
    parser.add_argument('--body-size', type=int, required=True)
    parser.add_argument('--connections', type=int, required=True)
    parser.add_argument('--rate', type=int, required=True)
    parser.add_argument('--duration', type=float, required=True)
    args = parser.parse_args()
    if not (0 < args.port < 65536 and 0 < args.body_size <= 1048576 and args.connections > 0
            and args.rate > 0 and math.isfinite(args.duration) and args.duration > 0):
        parser.error('invalid port, size, rate, connection count or duration')
    print(json.dumps(asyncio.run(run(args))), flush=True)


if __name__ == '__main__':
    main()
