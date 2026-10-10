"""Checks for evidence gating and HTTP-close handling; no Docker required."""

import contextlib
import argparse
import io
import json
import os
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import run
import matrix
import workload_strategy
import protocol_workload
import protocol_strategy
import relay_compare

from run import (
    Harness,
    connection_header,
    expected_body,
    request_bytes,
    response,
    response_head,
    origin_reuse_records,
    valid_origin_reuse,
    validate_proxy_profile,
)
from summarize import aggregate, render
from matrix import assess


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = iter(chunks)

    def sendall(self, _request):
        pass

    def recv(self, _size):
        return next(self.chunks, b"")


class ToolsTest(unittest.TestCase):
    def test_api_origin_command_and_readiness_are_forwarded(self):
        command = relay_compare.api_origin_command(
            Path("relay_compare.py"), 8704, "3,4", Path("payload.bin"), 1, 16384, .2
        )
        self.assertEqual(command[0], sys.executable)
        self.assertEqual(command[command.index("--port") + 1], "8704")
        self.assertEqual(command[command.index("--cpus") + 1], "3,4")
        self.assertEqual(command[command.index("--fragment-bytes") + 1], "16384")
        class ReadyProcess:
            def poll(self):
                return None

        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "origin.log"
            log.write_text("noise\nAPI_READY worker=0\nAPI_READY worker=1\n")
            relay_compare.wait_for_api_origin_ready(log, ReadyProcess(), 2)

    def test_direct_origin_targets_origin_port(self):
        args = SimpleNamespace(origin_port=8704, front_port=8604)
        self.assertEqual(relay_compare.direct_origin_port(args), 8704)

    def test_api_origin_fresh_close_accepts_valid_pooled_or_distinct_markers(self):
        markers = ["close-0", "close-1"]
        fresh = [(markers[0], 10, 1), (markers[1], 11, 1)]
        pooled = [(markers[0], 10, 1), (markers[1], 10, 2)]
        self.assertTrue(relay_compare.valid_api_origin_records(fresh, markers, True))
        self.assertTrue(relay_compare.valid_api_origin_records(pooled, markers, True))
        self.assertTrue(relay_compare.valid_api_origin_records(pooled, markers, False))
        self.assertFalse(relay_compare.valid_api_origin_records(pooled[:1], markers, True))
        self.assertFalse(relay_compare.valid_api_origin_records([pooled[1], pooled[0]], markers, True))

    def test_stream_deadline_allows_inflight_timeout_but_rejects_truncation(self):
        fixed = bytes((i * 29) & 255 for i in range(16))

        async def consume(raw, chunks, deadline):
            reader = protocol_workload.asyncio.StreamReader()
            if raw is not None:
                reader.feed_data(raw)
            if deadline == float("inf"):
                reader.feed_eof()
            counts = dict(messages=0, bytes=0)
            values = ([], [], [], [])
            return await protocol_workload.consume_stream(
                reader, 16, fixed, chunks, time.monotonic(), 0,
                deadline, counts, *values
            )

        complete = b"10\r\n" + struct.pack("!QI", 1, 0) + fixed[12:] + b"\r\n0\r\n\r\n"
        self.assertFalse(protocol_workload.asyncio.run(consume(complete, 1, float("inf"))))
        with self.assertRaisesRegex(ValueError, "invalid terminator"):
            protocol_workload.asyncio.run(consume(b"1\r\na\r\n0\r\n\r\n", 1, float("inf")))
        self.assertTrue(protocol_workload.asyncio.run(consume(None, 1, time.monotonic() + .01)))

    def test_client_connection_failure_cancels_other_startup_attempts(self):
        entered = 0
        cancelled = []

        async def open_connection(_host, _port):
            nonlocal entered
            entered += 1
            if entered == 2:
                raise ConnectionError('injected handshake failure')
            try:
                while entered < 2:
                    await protocol_workload.asyncio.sleep(0)
                await protocol_workload.asyncio.Event().wait()
            except protocol_workload.asyncio.CancelledError:
                cancelled.append(True)
                raise

        class Output:
            sample = None

            def put(self, value):
                self.sample = value

        output = Output()
        args = SimpleNamespace(kind='streaming', size=16, warmup=0, duration=1,
                               connections=2, port=12345, chunks=1)
        cpu = min(os.sched_getaffinity(0))
        with mock.patch.object(protocol_workload.asyncio, 'open_connection', open_connection):
            protocol_workload.client_worker(cpu, args, output)
        self.assertEqual(output.sample['counts']['errors'], 1)
        self.assertEqual(output.sample['counts']['connections'], 0)
        self.assertEqual(cancelled, [True])

    def test_smoke_engine_filter_rejects_empty_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(Path(protocol_strategy.__file__)),
                 "--output", directory, "--rut", "/bin/true",
                 "--harness", str(Path(run.__file__)), "--smoke", "--engines", "nginx"],
                capture_output=True, text=True
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("select no runnable configurations", result.stderr)

    def test_protocol_cli_rejects_incompatible_cases_and_short_non_smoke(self):
        with tempfile.TemporaryDirectory() as directory:
            base = [sys.executable, str(Path(protocol_strategy.__file__)),
                    "--output", directory, "--rut", "/bin/true",
                    "--harness", str(Path(run.__file__))]
            incompatible = subprocess.run(base + ["--tcpkali2", "/bin/true"], capture_output=True, text=True)
            short = subprocess.run(base + ["--repeats", "2"], capture_output=True, text=True)
        self.assertEqual(incompatible.returncode, 2)
        self.assertIn("WebSocket-only", incompatible.stderr)
        self.assertEqual(short.returncode, 2)
        self.assertIn("at least three repeats", short.stderr)

    def test_protocol_cli_rejects_nonpositive_duration_before_output_or_process(self):
        for duration in ('0', '-1'):
            with self.subTest(duration=duration), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'study'
                argv = ['protocol_strategy.py', '--output', str(output), '--rut', '/bin/true',
                        '--harness', str(Path(run.__file__)), '--duration', duration]
                with mock.patch.object(sys, 'argv', argv), \
                        mock.patch.object(protocol_strategy.subprocess, 'Popen') as launch:
                    with self.assertRaises(SystemExit) as raised:
                        protocol_strategy.main()
                self.assertEqual(raised.exception.code, 2)
                self.assertFalse(output.exists())
                launch.assert_not_called()

    def test_workload_cli_rejects_nonpositive_durations_before_output_or_process(self):
        for flag in ('--screen-seconds', '--confirm-seconds'):
            for duration in ('0', '-1'):
                with self.subTest(flag=flag, duration=duration), tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / 'study'
                    argv = ['workload_strategy.py', '--output', str(output),
                            '--relay-script', str(Path(relay_compare.__file__)),
                            '--rut', '/bin/true', '--converter', '/bin/true', '--wrk', '/bin/true',
                            flag, duration]
                    with mock.patch.object(sys, 'argv', argv), \
                            mock.patch.object(workload_strategy.subprocess, 'Popen') as launch:
                        with self.assertRaises(SystemExit) as raised:
                            workload_strategy.main()
                    self.assertEqual(raised.exception.code, 2)
                    self.assertFalse(output.exists())
                    launch.assert_not_called()

    def test_workload_cli_keeps_positive_duration_values_valid(self):
        class ReachedOutputSetup(Exception):
            pass

        with tempfile.TemporaryDirectory() as directory:
            argv = ['workload_strategy.py', '--output', str(Path(directory) / 'study'),
                    '--relay-script', str(Path(relay_compare.__file__)),
                    '--rut', '/bin/true', '--converter', '/bin/true', '--wrk', '/bin/true',
                    '--screen-seconds', '1', '--confirm-seconds', '1']
            with mock.patch.object(sys, 'argv', argv), \
                    mock.patch.object(Path, 'mkdir', side_effect=ReachedOutputSetup), \
                    mock.patch.object(workload_strategy.subprocess, 'Popen') as launch:
                with self.assertRaises(ReachedOutputSetup):
                    workload_strategy.main()
            launch.assert_not_called()

    def test_protocol_manifest_records_selection_filters(self):
        args = SimpleNamespace(cases=["websocket-bulk-64k", "websocket-interactive-64"],
                               engines=["nginx"], policies=["current"], smoke=True)
        self.assertEqual(protocol_strategy.selection_manifest(args), {
            "cases_filter": ["websocket-bulk-64k", "websocket-interactive-64"],
            "engines_filter": ["nginx"], "policies_filter": ["current"], "smoke": True,
        })

    def test_study_environment_clears_all_runtime_knobs(self):
        clean = workload_strategy.study_environment({
            "DOCKER_HOST": "tcp://unused", "RUT_STUDY_POLICY": "latency",
            "RUT_STUDY_DIRECT_BODY_SEND": "on", "RUT_STUDY_SELECTIVE_VECTOR": "on",
            "PATH": "/bin",
        })
        self.assertNotIn("DOCKER_HOST", clean)
        self.assertFalse(any(key.startswith("RUT_STUDY_") for key in clean))
        self.assertEqual(clean["PATH"], "/bin")

    def test_protocol_environment_clears_unselected_runtime_knobs(self):
        env = protocol_strategy.protocol_environment({
            "RUT_STUDY_WS_RECV": "once", "RUT_STUDY_DIRECT_BODY_SEND": "on",
            "RUT_STUDY_SELECTIVE_VECTOR": "on", "PATH": "/bin"})
        self.assertEqual(env["RUT_STUDY_WS_RECV"], "once")
        self.assertNotIn("RUT_STUDY_DIRECT_BODY_SEND", env)
        self.assertNotIn("RUT_STUDY_SELECTIVE_VECTOR", env)

    def test_protocol_manifest_hashes_strategy_and_harness(self):
        with tempfile.NamedTemporaryFile() as harness:
            harness.write(b"harness-v1")
            harness.flush()
            hashes = protocol_strategy.manifest_script_hashes(SimpleNamespace(
                harness=Path(harness.name)))
        self.assertEqual(hashes["harness_sha256"],
                         __import__("hashlib").sha256(b"harness-v1").hexdigest())
        self.assertEqual(hashes["protocol_strategy_sha256"],
                         __import__("hashlib").sha256(Path(protocol_strategy.__file__).read_bytes()).hexdigest())

    def test_direct_origin_cpu_observation_is_absent(self):
        self.assertIsNone(protocol_strategy.frontend_cpu_observation("direct-origin", 1, 3, 1))
        self.assertEqual(protocol_strategy.frontend_cpu_observation("uring", 1, 3, 1), 200)
        self.assertIsNone(run.server_cpu_observation("direct-origin", 1, 3, 1))
        self.assertEqual(run.server_cpu_observation("uring", 1, 3, 1), 200)
        self.assertEqual(workload_strategy.format_cpu(None), "n/a")
        self.assertEqual(workload_strategy.format_cpu(12.345), "12.3")

    def test_protocol_summary_labels_full_cpu_observation(self):
        case = protocol_strategy.CASES[0]
        rows = [dict(case=case, engine="nginx", policy="current", messages_per_second=100,
                     received_mib_per_second=1, rtt_us=dict(p99_us=10),
                     origin_cpu_observation_pct=12, frontend_cpu_observation_pct=34)
                for _ in range(3)]
        summary = protocol_strategy.summarize(rows)[0]
        self.assertEqual(summary["origin_cpu_observation_pct"], 12)
        self.assertEqual(summary["frontend_cpu_observation_pct"], 34)
        self.assertNotIn("origin_cpu_pct", summary)
        self.assertNotIn("frontend_cpu_pct", summary)
        self.assertNotIn("cpu_measurement_seconds", summary)

    def test_protocol_summary_keeps_missing_first_chunk_percentile_out_of_selection(self):
        case = next(case for case in protocol_strategy.CASES
                    if case['name'] == 'streaming-live-256')
        rows = []
        for policy in ('current', 'latency', 'balanced'):
            for repeat in range(3):
                rows.append(dict(case=case, engine='uring', policy=policy,
                                 messages_per_second=100, received_mib_per_second=1,
                                 delivery_us=dict(p99_us=100),
                                 first_us=dict(p99_us=5 if policy == 'current' and repeat != 1 else None),
                                 source_gap_us=dict(p99_us=20),
                                 origin_cpu_observation_pct=10))
        summaries = protocol_strategy.summarize(rows)
        self.assertTrue(all(row['first_p99_us'] is None for row in summaries))
        current = next(row for row in summaries if row['policy'] == 'current')
        self.assertEqual(current['throughput_policy'], 'current')

    def test_run_client_cleans_group_when_wait_is_interrupted(self):
        class Child:
            pid = 12345

            def __init__(self):
                self.waits = [KeyboardInterrupt(), 0, 0]

            def wait(self, timeout=None):
                result = self.waits.pop(0)
                if isinstance(result, BaseException):
                    raise result
                return result

        child = Child()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(protocol_strategy.subprocess, 'Popen', return_value=child), \
                mock.patch.object(protocol_strategy.os, 'killpg') as killpg:
            with self.assertRaises(KeyboardInterrupt):
                protocol_strategy.run_client(['client'], Path(directory) / 'client.log', 1, {})
        self.assertEqual([call.args[1] for call in killpg.call_args_list],
                         [protocol_strategy.signal.SIGTERM, protocol_strategy.signal.SIGKILL])

    def test_strategy_requires_repeats_and_guards_tail_latency(self):
        rows = []
        for policy, rate, tail in [('current', 100, 100), ('throughput', 150, 130),
                                   ('balanced', 120, 105), ('latency', 90, 70)]:
            for repeat in range(3):
                rows.append(dict(stage='confirm', workload_profile={'name': 'static-1m'},
                                 engine='uring', policy=policy, rps=rate, p99_us=tail,
                                 server_cpu_pct=100, origin_cpu_pct=100))
        result = workload_strategy.summarize(rows, .10)['decisions'][0]
        self.assertEqual(result['throughput_policy'], 'balanced')
        self.assertEqual(result['latency_policy'], 'latency')
        self.assertEqual(workload_strategy.summarize(rows[:2], .10)['decisions'], [])

    def test_workload_manifest_rejects_resume_after_imported_harness_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relay = root / 'relay_compare.py'
            for name in ('relay_compare.py', 'api_origin.py', 'run.py'):
                (root / name).write_text(name + '-v1')
            first = dict(scripts=workload_strategy.script_hashes(relay))
            prior = root / 'study.json'
            workload_strategy.require_matching_manifest(prior, first)
            run_script = root / 'run.py'
            run_script.write_text('run.py-v2')
            resumed = dict(scripts=workload_strategy.script_hashes(relay))
            self.assertNotEqual(first, resumed)
            with self.assertRaisesRegex(RuntimeError, 'manifest changed'):
                workload_strategy.require_matching_manifest(prior, resumed)

        hashes = workload_strategy.script_hashes(Path(workload_strategy.__file__).with_name('relay_compare.py'))
        self.assertIn(str(Path(run.__file__).resolve()), hashes)
        self.assertIn(str(Path(workload_strategy.__file__).resolve()), hashes)

    def test_streaming_latency_policy_bounds_first_chunk_before_delivery_tail(self):
        case = next(case for case in protocol_strategy.CASES
                    if case['name'] == 'streaming-live-256')
        rows = []
        for policy, delivery, first in (('current', 100, 100),
                                        ('latency', 60, 200),
                                        ('balanced', 80, None)):
            for _ in range(3):
                rows.append(dict(case=case, engine='uring', policy=policy,
                                 messages_per_second=100, received_mib_per_second=1,
                                 delivery_us=dict(p99_us=delivery),
                                 first_us=dict(p99_us=first),
                                 source_gap_us=dict(p99_us=20),
                                 origin_cpu_observation_pct=10))
        current = next(row for row in protocol_strategy.summarize(rows)
                       if row['policy'] == 'current')
        self.assertEqual(current['experimental_latency_candidate'], 'current')
        self.assertEqual(current['latency_policy'], 'current')

    def test_mixed_throughput_weights_bytes_instead_of_request_count(self):
        current = dict(rps=10100, large_client={'rps': 100}, small_client={'rps': 10000})
        more_small = dict(rps=20040, large_client={'rps': 40}, small_client={'rps': 20000})
        self.assertLess(current['rps'], more_small['rps'])
        self.assertGreater(workload_strategy.throughput_score(current),
                           workload_strategy.throughput_score(more_small))

    def test_mixed_strategy_guards_small_client_tail(self):
        row = {'p99_us': 50000, 'small_client': {'p99_us': 200}}
        self.assertEqual(workload_strategy.metric(row), 200)

    def test_stream_records_ignore_http_chunk_boundaries(self):
        expected = [b'abcdefgh', b'ijklmnop', b'qrstuvwx']
        for physical in [[b''.join(expected)], [b'ab', b'cdefghijk', b'lmnopqrs', b'tuvwx']]:
            raw = b''.join(f'{len(part):x}\r\n'.encode() + part + b'\r\n' for part in physical) + b'0\r\n\r\n'
            async def decode():
                reader = protocol_workload.asyncio.StreamReader()
                reader.feed_data(raw)
                reader.feed_eof()
                return [record async for record in protocol_workload.stream_records(reader, 8)]
            self.assertEqual(protocol_workload.asyncio.run(decode()), expected)

    def test_websocket_masking_and_extended_lengths(self):
        for size in [0, 64, 125, 126, 65535, 65536]:
            data = bytes((i * 29) & 255 for i in range(size))
            key = b'\x00\x11\x80\xff'
            self.assertEqual(protocol_workload.masking(protocol_workload.masking(data, key), key), data)
            raw = protocol_workload.frame(data, masked=True)
            async def decode():
                reader = protocol_workload.asyncio.StreamReader()
                reader.feed_data(raw)
                reader.feed_eof()
                return await protocol_workload.read_frame(reader, True)
            self.assertEqual(protocol_workload.asyncio.run(decode()), (2, True, data))

    def test_native_streaming_payload_and_reuse_evidence_reject_corruption(self):
        wanted = expected_body("proxy", native_streaming=True)
        self.assertEqual(len(wanted), 256 * 1024)
        self.assertNotEqual(wanted[:4096], wanted[4096:8192])
        head = (b"HTTP/1.1 200 OK\r\nContent-Length: 262144\r\n"
                b"Content-Type: application/octet-stream\r\n\r\n")
        raw, closed = response(
            FakeSocket([head, wanted]), "proxy", False,
            keepalive_header="implicit", native_streaming=True,
        )
        self.assertFalse(closed)
        self.assertTrue(raw.endswith(wanted))
        with self.assertRaisesRegex(ValueError, "complete body"):
            response(FakeSocket([head, wanted[:-1]]), "proxy", False,
                     keepalive_header="implicit", native_streaming=True)
        reordered = wanted[4096:8192] + wanted[:4096] + wanted[8192:]
        with self.assertRaisesRegex(ValueError, "unexpected body"):
            response(FakeSocket([head, reordered]), "proxy", False,
                     keepalive_header="implicit", native_streaming=True)
        with self.assertRaisesRegex(ValueError, "bounded Content-Length"):
            response(FakeSocket([b"HTTP/1.1 200 OK\r\nContent-Length: 262143\r\n"
                                 b"Content-Type: application/octet-stream\r\n"
                                 b"Transfer-Encoding: chunked\r\n\r\n", wanted]),
                     "proxy", False, keepalive_header="implicit", native_streaming=True)
        with self.assertRaisesRegex(ValueError, "unexpected body"):
            response(FakeSocket([b"HTTP/1.1 200 OK\r\nContent-Length: 262143\r\n"
                                 b"Content-Type: application/octet-stream\r\n\r\n", wanted]),
                     "proxy", False, keepalive_header="implicit", native_streaming=True)
        with self.assertRaisesRegex(ValueError, "Content-Type"):
            response(FakeSocket([b"HTTP/1.1 200 OK\r\nContent-Length: 262144\r\n"
                                 b"Content-Type: text/plain\r\n\r\n", wanted]),
                     "proxy", False, keepalive_header="implicit", native_streaming=True)
        for duplicated in (
            b"HTTP/1.1 200 OK\r\nContent-Length: 262144\r\nContent-Length: 262144\r\n"
            b"Content-Type: application/octet-stream\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 262144\r\n"
            b"Content-Type: application/octet-stream\r\nContent-Type: application/octet-stream\r\n\r\n",
        ):
            with self.subTest(duplicated=duplicated), self.assertRaisesRegex(ValueError, "duplicate header"):
                response(FakeSocket([duplicated, wanted]), "proxy", False,
                         keepalive_header="implicit", native_streaming=True)
        with self.assertRaisesRegex(ValueError, "keepalive semantics"):
            response(FakeSocket([b"HTTP/1.1 200 OK\r\nContent-Length: 262144\r\n"
                                 b"Content-Type: application/octet-stream\r\n"
                                 b"Connection: close\r\n\r\n", wanted]),
                     "proxy", False, keepalive_header="implicit", native_streaming=True)

        markers = [f"sample-r1-nginx-keepalive-{n}" for n in range(3)]
        complete = "\n".join(
            f"marker={marker_prefix} connection=91 requests={i + 8}"
            for i, marker_prefix in enumerate(markers)
        )
        rows = origin_reuse_records(complete, markers)
        self.assertEqual(len(rows), 3)
        self.assertEqual(len({row[1] for row in rows}), 1)
        self.assertTrue(valid_origin_reuse(rows, markers))
        reconnect = complete.replace("connection=91 requests=9", "connection=92 requests=1")
        self.assertFalse(valid_origin_reuse(origin_reuse_records(reconnect, markers), markers))
        out_of_order = complete.replace("requests=9", "requests=11").replace("requests=10", "requests=9")
        self.assertFalse(valid_origin_reuse(origin_reuse_records(out_of_order, markers), markers))
        missing = "\n".join(complete.splitlines()[:-1])
        self.assertFalse(valid_origin_reuse(origin_reuse_records(missing, markers), markers))

    def test_bounded_origin_reuse_rejects_unsupported_profiles_and_transport(self):
        baseline = dict(proxy_profile="converter-bounded", bounded_origin_reuse="on",
                        tls_cert=None, scenarios=["proxy-close", "proxy-keepalive"])
        validate_proxy_profile(argparse.ArgumentParser(), SimpleNamespace(**baseline))
        for change in ({"proxy_profile": "converter-strict"}, {"tls_cert": Path("cert.pem")},
                       {"scenarios": ["static-close"]}):
            with self.assertRaises(SystemExit):
                validate_proxy_profile(argparse.ArgumentParser(), SimpleNamespace(**(baseline | change)))

    def test_native_streaming_profile_rejects_unsupported_matrix_shapes(self):
        parser = argparse.ArgumentParser()
        baseline = dict(proxy_profile="native-streaming", body_size=None,
                        scenarios=["proxy-keepalive"], concurrency=[1, 32],
                        keepalive_header="implicit")
        args = SimpleNamespace(**baseline)
        validate_proxy_profile(parser, args)
        self.assertEqual(args.body_size, 256 * 1024)
        single = SimpleNamespace(**(baseline | {"concurrency": [32]}))
        validate_proxy_profile(parser, single)
        self.assertEqual(single.body_size, 256 * 1024)
        large = SimpleNamespace(**(baseline | {"body_size": 1048576,
                                "scenarios": ["proxy-close", "proxy-keepalive"],
                                "concurrency": [1, 128]}))
        validate_proxy_profile(parser, large)
        self.assertEqual(large.body_size, 1048576)
        for key, value in (("scenarios", ["static-close"]),
                           ("concurrency", [8]),
                           ("concurrency", []),
                           ("body_size", 1048577),
                           ("keepalive_header", "explicit")):
            with self.subTest(key=key), self.assertRaises(SystemExit):
                validate_proxy_profile(parser, SimpleNamespace(**(baseline | {key: value})))

    def test_large_native_close_checks_tail_content_and_transport_eof(self):
        wanted = expected_body("proxy", 1048576, native_streaming=True)
        head = (b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n"
                b"Content-Type: application/octet-stream\r\nConnection: close\r\n\r\n")
        raw, closed = response(FakeSocket([head, wanted]), "proxy", True,
                               body_size=1048576, native_streaming=True)
        self.assertTrue(closed)
        self.assertTrue(raw.endswith(wanted))
        damaged = wanted[:900000] + bytes([wanted[900000] ^ 1]) + wanted[900001:]
        with self.assertRaisesRegex(ValueError, "unexpected body"):
            response(FakeSocket([head, damaged]), "proxy", True,
                     body_size=1048576, native_streaming=True)
        with self.assertRaisesRegex(ValueError, "expected EOF"):
            response(FakeSocket([head, wanted, b"surplus"]), "proxy", True,
                     body_size=1048576, native_streaming=True)

    def test_default_proxy_profile_leaves_arguments_unchanged(self):
        args = SimpleNamespace(proxy_profile="converter-strict", body_size=None,
                               scenarios=["proxy-close"], concurrency=[1],
                               keepalive_header="explicit")
        validate_proxy_profile(argparse.ArgumentParser(), args)
        self.assertIsNone(args.body_size)

    def test_worker_evidence_is_topology_specific_and_bool_is_not_worker_count(self):
        rows = []
        for engine in ("nginx", "rut"):
            for rep in (1, 2, 3):
                rows.append({
                    "workload": "static", "connection": "close", "transport": "http",
                    "body_size": 16, "concurrency": 1, "engine": engine, "rep": rep,
                    "requests": 100, "rps": 100.0, "seconds": 5.0, "valid": True,
                    "errors": dict.fromkeys(run.ERROR_NAMES, 0),
                    "warmup_errors": dict.fromkeys(run.ERROR_NAMES, 0),
                    "workers": 2, "server_cpus": "2,3",
                })
        self.assertTrue(assess(rows, "static-close", "http", 16, 1, 3, 5,
                               workers=2, server_cpus="2,3")["measurement_valid"])
        mixed_topology = [dict(row) for row in rows]
        mixed_topology[0]["server_cpus"] = "2,4"
        for altered in (rows[:-1], [dict(row, workers=True) for row in rows], mixed_topology):
            self.assertFalse(assess(altered, "static-close", "http", 16, 1, 3, 5,
                                    workers=2, server_cpus="2,3")["measurement_valid"])
        legacy = [dict(row) for row in rows]
        for row in legacy:
            row.pop("workers")
            row.pop("server_cpus")
        self.assertTrue(assess(legacy, "static-close", "http", 16, 1, 3, 5)["measurement_valid"])
        self.assertFalse(assess(legacy, "static-close", "http", 16, 1, 3, 5,
                                workers=2, server_cpus="2,3")["measurement_valid"])

    def test_two_worker_frontend_config_and_legacy_default(self):
        self.assertIn("worker_processes 2;", Harness.nginx_config("server {};", workers=2))
        self.assertEqual(
            Harness.nginx_config("server {};").encode(),
            b"worker_processes 1;\nerror_log /dev/stderr warn;\npid /tmp/nginx.pid;\n"
            b"events { worker_connections 8192; }\nhttp { access_log off;\nserver {};\n}\n",
        )

    def test_worker_cpu_arguments_are_mutually_exclusive_and_normalized(self):
        parser = argparse.ArgumentParser()
        run.add_cpu_arguments(parser)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["--server-cpu=2", "--server-cpus=2", "--origin-cpu=3",
                               "--client-cpus=4"])
        args = SimpleNamespace(server_cpu=None, server_cpus="02, 03", workers=2)
        run.normalize_cpu_arguments(parser, args)
        self.assertEqual(args.server_cpus, "2,3")
        for mask, workers in (("2,02", 2), ("2,,3", 2), ("2,3", 1),
                              ("2,3,4", 4), ("2,3", True)):
            with self.subTest(mask=mask, workers=workers), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                run.normalize_cpu_arguments(parser, SimpleNamespace(
                    server_cpu=None, server_cpus=mask, workers=workers))

    def test_matrix_normalizes_and_forwards_worker_topology_before_child(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "matrix"
            argv = ["matrix.py", "--output", str(output), "--tls-cert", "unused.pem",
                    "--tls-key", "unused.key", "--transports", "http", "--body-sizes", "16",
                    "--scenarios", "static-close", "--concurrency", "1", "--profile", "quick",
                    "--server-cpus=02, 03", "--workers", "2", "--origin-cpu", "4",
                    "--client-cpus", "5,6"]
            previous_sigterm = signal.getsignal(signal.SIGTERM)
            try:
                with mock.patch.object(sys, "argv", argv), \
                        mock.patch.object(matrix, "validate_cpu_topology"), \
                        mock.patch.object(matrix, "run_cell", return_value=2) as child, \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(matrix.main(), 2)
            finally:
                signal.signal(signal.SIGTERM, previous_sigterm)
            command = child.call_args.args[0]
            self.assertEqual(command[command.index("--server-cpus") + 1], "2,3")
            self.assertEqual(command[command.index("--workers") + 1], "2")
            report = json.loads((output / "matrix.json").read_text())
            self.assertEqual(report["server_cpus"], "2,3")
            self.assertEqual(report["workers"], 2)
            invalid_output = Path(directory) / "invalid"
            invalid_argv = ["matrix.py", "--output", str(invalid_output), "--tls-cert", "unused.pem",
                            "--tls-key", "unused.key", "--transports", "http", "--body-sizes", "16",
                            "--scenarios", "static-close", "--concurrency", "1",
                            "--server-cpus=2,3", "--workers", "1", "--origin-cpu", "4",
                            "--client-cpus", "5,6"]
            try:
                with mock.patch.object(sys, "argv", invalid_argv), \
                        mock.patch.object(matrix, "run_cell") as invalid_child, \
                        contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    matrix.main()
            finally:
                signal.signal(signal.SIGTERM, previous_sigterm)
            invalid_child.assert_not_called()
            self.assertFalse(invalid_output.exists())

    def test_rut_frontend_uses_matching_legacy_and_multiworker_affinity(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            rut = out / "rut"
            rut.touch()
            for workers, mask in ((1, "2"), (2, "2,6")):
                args = SimpleNamespace(output=out, rut=rut, server_cpus=mask,
                                       workers=workers, front_port=8087,
                                       tls_cert=None, tls_key=None)
                harness = Harness(args)
                proc = mock.Mock()
                proc.poll.return_value = None
                with mock.patch.object(run.subprocess, "Popen", return_value=proc) as popen, \
                        mock.patch.object(harness, "ready"), \
                        mock.patch.object(harness, "rut_shards_ready") as shards_ready, \
                        harness.frontend("rut", "proxy", f"case-{workers}"):
                    pass
                shards_ready.assert_called_once_with(
                    out / f"case-{workers}-server.log", proc.pid, workers)
                argv = popen.call_args.args[0]
                self.assertEqual(argv[0:3], ["taskset", "-c", mask])
                self.assertEqual(argv[argv.index("--shards") + 1], str(workers))
                self.assertIn("--no-pin", argv)
                if workers == 1:
                    self.assertEqual(argv, ["taskset", "-c", "2", str(rut),
                                            str(out / "proxy.rut"), "--shards", "1",
                                            "--no-pin", "--drain", "1", "--opt", "2"])

    def test_rut_shard_count_comes_from_the_selected_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "server.log"
            pid = os.getpid()
            log.write_text("TLS: enabled\nListening on port 8087 with 2 shard(s)\n")
            Harness.rut_shards_ready(log, pid, 2)
            # A binary with a smaller compiled cap clamps --shards silently.
            log.write_text("Listening on port 8087 with 1 shard(s)\n")
            with self.assertRaisesRegex(RuntimeError, "started 1 shard"):
                Harness.rut_shards_ready(log, pid, 2)
            log.write_text("")
            with mock.patch.object(run.Path, "exists", return_value=False), \
                    self.assertRaisesRegex(RuntimeError, "exited before reporting"):
                Harness.rut_shards_ready(log, pid, 2)

    def test_nginx_container_uses_complete_server_mask(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            harness = Harness(SimpleNamespace(output=out, tls_cert=None, tls_key=None))
            harness.image = "mock-image"
            calls = []

            def fake_command(argv, timeout=20):
                calls.append(argv)
                stdout = ("container-id" if argv[1] == "create" else
                          "123" if argv[:2] == ["docker", "inspect"] else "")
                return subprocess.CompletedProcess(argv, 0, stdout, "")

            with mock.patch.object(harness, "command", side_effect=fake_command), \
                    mock.patch.object(harness, "ready"), \
                    harness.nginx("frontend", "frontend.conf", "2,6", 8087):
                pass
            create = calls[0]
            self.assertEqual(create[create.index("--cpuset-cpus") + 1], "2,6")

    def test_prepare_applies_frontend_workers_in_all_profiles_and_origin_stays_single(self):
        cases = (("converter", "converter-return", "converter-strict", ["proxy-close"], "proxy"),
                 ("bounded", "converter-return", "converter-bounded", ["proxy-close"], "proxy"),
                 ("bounded-reuse", "converter-return", "converter-bounded", ["proxy-close"], "proxy"),
                 ("native-body", "native-body", "converter-strict", ["static-close"], "static"),
                 ("native-streaming", "converter-return", "native-streaming",
                  ["proxy-keepalive"], "proxy"))
        for name, static_profile, proxy_profile, scenarios, work in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                binaries = {}
                for binary in ("rut", "converter", "wrk"):
                    path = out / binary
                    path.write_text("mock executable\n")
                    path.chmod(0o755)
                    binaries[binary] = path
                args = SimpleNamespace(
                    output=out, rut=binaries["rut"], converter=binaries["converter"],
                    wrk=binaries["wrk"], tls_cert=None, tls_key=None, body_size=None,
                    mode="benchmark", server_cpu=2, server_cpus="2,6", workers=2,
                    origin_cpu=3, client_cpus="4,5", keepalive_header="implicit",
                    front_port=8087, origin_port=9087, scenarios=scenarios, repeats=1,
                    first_engine="nginx", static_profile=static_profile,
                    proxy_profile=proxy_profile,
                    bounded_origin_reuse="on" if name == "bounded-reuse" else "off",
                )
                harness = Harness(args)

                def fake_command(argv, timeout=20):
                    command = [str(value) for value in argv]
                    if command == ["docker", "context", "inspect"]:
                        stdout = '[{"Endpoints":{"docker":{"Host":"unix:///mock.sock"}}}]'
                    elif command[:2] == ["docker", "info"]:
                        stdout = "mock docker"
                    elif command[:3] == ["docker", "image", "inspect"]:
                        stdout = '[{"Id":"mock-image"}]'
                    elif command[0] == "git":
                        stdout = "" if "status" in command else "mock-head"
                    elif command == ["lscpu"]:
                        stdout = "mock topology"
                    elif command[0] == str(binaries["converter"]):
                        stdout = f"listen 127.0.0.1:{args.front_port}\nresponse_buffering: .completeContentLength\n"
                    else:
                        raise AssertionError(f"unexpected command {argv!r}")
                    return subprocess.CompletedProcess(argv, 0, stdout, "")

                with mock.patch.object(harness, "command", side_effect=fake_command):
                    harness.prepare()
                frontend = out / f"{work}-nginx.conf"
                self.assertIn("worker_processes 2;", frontend.read_text())
                self.assertIn("worker_processes 1;", (out / "origin.conf").read_text())
                if name == "bounded-reuse":
                    self.assertIn("keepalive_timeout 60;", (out / "origin.conf").read_text())
                    self.assertIn("rut_preflight", (out / "origin.conf").read_text())
                    self.assertIn('proxy_set_header Connection "";', frontend.read_text())
                if proxy_profile == "converter-bounded":
                    self.assertIn("response_buffering: .bounded", (out / "proxy.rut").read_text())
                    self.assertIn("response_buffering: .completeContentLength",
                                  (out / "proxy.converted.rut").read_text())


    def test_matrix_profiles_forward_budget_without_dropping_coordinates(self):
        cases = (([], (5, 1, 3)),
                 (["--profile", "quick"], (2, 1, 1)),
                 (["--profile", "full"], (10, 2, 3)),
                 (["--duration", "5", "--warmup", "3", "--repeats", "4"], (5, 3, 4)))
        for flags, expected in cases:
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "matrix"
                argv = ["matrix.py", "--output", str(output),
                        "--tls-cert", "unused.pem", "--tls-key", "unused.key",
                        "--server-cpu", "2", "--origin-cpu", "3", "--client-cpus", "4,5", *flags]
                previous_sigterm = signal.getsignal(signal.SIGTERM)
                try:
                    with mock.patch.object(sys, "argv", argv), \
                            mock.patch.object(matrix, "validate_cpu_topology"), \
                            mock.patch.object(matrix, "run_cell", return_value=2) as child, \
                            contextlib.redirect_stdout(io.StringIO()) as stdout:
                        self.assertEqual(matrix.main(), 2)
                finally:
                    signal.signal(signal.SIGTERM, previous_sigterm)
                self.assertEqual(child.call_count, 32)
                for call in child.call_args_list:
                    command = call.args[0]
                    self.assertEqual(tuple(int(command[command.index(flag) + 1])
                                           for flag in ("--duration", "--warmup", "--repeats")),
                                     expected)
                report = json.loads((output / "matrix.json").read_text())
                self.assertEqual(len(report["cells"]), 96)
                self.assertFalse(report["target_met"])
                duration, warmup, repeats = expected
                self.assertIn(f"load budget {96 * 2 * repeats * (warmup + duration)}s",
                              stdout.getvalue())

    def test_matrix_keeps_valid_groups_only_after_completed_child(self):
        cases = (
            # One failed concurrency must not erase its valid siblings.
            (1, True, True, [True, True, False], 2),
            (0, True, False, [True, True, True], 0),
            # Setup errors, signals and missing/incomplete completion evidence
            # invalidate all groups even if results.json already has good rows.
            (2, True, False, [False, False, False], 2),
            (-signal.SIGTERM, True, False, [False, False, False], 2),
            (1, False, False, [False, False, False], 2),
            (1, None, False, [False, False, False], 2),
            (0, False, False, [False, False, False], 2),
        )
        for returncode, complete, bad_sample, expected, expected_exit in cases:
            with self.subTest(returncode=returncode, complete=complete, bad_sample=bad_sample), \
                    tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "matrix"
                argv = ["matrix.py", "--output", str(output),
                        "--tls-cert", "unused.pem", "--tls-key", "unused.key",
                        "--server-cpu", "2", "--origin-cpu", "3", "--client-cpus", "4,5",
                        "--transports", "http", "--body-sizes", "16",
                        "--scenarios", "static-close", "--concurrency", "1", "32", "128",
                        "--duration", "5", "--repeats", "3"]

                def child_run(command, _log):
                    folder = Path(command[command.index("--output") + 1])
                    folder.mkdir()
                    rows = []
                    for concurrency in (1, 32, 128):
                        for engine, rps in (("nginx", 100), ("rut", 120)):
                            for rep in (1, 2, 3):
                                invalid = bad_sample and concurrency == 128 and engine == "rut" and rep == 1
                                rows.append(dict(
                                    workload="static", connection="close", transport="http",
                                    body_size=16, concurrency=concurrency, engine=engine,
                                    rep=rep, requests=500, rps=rps, seconds=5, valid=not invalid,
                                    errors=dict(connect=0, read=int(invalid), write=0, status=0, timeout=0),
                                    warmup_errors=dict(connect=0, read=0, write=0, status=0, timeout=0)))
                    run.save_json(folder / "results.json", rows)
                    if complete is not None:
                        run.save_json(folder / "status.json",
                                      {"complete": complete, "valid": not bad_sample})
                    return returncode

                previous_sigterm = signal.getsignal(signal.SIGTERM)
                try:
                    with mock.patch.object(sys, "argv", argv), \
                            mock.patch.object(matrix, "validate_cpu_topology"), \
                            mock.patch.object(matrix, "run_cell", side_effect=child_run), \
                            contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(matrix.main(), expected_exit)
                finally:
                    signal.signal(signal.SIGTERM, previous_sigterm)
                report = json.loads((output / "matrix.json").read_text())
                self.assertTrue(report["complete"])
                self.assertEqual(report["target_met"], all(expected))
                self.assertEqual([c["measurement_valid"] for c in report["cells"]], expected)
                self.assertEqual([c["target_met"] for c in report["cells"]], expected)
                self.assertTrue(all(c["exit_code"] == returncode for c in report["cells"]))

    def test_invalid_tls_certificate_retains_failed_status(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            cert = out / "invalid.pem"
            cert.write_text("not a PEM certificate\n")
            args = SimpleNamespace(output=out, tls_cert=cert)
            with mock.patch.object(run, "arguments", return_value=args), \
                    mock.patch.object(Harness, "prepare") as prepare, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(run.main(), 2)
            prepare.assert_not_called()
            status = json.loads((out / "status.json").read_text())
            self.assertFalse(status["complete"])
            self.assertFalse(status["valid"])
            self.assertIn("SSLError", status["error"])

    def test_static_body_bound_rejected_before_external_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            for scenario, size, rejected in (
                ("static-close", run.STATIC_BODY_LIMIT, False),
                ("static-keepalive", run.STATIC_BODY_LIMIT + 1, True),
                ("static-close", 1048576, True),
                ("static-close", None, False),
                ("proxy-close", 1048576, False),
            ):
                with self.subTest(scenario=scenario, size=size):
                    harness = Harness(SimpleNamespace(
                        output=Path(directory), scenarios=[scenario], body_size=size))
                    with mock.patch.object(harness, "command", side_effect=RuntimeError("external")) as command:
                        if rejected:
                            with self.assertRaisesRegex(ValueError, "this matrix cell has NOT passed"):
                                harness.prepare()
                            command.assert_not_called()
                        else:
                            with self.assertRaisesRegex(RuntimeError, "external"):
                                harness.prepare()
                            command.assert_called_once()

    def test_matrix_interrupt_allows_child_cleanup_once(self):
        tools_dir = Path(__file__).resolve().parent
        for group_signal in (True, False):
            with self.subTest(group_signal=group_signal), tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                child_script = out / "child.py"
                child_script.write_text(
                    "import os,signal,time\nfrom pathlib import Path\n"
                    "def interrupt(sig,frame):\n"
                    "    with Path('signals').open('a') as f: f.write(str(sig)+'\\n')\n"
                    "    raise KeyboardInterrupt\n"
                    "signal.signal(signal.SIGTERM,interrupt)\n"
                    "signal.signal(signal.SIGINT,interrupt)\n"
                    "Path('child.pid').write_text(str(os.getpid()))\n"
                    "try:\n"
                    "    Path('ready').touch()\n"
                    "    time.sleep(20)\n"
                    "except KeyboardInterrupt:\n"
                    "    Path('cleaning').touch()\n"
                    "    time.sleep(0.5)\n"
                    "    Path('cleaned').touch()\n"
                )
                parent_code = (
                    "import signal,sys\nfrom pathlib import Path\n"
                    f"sys.path.insert(0,{str(tools_dir)!r})\n"
                    "from matrix import run_cell\n"
                    "def interrupt(sig,frame): raise KeyboardInterrupt\n"
                    "signal.signal(signal.SIGTERM,interrupt)\n"
                    "try:\n"
                    "    with open('child.log','w') as log:\n"
                    "        run_cell([sys.executable,'child.py'],log)\n"
                    "except KeyboardInterrupt:\n"
                    "    Path('interrupted').touch()\n"
                )

                def wait_for(name, parent):
                    deadline = time.monotonic() + 5
                    while not (out / name).exists():
                        self.assertIsNone(parent.poll(), 'parent exited before ' + name)
                        self.assertLess(time.monotonic(), deadline, 'timed out waiting for ' + name)
                        time.sleep(0.01)

                with (out / "parent.log").open("w") as log:
                    parent = subprocess.Popen([sys.executable, "-c", parent_code],
                                              cwd=out, stdout=log, stderr=log,
                                              start_new_session=True)
                    try:
                        wait_for("ready", parent)
                        if group_signal:
                            os.killpg(parent.pid, signal.SIGINT)
                        else:
                            parent.terminate()
                        wait_for("cleaning", parent)
                        # A second terminal interruption must not interrupt the
                        # child's resource cleanup while the parent waits.
                        os.killpg(parent.pid, signal.SIGTERM)
                        self.assertEqual(parent.wait(timeout=5), 0)
                        self.assertTrue((out / "cleaned").exists())
                        self.assertTrue((out / "interrupted").exists())
                        self.assertEqual((out / "signals").read_text(), f"{signal.SIGTERM}\n")
                    finally:
                        if parent.poll() is None:
                            parent.kill()
                            parent.wait()
                        child_pid_file = out / "child.pid"
                        if child_pid_file.exists() and not (out / "cleaned").exists():
                            with contextlib.suppress(ProcessLookupError):
                                os.kill(int(child_pid_file.read_text()), signal.SIGKILL)

    def test_native_static_comparison_keeps_content_and_framing(self):
        nginx = (b"HTTP/1.1 200 OK\r\nServer: nginx\r\nDate: today\r\n"
                 b"Content-Length: 3\r\nContent-Type: text/plain; charset=utf-8\r\n"
                 b"Connection: keep-alive\r\n\r\nabc")
        rut = (b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n"
               b"Content-Type: text/plain; charset=utf-8\r\nConnection: keep-alive\r\n\r\nabc")
        canonical = run.canonical_native_static_response
        self.assertEqual(canonical(nginx), canonical(rut))
        for changed in (rut.replace(b"abc", b"abd"), rut.replace(b"keep-alive", b"close"),
                        rut.replace(b"Length: 3", b"Length: 4")):
            self.assertNotEqual(canonical(nginx), canonical(changed))
        with self.assertRaises(ValueError):
            canonical(rut.replace(b"text/plain", b"text/html"))

    def test_matrix_rejects_static_samples_from_a_different_profile(self):
        rows = [dict(workload="static", connection="close", transport="http",
                     body_size=65536, concurrency=32, engine=engine, rep=rep,
                     requests=600, rps=rps, seconds=5, valid=True,
                     errors=dict.fromkeys(run.ERROR_NAMES, 0),
                     warmup_errors=dict.fromkeys(run.ERROR_NAMES, 0))
                for engine, rps in (("nginx", 100), ("rut", 120)) for rep in (1, 2, 3)]
        def result():
            return assess(rows, "static-close", "http", 65536, 32, 3, 5, "native-body")
        self.assertFalse(result()["measurement_valid"])
        for row in rows:
            row["static_profile"] = "native-body"
        self.assertTrue(result()["target_met"])
        rows[0]["static_profile"] = "converter-return"
        self.assertFalse(result()["measurement_valid"])

    def test_preflight_comparison_budget_retains_multiple_requests(self):
        for size, count in ((0, 100), (16, 100), (1024, 100), (65536, 16), (1048576, 3)):
            self.assertEqual(run.preflight_request_count(size), count)

    def test_large_body_preflight_is_exact_and_bounded(self):
        size = 1048576
        head = f"HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n".encode()
        chunks = [head] + [b"x" * 4096] * (size // 4096)
        raw, closed = response(FakeSocket(chunks), "proxy", True, body_size=size)
        self.assertTrue(raw.endswith(b"x" * size))
        with self.assertRaises(ValueError):
            response_head(head)
        with self.assertRaises(ValueError):
            response(FakeSocket(chunks[:-1]), "proxy", True, body_size=size)
        with self.assertRaises(ValueError):
            response(FakeSocket([head, b"y" * size]), "proxy", True, body_size=size)

    def test_matrix_missing_wrong_shape_errors_and_smoke_never_pass(self):
        import copy
        rows = []
        for engine, rps in (("nginx", 100), ("rut", 120)):
            for rep in (1, 2, 3):
                rows.append(dict(workload="proxy", connection="close", transport="https",
                                 body_size=65536, concurrency=32, engine=engine, rep=rep,
                                 requests=500, rps=rps, seconds=5, valid=True,
                                 errors=dict(connect=0, read=0, write=0, status=0, timeout=0),
                                 warmup_errors=dict(connect=0, read=0, write=0, status=0, timeout=0)))
        def evaluate(data, duration=5):
            return assess(data, "proxy-close", "https", 65536, 32, 3, duration)
        self.assertTrue(evaluate(rows)["target_met"])
        self.assertFalse(evaluate(rows[:-1])["target_met"])
        self.assertFalse(evaluate(rows, duration=1)["target_met"])
        for key, value in (("body_size", 16), ("transport", "http"), ("rep", 99),
                           ("valid", False), ("errors", {"timeout": 1}), ("rps", 104.9)):
            bad = copy.deepcopy(rows)
            for row in bad:
                if row["engine"] == "rut":
                    row[key] = value
            self.assertFalse(evaluate(bad)["target_met"], key)
        for row in rows:
            if row["engine"] == "rut":
                row["rps"] = 105
        self.assertFalse(evaluate(rows)["target_met"])

    def test_matrix_requires_actual_measurement_duration(self):
        import copy
        rows = [dict(workload="static", connection="close", transport="http",
                     body_size=16, concurrency=1, engine=engine, rep=rep,
                     requests=500, rps=rps, seconds=5, valid=True,
                     errors=dict.fromkeys(run.ERROR_NAMES, 0),
                     warmup_errors=dict.fromkeys(run.ERROR_NAMES, 0))
                for engine, rps in (("nginx", 100), ("rut", 120)) for rep in (1, 2, 3)]
        self.assertTrue(assess(rows, "static-close", "http", 16, 1, 3, 5)["target_met"])
        for engine in ("nginx", "rut"):
            for seconds in (4.999, 0, -1, None, "5", True, float("nan"), float("inf")):
                with self.subTest(engine=engine, seconds=seconds):
                    bad = copy.deepcopy(rows)
                    next(r for r in bad if r["engine"] == engine)["seconds"] = seconds
                    result = assess(bad, "static-close", "http", 16, 1, 3, 10)
                    self.assertFalse(result["performance_eligible"])
                    self.assertFalse(result["target_met"])
                    if seconds == 4.999:
                        self.assertTrue(result["measurement_valid"])
        missing = copy.deepcopy(rows)
        del missing[0]["seconds"]
        self.assertFalse(assess(missing, "static-close", "http", 16, 1, 3, 10)["target_met"])

    def test_matrix_continues_after_bad_evidence(self):
        cases = (
            ("results.json", b"[", "truncated rows"),
            ("status.json", b"{", "truncated status"),
            ("results.json", b"\xff", "invalid UTF-8"),
            ("results.json", b"[" * 2000 + b"]" * 2000, "excessive JSON nesting"),
            ("results.json", b"{}", "rows object"),
            ("results.json", b"[null]", "non-object row"),
            ("results.json", b"[{}]", "missing fields"),
            ("status.json", b"[]", "status array"),
            ("status.json", b'{"complete": "true", "valid": true}', "non-boolean completion"),
            ("status.json", None, "missing status"),
            ("results.json", None, "missing rows"),
            ("results.json", b"DIRECTORY", "unreadable rows path"),
        )
        for filename, payload, label in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "matrix"
                argv = ["matrix.py", "--output", str(output),
                        "--tls-cert", "unused.pem", "--tls-key", "unused.key",
                        "--server-cpu", "2", "--origin-cpu", "3", "--client-cpus", "4,5",
                        "--transports", "http", "--body-sizes", "16", "32",
                        "--scenarios", "static-close", "--concurrency", "1",
                        "--duration", "5", "--repeats", "3"]

                def child_run(command, _log):
                    folder = Path(command[command.index("--output") + 1])
                    size = int(command[command.index("--body-size") + 1])
                    folder.mkdir()
                    rows = [dict(workload="static", connection="close", transport="http",
                                 body_size=size, concurrency=1, engine=engine, rep=rep,
                                 requests=500, rps=rps, seconds=5, valid=True,
                                 errors=dict.fromkeys(run.ERROR_NAMES, 0),
                                 warmup_errors=dict.fromkeys(run.ERROR_NAMES, 0))
                            for engine, rps in (("nginx", 100), ("rut", 120)) for rep in (1, 2, 3)]
                    run.save_json(folder / "results.json", rows)
                    run.save_json(folder / "status.json", {"complete": True, "valid": True})
                    if size == 16:
                        artifact = folder / filename
                        if payload is None:
                            artifact.unlink()
                        elif payload == b"DIRECTORY":
                            artifact.unlink()
                            artifact.mkdir()
                        else:
                            artifact.write_bytes(payload)
                    return 0

                previous_sigterm = signal.getsignal(signal.SIGTERM)
                try:
                    with mock.patch.object(sys, "argv", argv), \
                            mock.patch.object(matrix, "validate_cpu_topology"), \
                            mock.patch.object(matrix, "run_cell", side_effect=child_run) as child, \
                            contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(matrix.main(), 2)
                        self.assertEqual(child.call_count, 2)
                finally:
                    signal.signal(signal.SIGTERM, previous_sigterm)
                report = json.loads((output / "matrix.json").read_text())
                self.assertTrue(report["complete"])
                self.assertFalse(report["target_met"])
                first, second = report["cells"]
                self.assertFalse(first["measurement_valid"])
                self.assertFalse(first["target_met"])
                self.assertTrue(first["evidence_error"])
                self.assertTrue(second["measurement_valid"])
                self.assertTrue(second["target_met"])

    def test_keepalive_wire_profiles_preserve_original_and_default_persistence(self):
        explicit = request_bytes("proxy", False)
        self.assertIn(b"Connection: keep-alive\r\n", explicit)
        implicit = request_bytes("proxy", False, "implicit")
        self.assertEqual(implicit, b"GET /proxy HTTP/1.1\r\nHost: client.example\r\n\r\n")
        self.assertIsNone(connection_header(False, "implicit"))
        self.assertEqual(
            request_bytes("proxy", True, "implicit"),
            request_bytes("proxy", True, "explicit"),
        )

    def test_first_engine_option_and_alternating_repeat_order(self):
        parser = run.argparse.ArgumentParser()
        run.add_first_engine_argument(parser)
        self.assertEqual(parser.parse_args([]).first_engine, "nginx")
        self.assertEqual(parser.parse_args(["--first-engine", "rut"]).first_engine, "rut")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["--first-engine", "other"])

    def test_benchmark_engine_start_order_matches_recorded_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            for first_engine in ("nginx", "rut"):
                out = Path(directory) / first_engine
                out.mkdir()
                tools = {}
                for name in ("rut", "converter", "wrk"):
                    path = out / name
                    path.write_text("mock executable\n")
                    path.chmod(0o755)
                    tools[name] = path
                args = SimpleNamespace(
                    output=out,
                    rut=tools["rut"],
                    converter=tools["converter"],
                    wrk=tools["wrk"],
                    tls_cert=None,
                    tls_key=None,
                    body_size=None,
                    mode="benchmark",
                    server_cpu=2,
                    server_cpus="2",
                    workers=1,
                    origin_cpu=3,
                    client_cpus="4,5",
                    keepalive_header="implicit",
                    front_port=8087,
                    origin_port=9087,
                    concurrency=[1],
                    duration=1,
                    warmup=1,
                    repeats=4,
                    first_engine=first_engine,
                    scenarios=["proxy-close"],
                )
                harness = Harness(args)

                def fake_command(argv, timeout=20):
                    if argv == ["docker", "context", "inspect"]:
                        stdout = '[{"Endpoints":{"docker":{"Host":"unix:///mock.sock"}}}]'
                    elif argv[:2] == ["docker", "info"]:
                        stdout = "mock docker"
                    elif argv[:3] == ["docker", "image", "inspect"]:
                        stdout = '[{"Id":"mock-image"}]'
                    elif argv[0] == "git":
                        stdout = "" if "status" in argv else "mock-head"
                    elif argv == ["lscpu"]:
                        stdout = "mock cpu topology"
                    elif str(argv[0]) == str(tools["converter"]):
                        stdout = f"listen 127.0.0.1:{args.front_port}\nresponse_buffering: .completeContentLength\n"
                    else:
                        raise AssertionError(f"unexpected external command: {argv!r}")
                    return subprocess.CompletedProcess(argv, 0, stdout, "")

                with mock.patch.object(harness, "command", side_effect=fake_command):
                    harness.prepare()
                metadata = json.loads((out / "environment.json").read_text())

                started = []

                @contextlib.contextmanager
                def mock_frontend(engine, _work, _label):
                    started.append(engine)
                    yield 123

                harness.frontend = mock_frontend
                harness.validate = lambda *_args: None
                sample = {
                    "requests": 1,
                    "seconds": 1.0,
                    "rps": 1.0,
                    "p50_us": 1.0,
                    "p95_us": 1.0,
                    "p99_us": 1.0,
                    "errors": dict.fromkeys(run.ERROR_NAMES, 0),
                    "client_cpu_seconds": 0.0,
                }
                harness.wrk = lambda *_args: dict(sample)
                with mock.patch.object(run, "proc_usage", return_value=(0.0, 0)), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertTrue(harness.benchmark(456))

                metadata_order = metadata["engine_order_by_scenario_and_repeat"]
                self.assertEqual([entry["repeat"] for entry in metadata_order], [1, 2, 3, 4])
                self.assertEqual({entry["scenario"] for entry in metadata_order}, {"proxy-close"})
                expected = (
                    ["nginx", "rut", "rut", "nginx", "nginx", "rut", "rut", "nginx"]
                    if first_engine == "nginx"
                    else ["rut", "nginx", "nginx", "rut", "rut", "nginx", "nginx", "rut"]
                )
                self.assertEqual(started, expected)
                self.assertEqual(started, [engine for entry in metadata_order
                                           for engine in entry["engines"]])

    def test_fragmented_body_and_normal_close(self):
        sock = FakeSocket(
            [
                (
                    b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n"
                    b"Connection: close\r\nDate: today\r\n\r\nhello "
                ),
                b"from nginx",
                b"",
            ]
        )
        raw, closed = response(sock, "static", True)
        self.assertTrue(closed)
        self.assertIn(b"Date: NORMALIZED", raw)
        self.assertTrue(raw.endswith(expected_body("static")))

    def test_server_declared_close_even_when_client_requests_keepalive(self):
        length, closed = response_head(
            b"HTTP/1.1 200 OK\r\ncontent-length: 16\r\nconnection: Close"
        )
        self.assertEqual(length, 16)
        self.assertTrue(closed)

    def test_truncated_or_mismatched_responses_reject(self):
        for payload in (
            b"",
            b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nshort",
            b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nhello from nginxEXTRA",
        ):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                response(FakeSocket([payload]), "static", True)

    @staticmethod
    def sample(engine="rut", valid=True):
        return {
            "workload": "static",
            "connection": "close",
            "concurrency": 1,
            "engine": engine,
            "rep": 1,
            "valid": valid,
            "errors": {"read": 0},
            "warmup_errors": {"read": 0},
            "rps": 10,
            "p50_us": 1,
            "p95_us": 2,
            "p99_us": 3,
            "server_cpu_pct": 20,
            "origin_cpu_pct": 0,
            "server_rss_bytes": 100,
            "client_cpu_seconds": 1,
            "seconds": 2,
        }

    def test_invalid_nginx_is_not_published_as_valid_baseline(self):
        groups = aggregate([self.sample("nginx", False), self.sample()], 1, True)
        line = render(groups).splitlines()[6]
        self.assertIn("INVALID / INCOMPLETE", line)
        self.assertNotIn("1.00×", line)

    def test_partial_and_duplicate_repeats_do_not_get_capacity_ratio(self):
        for rows, repeats, complete in (
            ([self.sample()], 2, True),
            ([self.sample(), self.sample()], 2, True),
            ([self.sample()], 1, False),
        ):
            with self.subTest(rows=rows, complete=complete):
                self.assertFalse(
                    next(iter(aggregate(rows, repeats, complete).values()))["valid"]
                )

    def test_timeout_stops_wrapper_and_load_child(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            child_file = out / "child.pid"
            harness = Harness(SimpleNamespace(output=out))
            code = (
                "import subprocess,sys,time; from pathlib import Path; "
                "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                "Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(30)"
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                harness.command(
                    [sys.executable, "-c", code, str(child_file)], timeout=1
                )
            stat = Path(f"/proc/{int(child_file.read_text())}/stat")
            try:
                state = stat.read_text().rsplit(")", 1)[1].split()[0]
            except FileNotFoundError:
                pass  # Already reaped by init.
            else:
                self.assertEqual(state, "Z")
            self.assertTrue((out / "command-failure-1.log").exists())

    def test_valid_ratio_and_warmup_error_totals(self):
        nginx, rut = self.sample("nginx"), self.sample()
        self.assertIn("1.00×", render(aggregate([nginx, rut], 1, True)))
        rut.update(warmup_errors={"read": 7})
        group = aggregate([rut], 1, True)[("static", "close", 1, "rut")]
        self.assertFalse(group["valid"])
        self.assertEqual(group["warmup_errors"], 7)


if __name__ == "__main__":
    unittest.main()
