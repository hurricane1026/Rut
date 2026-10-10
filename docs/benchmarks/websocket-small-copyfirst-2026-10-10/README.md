# WebSocket small-message copy-first experiment (2026-10-10)

This experiment applies only to opaque plaintext HTTP/1.1 WebSocket tunnels in the io_uring study build. It does not change ordinary HTTP, TLS, inspection, epoll, or the default runtime strategy.

## Mechanism

After upgrade handoff and existing I/O owners drain, reuse the connection buffers for an at-most-4096-byte nonblocking recv/send pair. A full actual read changes that direction to splice until read EAGAIN; there is no URL/history/frame-size prediction. A full copied prefix permits one additional bounded read/write pair (at most two extra syscalls per turn), avoiding a forced poll between prefix and remainder. Partial writes retain the buffer and use the existing episode-tagged readiness/cancel ledger. No new connection buffer or heap allocation is introduced.

The switch is `RUT_STUDY_WS_SPLICE=on RUT_STUDY_WS_COPY=on`; copy-first defaults off. Results below use 64KiB pipes and two calls per ordinary turn.

## Final frozen binary results

Identical patched tcpkali2 binary, full latency sampling, binary echo verification, 192 connections, three client threads on CPUs 5/6/7. One frontend worker on CPU 2, four origin workers on CPUs 3/4/8/9. Frontends run serially, rotate order, warm up 2s and measure 8s. nginx buffer512KiB (256KiB for 1MiB), proxy buffering off. Tests are closed-loop ping-pong; RTT includes client frame preparation.

| Payload | Engine | Copy first | Runs | Messages/s median (range) | MiB/s median | RTT p99 ms median |
|---|---|---|---:|---:|---:|---:|
| websocket-small-16384 | uring | off | 3 | 54708 (53680–56190) | 854.8 | 4.39 |
| websocket-small-16384 | uring | on | 3 | 53309 (52899–55155) | 833.0 | 4.38 |
| websocket-small-16384 | nginx | off | 3 | 42863 (42588–43223) | 669.7 | 4.72 |
| websocket-small-4096 | uring | off | 1 | 67911 (67911–67911) | 265.3 | 3.32 |
| websocket-small-4096 | uring | on | 1 | 68288 (68288–68288) | 266.8 | 3.04 |
| websocket-small-4096 | nginx | off | 1 | 65411 (65411–65411) | 255.5 | 3.53 |
| websocket-interactive-64 | uring | off | 3 | 76022 (74917–76618) | 4.6 | 3.35 |
| websocket-interactive-64 | uring | on | 3 | 83549 (82903–83841) | 5.1 | 3.03 |
| websocket-interactive-64 | nginx | off | 3 | 83537 (83430–84475) | 5.1 | 2.96 |
| websocket-bulk-64k | uring | off | 1 | 22139 (22139–22139) | 1383.7 | 9.87 |
| websocket-bulk-64k | uring | on | 1 | 21874 (21874–21874) | 1367.1 | 10.64 |
| websocket-bulk-64k | nginx | off | 1 | 17264 (17264–17264) | 1079.0 | 11.62 |
| websocket-bulk-1m | uring | off | 1 | 1040 (1040–1040) | 1039.6 | 224.90 |
| websocket-bulk-1m | uring | on | 1 | 1033 (1033–1033) | 1033.0 | 210.05 |
| websocket-bulk-1m | nginx | off | 1 | 916 (916–916) | 916.2 | 250.37 |

Final 64B: throughput +9.9%, p99 -9.4% versus the same binary with copy-first off. nginx and Rut rate ranges overlap; this establishes parity, not a stable nginx win.

16KiB: median throughput falls approximately 2.6%, while median p99 is approximately flat and individual tails vary. Keep this an explicit experiment, not a universal default. The final 4KiB/64KiB/1MiB measurements are single-run guards, not statistically confirmed gains; 64KiB final p99 rises about 7.8%. Bulk origin workers approach capacity, so these measurements do not establish an unlimited-origin throughput ceiling. All final cases reported zero errors and checked every echo.

## Earlier stages

The parent directory retains 27 three-repeat initial copy-first measurements and 8 size screens. Those use a different frozen binary without the extra prefix continuation pair and must not be pooled with final results. Initial 256B/1KiB screens improved roughly 10%; the 16KiB screen exposed a p99 regression that motivated the bounded continuation. The failed-build-mismatch directory records an unsuccessful startup before any timed measurement, caused by initially pairing a new runtime with the old compiler.

## Validation and provenance

Release runtime/compiler and native WebSocket regression target built successfully. CTest test_ws_tunnel_iouring and test_splice passed after the final change. Added cases cover 64B, exact4096 and4097 byte boundaries, buffered handoff, slow readers, full duplex, half-close reverse reply, and close with pending polls. Affected files passed clang-format22 and git diff whitespace checks. Targeted clang-tidy22 on the WebSocket test and experiment header reported no visible diagnostics. Full CI and sanitizer validation have not run for this experiment. Existing compile warnings in unrelated event-loop expressions remain.

Runtime SHA256: `aefe084463ad9323442b1cf60b6bb3ccb0fc900942d41531382145ab7d7f83ff`.
Compiler SHA256: `8223eeddbbed631257231726e9984adc015c1e91880ca13097a5605f6ece7952`.
Client SHA256: `8f9433dd9390a0805d9f6619472f16987258e5784980644386a9b847dfb0f3b4`.

Raw measurements, tcpkali2 CSV files, frontend/origin logs, runner scripts and frozen binaries are retained under this checkpoint directory.
