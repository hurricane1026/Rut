# HTTP exact empty terminal scan experiment

Candidate: `36e597b7`, based on PR #787 `726de9a5`. Opt-in
`RUT_STUDY_HTTP_TERMINAL_SCAN=on`; default remains off. The cached empty
state is invalidated by the real terminal publisher. Expiry, body pumping,
request-boundary admission and reclamation retain their existing behavior.

Serial HTTP/1 keep-alive proxy: one frontend CPU 2, four nginx origin workers
on CPUs 3,4,8,9, wrk CPUs 5,7, 128 connections, 2s warmup / 6s measurement.
All sizes use static origin bodies, including 4KiB: this is not an API-origin
benchmark. Frontends never overlap. No compilation during measurements.
Same frozen candidate binaries for on/off/epoll; hashes included.

Three on/off rotations (off/on, on/off, off/on):

| Body | Off median RPS | On median RPS | Off median p99 ms | On median p99 ms |
|---|---:|---:|---:|---:|
| 512 | 97926 | 104339 | 2.092 | 1.821 |
| 4096 | 95722 | 90913 | 1.846 | 2.147 |
| 1048576 | 5481 | 5537 | 27.083 | 26.619 |

512B improves in the median but off samples vary substantially. 4KiB
regresses; 1MiB differences are small with overlapping ranges. Do not promote
the flag to default or claim a universal win. All 30 timed rows and warmups
have zero reported connect/read/write/status/timeout errors. Shutdown logs
confirm skipped scans and no remaining terminal pending state.

The single-round nginx 1MiB p99 is 538.219ms, an unexplained outlier; do not
use it to claim a latency advantage. Repeat nginx before broad conclusions.

Validation: Release build; test_network, test_splice, test_cli_backend and
test_ws_tunnel_iouring passed, including a normal HTTP event test exercising
empty-cache invalidation by the real publisher. Full sanitizer/remote CI for
this experimental branch has not run.

Next: HTTP/1 boundary readiness is published through one helper, but recovery
still traverses all initialized slots. Investigate an exact ready-owner set
while preserving whole-CQ-batch ordering, cancellation, close and slot reuse.

Raw outputs, frontend logs, frozen binaries and standalone runners:
`/home/hurricane/private/code/rut-performance-checkpoints/http-terminal-scan-20261010`.
