# nginx / Rut performance acceptance — 2026-09-23

**FAIL: 96/96 cells evaluated; 38 passed, 10 were below the throughput target,
and 48 had no valid comparison.** Elapsed time was **2,122.50 seconds
(35 minutes 22.50 seconds)**, matrix exit **2**, `complete: true`,
`target_met: false`. The matrix completed its evaluation; this does not mean
all requested measurements succeeded. No benchmark containers remained.

| Transport | Passed | Valid but below 1.10× | Invalid comparison | Total |
|---|---:|---:|---:|---:|
| HTTP | 14 | 10 | 24 | 48 |
| HTTPS | 24 | 0 | 24 | 48 |
| Total | 38 | 10 | 48 | 96 |

The full coordinate table is in [REPORT.md](REPORT.md); numeric values and
failure details are in [cells.csv](cells.csv). [acceptance.json](acceptance.json)
records the verdict, elapsed time and evidence archive SHA-256.
[verification.json](verification.json) records an independent recomputation
from the archived samples, coordinate coverage, and post-run hash checks.

## Acceptance requirements and findings

The requested scope was HTTP/HTTPS × static-close/static-keepalive/proxy-close/
proxy-keepalive × 16/1024/65536/1048576 bytes × concurrency 1/32/128.
Every cell must have at least three valid samples per engine, each measured
for at least 5 seconds, zero recorded warmup/measurement errors, completed
cleanup, and median Rut/nginx requests per second >= 1.10. Missing or unsupported
cells fail; no coordinates were removed and no acceptance thresholds relaxed.

This run used the default `acceptance` profile: 1-second warmup, 5-second
measurement and three repeats. Engine order was nginx/Rut, Rut/nginx,
nginx/Rut across the three repeats. Each frontend persists across ascending
concurrency levels within its repeat. The minimum recorded measurement duration
was 5.000121 seconds. Exactly 16 child runs completed with all 18 samples each
(288 samples); 16 child runs failed. Another 24 partial nginx samples from failed
proxy runs are retained, for 312 raw samples total. Partial samples do not
qualify failed cells for acceptance.

Failure categories:

- **24 static cells:** 64 KiB and 1 MiB exceed the converter's 4093-byte
  `local_response` bound. Setup rejected both connection modes and transports.
- **24 proxy cells:** 64 KiB and 1 MiB failed Rut response preflight with
  `EOF before response header`, after the first nginx load. This is a recorded
  symptom, not a demonstrated root cause. Two partial nginx samples also had
  timeout errors: HTTP 1 MiB proxy-close/c1 (one timeout), and HTTPS 1 MiB
  proxy-keepalive/c128 (two timeouts). None of these groups has a valid ratio.
- **10 valid HTTP cells below 1.10×:** static-close at both 16 B and 1 KiB,
  all three concurrency levels; static-keepalive at both sizes, concurrency 1;
  and 16 B proxy-close at concurrency 32/128. Their ratios span 0.966–1.092×.

All 24 HTTPS cells at 16 B and 1 KiB passed the configured throughput gate.
This does not establish a full-matrix pass or a latency improvement; raw
latency/CPU/RSS and per-group summary tables remain in the evidence archive.
No latency acceptance threshold was defined by this matrix.

## Source and measurement conditions

Both Rut and converter were freshly built from main
`601f144e13ae0d8d991c0c9f7fb0c831848f3b0a`, the latest main at setup time.
Harness commit: `ac01bee3f1a0587c6e6b7148cacfbf2c2a407ab8`.
The source tree was clean at measurement start, with no runtime/build-source
differences from that main commit. Build: clang 22.1.8, CMake/Ninja Release,
project `-O2 -DNDEBUG`, JIT ON, IPO OFF. Source/submodule revisions, runner and
executable hashes are in [provenance.json](provenance.json); build/configure logs
are retained. This supersedes the archived-binary smoke run as performance
acceptance evidence; that earlier quick result remains separately documented.

Host: Intel Core i7-10700, Linux; frontend CPU 2, nginx origin CPU 3, wrk CPUs
4 and 5, distinct physical cores. Rut used one shard and io_uring (including
TLS); nginx used one worker, pinned Docker image, host networking and disabled
access logging. No builds or tests ran during measurement. CPU frequency was
not locked and the machine was not exclusively reserved. These are local
acceptance results under those conditions, not confidence intervals or a
cross-machine guarantee.

Proxy profile was `converter-strict`, with origin connection reuse disabled.
Keepalive used implicit HTTP/1.1 persistence. Explicit `Connection: keep-alive`
and native-streaming are different workloads and were not evaluated here.
HTTPS used the same certificate on both frontends and the retained wrk
[TLS full-handshake patch](../../../scripts/nginx_benchmark/wrk-tls-full-handshake.patch): TLS 1.3,
TLS_AES_256_GCM_SHA384, X25519, no resumed reconnect handshakes. The archived wrk
executable was hash-verified; its source/build provenance is recorded.
The existing throwaway certificate remained valid throughout the run.

## Reproduction and evidence

Build the pinned source and submodules with the recorded configuration, then
substitute tool paths and a localhost certificate/key pair:

```sh
python3 scripts/nginx_benchmark/matrix.py --profile acceptance \
  --rut ./build/src/rut --converter ./build/src/rut-nginx-convert \
  --wrk /path/to/patched/wrk --output /tmp/nginx-acceptance \
  --server-cpu 2 --origin-cpu 3 --client-cpus 4,5 \
  --keepalive-header implicit --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem
```

[command.json](command.json) retains the actual invocation. Existing Docker
group membership was activated with `sg docker`. On the enforcing SELinux host,
the fresh empty matrix output and copied test certificate/key directory were
labeled `container_file_t` to permit read-only mounts. No host security setting
was disabled.

[evidence.tar.gz](evidence.tar.gz) contains the full matrix directory: all
commands, environment/status JSON, wrk output and CPU samples, generated configs
and Rut programs, server logs, and generated per-group summaries. It also
contains the exact harness sources, build logs, launcher and certificate.
Private key and executables are retained locally and are not embedded.
[matrix.json](matrix.json) is the unmodified runner verdict.

Validation: 22 benchmark-tool tests passed; fresh runtime/converter build passed;
all 96 coordinates were attempted. A maximum scheduled load budget of 57.6
minutes replaces the old 115.2 minutes. Actual elapsed time was shorter because
failed coordinates did not finish their measurement budget; it must not be
reported as a timed speedup of a successful full matrix.
