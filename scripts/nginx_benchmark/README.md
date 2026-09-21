# Local nginx / RUT benchmark

Run real pinned nginx and converter-generated RUT against the same requests on
one physical core each, with separate cores for the client and origin. This is
an opt-in local experiment, not a performance CI gate or an expansion of the
nginx compatibility matrix. The harness does not modify production source.

## Requirements

- Linux, Python 3.11+, `taskset`, `lscpu`, GNU `/usr/bin/time`, Git.
- A local Docker daemon through a Unix socket; the image in
  `tests/pinned-nginx-image.txt` must already be present (`docker pull` that
  exact digest). No remote Docker, bridge/NAT, sudo, or privileged containers.
- Release/JIT `rut` and `rut-nginx-convert` executables. Record the source commit,
  build flags, compiler, and any source/binary equivalence separately; the
  harness records executable hashes but cannot infer which source built them.
- `wrk`. The original measurement used wg/wrk commit
  `a211dd5a7050b1f9e8a9870b95513060e72ac4a0`. Build with `make -j1
  WITH_OPENSSL=/usr` if using system OpenSSL development files; LuaJIT is built
  from wrk's bundled source. The harness neither downloads nor builds tools.
- Four available physical cores (the example uses 2, 3, 4, 5). The script rejects
  unavailable CPUs, overlapping assignments, and SMT siblings. It does not
  reserve these cores against other programs or lock CPU frequency.

## Run

From the repository root, substitute actual executable paths and CPU IDs:

```sh
python3 scripts/nginx_benchmark/run.py \
  --rut ./build/src/rut --converter ./build/src/rut-nginx-convert \
  --wrk /path/to/wrk --output /tmp/nginx-rut-benchmark \
  --server-cpu 2 --origin-cpu 3 --client-cpus 4,5
python3 scripts/nginx_benchmark/summarize.py /tmp/nginx-rut-benchmark
```

Default: four scenarios, concurrency 1/32/128, 2-second warmup and 8-second
measurement, three repeats, alternating nginx/RUT order. Each repeat starts
one frontend per engine, then runs all concurrency levels in order on that
same process. Higher levels include the earlier load history; this is not a
cold-start-per-level capacity measurement. JIT startup is outside timing.

The default `--keepalive-header explicit` preserves #644's original wire shape
(`Connection: keep-alive`). The bounded converter proxy currently rejects that
request shape, so the full default run can fail its proxy keepalive preflight.
Use `--keepalive-header implicit` to test HTTP/1.1 default persistence with no
Connection header. Preflight, wrk and the independent client all use the chosen
shape, which is recorded in `environment.json`. Close cases always send
`Connection: close`. Passing the implicit profile does **not** establish support
for explicit keep-alive, nor erase the original failed results.

`--proxy-profile native-streaming` selects the public native Rut DSL for the
bounded 256 KiB `GET /proxy` keepalive workload. It requires exactly
`--keepalive-header implicit --scenarios proxy-keepalive`; choose a nonempty
subset of `--concurrency 1 32` (other levels are rejected);
HTTP is the default, and the same run can use the existing `--tls-cert` /
`--tls-key` TLS listener. This profile has no converter strict-response or
request-deadline policy, so its measurements are recorded separately from the
default `converter-strict` profile. Both frontends use a 60-second origin idle
timeout and origin connection reuse; nginx has a 4096-entry idle upstream pool
and streams responses with buffering disabled. Nginx's 16 KiB response header
buffer is paired with a 16 KiB busy-buffer limit to satisfy its buffer
configuration constraints; response buffering remains off and cannot spill to
temporary files. Rut uses the native
`upstream` / `forward` DSL and its per-shard 4096-connection idle pool.

The native preflight first delays reading a complete 256 KiB response, then
reads a successor response on that same downstream socket. It saves the exact
response bytes and a read timing trace; this checks response integrity across a
slow reader without claiming to prove an internal high/low water mark. It then
sends 100 sequential requests on that socket and checks status, one exact
Content-Length, one `application/octet-stream` Content-Type, keepalive
semantics, no Transfer-Encoding, and every byte of a deterministic payload with
distinct blocks. Separate marker values identify the slow-read and 100-request
stages. The shared origin conditionally logs those markers with `$connection`
and `$connection_requests`; the runner requires each stage to use one origin
connection with a continuous request counter and retains the raw log. wrk does
not send the marker, so the origin performs no access-log writes during
throughput timing. This validates actual origin reuse instead of inferring it
from pool settings. Nginx origin, upstream idle pool, and downstream connection
allow up to 1,000,000,000 requests before recycling; the value is recorded in
`environment.json`.

Use `--duration 1 --warmup 1 --repeats 1 --concurrency 1 32` for a smoke test.
Select cases with `--scenarios static-close proxy-keepalive`. Ports default to
8087/9087; `--front-port` and `--origin-port` accept distinct free unprivileged
four-digit ports admitted by the converter. Output must be new or empty:
there is no resume that silently replaces warmed processes with fresh ones.

- `static`: exact route returning 16 bytes (`hello from nginx`), with a root
  proxy fallback required by the converter.
- `proxy`: root proxy to a separate nginx origin returning 1024 bytes.
- `close` / `keepalive`: downstream HTTP/1.1 connection behavior. Origin
  keepalive is disabled identically for both engines. Default transport is HTTP; no pipelining.
- nginx: one worker, Docker host network, access logging off. RUT: one shard,
  `--no-pin` with outer `taskset`, JIT O2, automatic I/O backend. Check the
  retained startup log for the actual backend (io_uring in the original run).

Every startup validates 100 complete responses, exact content and
Date-normalized wire equality against the other engine. Short connections must
reach EOF; keepalive cases additionally validate 100 responses on one socket.
Under wrk load there is no per-response Lua body callback; socket and status
errors are recorded without adding that client overhead.

Exit **0** means every selected measurement and warmup was nonempty and error
free; **1** means the matrix completed but contains failed/empty groups;
**2** means setup, response validation, interruption, or cleanup failed. Failed
measurements remain in JSON/logs while subsequent measurements continue.
`status.json` is written only after cleanup has been attempted. SIGINT/SIGTERM
unwind owned frontend/origin resources; forced process termination or an
unreachable Docker daemon can still require manual removal using the recorded
container IDs in `commands.json`. No existing named containers are removed.

`results.json`, per-run wrk output/Lua/CPU files, generated configurations and
RUT stdout, binary hashes, command records, and server logs are retained.
`REPORT.md` masks invalid/incomplete groups; `summary.csv` retains their raw
values with an explicit `valid` column. A p99 summary is the median of each
run's p99, not a pooled histogram. Socket errors are not application failure
percentages. CPU 100% denotes one logical CPU; summed parent/child RSS can
count shared nginx pages twice and includes RUT's resident compiler/JIT.

## Independent EOF diagnosis

```sh
python3 scripts/nginx_benchmark/run.py --mode diagnose \
  --rut ./build/src/rut --converter ./build/src/rut-nginx-convert \
  --wrk /path/to/wrk --output /tmp/nginx-rut-diagnose \
  --server-cpu 2 --origin-cpu 3 --client-cpus 4,5 \
  --scenarios static-keepalive proxy-close --concurrency 32 \
  --warmup 3 --duration 5
```

Each fresh frontend receives a wrk burst, then an independent asyncio client
checks complete HTTP responses for the requested duration, without pipelining.
It honors server-declared `Connection: close` even when requesting keepalive.
Counts and bounded exception examples are in `diagnostics.json`; this client
is for correctness, not a Python throughput comparison. It may fail to
reproduce timing-sensitive failures visible with the faster wrk client.

For first-read-error observations, apply `wrk-read-diagnostic.patch` to a
**separate checkout** of the pinned wrk source, rebuild, and pass that binary
via `--wrk` in a separate diagnosis run. It records EOF/read/parser state and
up to 300 response bytes for the first eight errors per thread. Do not replace
the baseline wrk binary mid-experiment or treat diagnostic throughput as the
original measurement. The original log's errno after `read()==0` was stale,
not an error cause; the patch prints errno only for negative read results.

## Harness checks and historical evidence

```sh
python3 -m unittest discover -s scripts/nginx_benchmark -p 'test_*.py' -v
```

The checks cover truncated/incorrect responses, explicit connection close,
invalid baselines, missing/duplicate repeats, warmup-error accounting, and
stopping wrapper/load children on command timeout. The dedicated CI workflow
runs these checks without generating benchmark traffic. Extraction checks and
retained runtime failures are recorded in [VALIDATION.md](VALIDATION.md).

[The 2026-09-13 snapshot](../../docs/benchmarks/nginx-2026-09-13/README.md)
preserves the original local findings. It was measured before this portable
harness was extracted; the original numbers are not a rerun of this PR.
EOF root-cause fixes and performance optimization are separate work.


## TLS and response-size matrix

`--body-size N` requests exactly N `x` bytes, up to 1 MiB. Without it, the
original static/proxy payloads remain unchanged. Configurable proxy payloads
are served from a read-only file mount by the origin. ETag, range advertisement
and Last-Modified are disabled identically at that shared origin to preserve
the controlled response-header shape; this is not a range/caching-header test. Static converter
`local_response` currently supports at most 4093 bytes: larger static cases
fail explicitly and do not count as passed. Established io_uring TLS supports
exact local responses; strict proxy TLS and larger-body cells still require
separate capability validation.

HTTPS uses `--tls-cert cert.pem --tls-key key.pem`. Generate a throwaway RSA
certificate with `openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj
/CN=localhost -addext subjectAltName=DNS:localhost -keyout key.pem -out cert.pem`.
Both frontends use the same certificate. The Python preflight verifies it and
requires TLS 1.3 / TLS_AES_256_GCM_SHA384. Build the pinned wrk source with
`wrk-tls-full-handshake.patch`, using the same OpenSSL and LuaJIT build options
as the original client. The patch fixes protocol/cipher and X25519 key exchange, clears sessions on
reconnect and rejects any resumed handshake. The harness rejects an HTTPS
measurement lacking the patch's capability marker. Retain the client patch,
build log and binary hash; a label alone is not external provenance proof.

Short connections use full TLS handshakes; keepalive reuses established TLS
connections. Ticket/resumption performance is a separate, unmeasured profile.
TLS listener setup uses Rut's existing CLI: raw converter output is preserved
as `.converted.rut`, its cleartext listener line is removed in the runnable
file, and CLI port/certificate/key configure TLS. Both TLS frontends bind the
same wildcard IPv4 port. This tests Rut TLS runtime performance, **not** TLS
converter compatibility. Original HTTP output stays unmodified.

`matrix.py` accepts the same binary/CPU arguments as `run.py`, plus required
`--tls-cert` / `--tls-key`. Defaults are all four scenarios, HTTP and HTTPS,
16 B / 1 KiB / 64 KiB / 1 MiB, and concurrency 1 / 32 / 128: 96 cells. Each
case has isolated retained evidence. Failed setup, unsupported capabilities,
missing repetitions and response errors leave their cells unpassed. A completed
child run with exit 1 preserves valid sibling-concurrency measurements while
rejecting the groups with bad samples. Other nonzero exits or missing/incomplete
`status.json` completion evidence invalidate every group from that child. Unreadable
or malformed JSON and invalid sample shapes are recorded as `evidence_error` for
that coordinate; later coordinates still run. It keeps
running other cases to expose the complete gap. `matrix.json` records exact
coordinates, commands, median ratios and validity. The overall target requires
every cell to reach Rut/nginx >= 1.10; both the requested duration and every
sample's measured `seconds` must be at least 5, with at least three repeats.
Short but otherwise valid measurements remain visible without qualifying for
performance acceptance. Exit 2 includes
valid measurements below target, not only execution errors. An interrupted
matrix remains incomplete. This is a local goal check, not a performance CI gate.
