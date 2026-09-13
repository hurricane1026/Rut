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

Use `--duration 1 --warmup 1 --repeats 1 --concurrency 1 32` for a smoke test.
Select cases with `--scenarios static-close proxy-keepalive`. Ports default to
8087/9087; `--front-port` and `--origin-port` accept distinct free unprivileged
four-digit ports admitted by the converter. Output must be new or empty:
there is no resume that silently replaces warmed processes with fresh ones.

- `static`: exact route returning 16 bytes (`hello from nginx`), with a root
  proxy fallback required by the converter.
- `proxy`: root proxy to a separate nginx origin returning 1024 bytes.
- `close` / `keepalive`: downstream HTTP/1.1 connection behavior. Origin
  keepalive is disabled identically for both engines. No TLS or pipelining.
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
