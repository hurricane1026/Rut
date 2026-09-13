# Local baseline: 2026-09-13

This snapshot records the local experiment requested after #269 merged as
`44d3cb0162707bd837533bc079d23aa3dc73ffab`. It predates extraction of the
[portable harness](../../../scripts/nginx_benchmark/README.md); these are
historical measurements, not results produced by the new CLI.

RUT reused the Release/JIT build at `a283731e`. Production `src/`, `include/`,
root CMake and third_party were identical to the merged tree; executable
hashes, compiler version, CPU and pinned nginx image are in environment.json.
RUT: Release `-O2`, IPO OFF, JIT O2, io_uring, one shard. nginx: pinned 1.29.7,
one worker, host-network Docker. Intel i7-10700; server CPU 2, origin CPU 3,
client CPUs 4/5 on separate physical cores. No CPU reservation or frequency
lock. Host kernel is recorded. Access logs off, loopback HTTP/1.1, no TLS or
pipelining, upstream keepalive off. Native versus container execution remains
a methodological difference despite host networking.

The converter's actual stdout was executed for exact 16-byte `/static` return
and root proxy to a 1 KiB origin. Each frontend start validated 100 fresh
responses including EOF and complete Date-normalized wire equality; reused
connections additionally passed 100 responses. wrk had no per-response body
callback. Each level warmed up for 2 seconds then measured 8 seconds. Three
repeats alternated engine order; the frontend process persisted across
concurrency 1/32/128 within each repeat. Higher levels therefore include load
history, not independent cold starts.

## Findings

Medians of three zero-error measurement runs:

| Workload / connection | Concurrency | nginx req/s | RUT req/s | RUT/nginx | nginx p99 µs | RUT p99 µs |
|---|---:|---:|---:|---:|---:|---:|
| 16 B return / close | 1 | 14,223 | 14,179 | 1.00× | 41 | 50 |
| 16 B return / close | 32 | 44,298 | 24,828 | 0.56× | 647 | 2,803 |
| 16 B return / close | 128 | 44,574 | 28,181 | 0.63× | 2,418 | 10,244 |
| 1 KiB proxy / close | 1 | 7,654 | 4,226 | 0.55× | 137 | 288 |

nginx: all 36 measurement groups had zero errors. RUT: 24 of 36 groups had
read errors (4,153,468 total). All RUT keepalive groups and concurrency 32/128
proxy-close groups are invalid as error-free capacity comparisons. The raw
values in results.json/summary.csv are retained for diagnosis; they do not
establish capacity or request failure percentages. p99 values are medians of
per-run percentiles, not merged histograms. Short connections and underfilled
server CPU can reflect local client/kernel overhead rather than server limits.

The original script stopped on the first measured error, retained
benchmark-first-stop.log, then resumed unmeasured groups. Static keepalive
RUT repeat 1 at concurrency 32/128 consequently used a restarted frontend;
its failed concurrency-1 measurement was not overwritten. This exception is
part of the historical evidence. The extracted harness forbids resume and
records warmup errors in addition to measured errors; the historical JSON
only aggregates measured errors. It also records command and lifecycle status
more strictly. These differences must not be hidden when reproducing results.

## Independent diagnosis

A separate instrumented wrk observed `read()==0`, parser error 0, parser state
4 (`s_start_res`) in static keepalive: EOF while waiting for a response, not
HTTP parse rejection. `errno=115` printed in the historical log was stale
after a zero-byte read and is not a causal errno. The optional patch in the
portable tool prints errno only on negative reads.

The final independent 32-concurrency, 5-second asyncio test reported:

| Scenario | nginx complete responses | nginx errors | RUT complete responses | RUT errors |
|---|---:|---:|---:|---:|
| static keepalive | 144,475 | 0 | 119,656 | 0 |
| proxy close | 27,049 | 0 | 23,809 | 3,269 response-header EOFs |

That client verified complete bodies and respected response `Connection:
close`. Its first version ignored nginx's declared close at its request
limit; those false positives are retained in
`diagnostic-before-client-close-fix.log`, not claimed as nginx defects.
`diagnostic.log` contains the corrected comparison. Static keepalive was not
reproduced by the slower Python client. Root cause is not established, and
all errors are not presumed to share one cause.

`benchmark.log` retains the measured rows and first-stop/resume history;
results.json and summary.csv preserve all 72 measurements. Local workspace
paths in logs/metadata were replaced with placeholders; timings, counters
and hashes were not changed. Full original per-run files remain in the local
experiment directory. These findings do not change the compatibility matrix
or prove production performance. Fixing EOF behavior is separate from this
PR's tooling and evidence publication.
