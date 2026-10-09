# io_uring relay scheduling and nginx buffer study

This checkpoint preserves the measured 128KiB relay implementation and its
diagnostics. It does not add SEND_ZC, URL-size prediction, a performance-policy
CLI, or automatic per-route policies. Future ideas are recorded separately in
[future-policy-ideas.md](future-policy-ideas.md).

## Runtime change

After the initial response header/prefix send completes, an eligible plaintext
HTTP/1.1 Content-Length response can enter the existing guarded splice relay
without another serialized copy/send prefix. Ready body reads stay in a bounded
shard FIFO instead of submitting a readiness poll after every successful segment.
The backend submits and harvests without waiting when that FIFO is runnable;
actual EAGAIN still arms kernel readiness. Slot and upstream-episode checks
protect cancellation, connection reuse, and stale queue entries.

Each wait turn has at most 16 splice calls and 1MiB of read-plus-write work. Reads
reserve a corresponding write budget. Segment size is 128KiB; if enlarging a pipe
fails, a 64KiB pipe remains supported. Relay admission still depends on parsed
response state and the existing remaining-body threshold, not request history.

A bounded CQ peek authenticates currently armed body-read/body-write completions.
Ordinary, invalid, stale or error completions are treated conservatively. After
the first half of the call budget, relay work yields when ordinary work has been
observed pending for 80us during that flush. This observation is not a kernel CQE
timestamp or a request-latency guarantee.

Existing experiment diagnostics are retained: splice direction/backpressure,
readiness and runnable-queue waits, CQ/flush phase work, and approximately 1/64
sampled request phases. The latter uses 128 fixed slots per shard and adds no
Connection fields. The 4KiB filter uses parsed Content-Length and covers both
streamed and one-shot completion. `RUT_BENCH_RELAY_STATS=1` enables shutdown
reporting; counters and sampling currently remain active without that variable.
This is a measured checkpoint, including that instrumentation overhead.

## Results and limits

Linux 6.19.10, one frontend worker on CPU2; four origin workers on four physical
cores CPU3,4,8,9; wrk on CPU5,7. nginx 1.29.7 was pinned by image digest. Frontends
ran serially. HTTP plaintext, 128 persistent connections, 1MiB uncached file
responses. Origin sendfile remained at its default off. These are localhost
results, not a general backend ranking.

The nginx scan tested 11 configurations once, then rotated the two selected
candidates and Rut through three 15s measurements with 3s warmup:

| Frontend | Median RPS | Payload GiB/s | Median p99 ms |
| --- | ---: | ---: | ---: |
| nginx, buffering off, 512KiB read buffer | 3,963 | 3.870 | 33.379 |
| nginx, buffering off, 1MiB read buffer | 4,001 | 3.907 | 33.374 |
| Rut io_uring, 128KiB relay | 5,543 | 5.413 | 26.280 |

Rut throughput was about 39% higher in this setup. Both nginx candidates had one
200ms+ p99 run and two approximately 33ms runs; the intermittent tail remains
unexplained. The earlier nginx p99 median of 265ms is not a stable upper bound.
This scans buffers, not every nginx performance setting; screening candidates
once introduces noise and selection bias.

Small-only 4/16/64KiB loads were essentially unchanged, but 4KiB + 1MiB mixed
traffic regressed with two-core origins. Four-core origins and a two-core
multi_accept-off experiment improved small-request service. This is a material
limitation: upstream sharing and request mix must be considered. Fixed connection
counts are closed-loop loads; their actual request proportions differ when
completion rates change. Mixed large-response RPS alone is not pure capacity.

Full measurement JSON, configurations and environment metadata are in the
subdirectories. Old paths and build hashes in metadata identify the measured
artifacts; they are not required paths for the new scripts. A successful
response/reuse preflight and zero client errors are required for a valid row.

## Reproduce

Use the existing harness dependencies described in
[the benchmark README](../../../scripts/nginx_benchmark/README.md). Build Rut and
rut-compile together; an alternative binary must have its matching rut-compile
alongside it. Pin physical cores appropriate to the host. Run Docker as an
authorized user; do not add competing benchmark jobs.

```bash
python3 scripts/nginx_benchmark/relay_compare.py \
  --rut "$PWD/build/src/rut" \
  --converter "$PWD/build/src/rut-nginx-convert" --wrk /path/to/wrk \
  --engines uring,nginx --origin-workers 4 --origin-cpus 3,4,8,9 \
  --server-cpu 2 --client-cpus 5,7 --workers 1 \
  --front-port 8604 --origin-port 8704 \
  --body-size 1048576 --concurrency 128 --duration 15 --warmup 3 --repeats 3 \
  --keepalive-header implicit --proxy-profile native-streaming \
  --native-nginx-buffering off --native-origin-reuse on \
  --scenarios proxy-keepalive --output /tmp/relay-compare

python3 scripts/nginx_benchmark/nginx_buffer_scan.py \
  --output /tmp/nginx-buffer-scan \
  --rut "$PWD/build/src/rut" \
  --converter "$PWD/build/src/rut-nginx-convert" --wrk /path/to/wrk \
  --origin-workers 4 --origin-cpus 3,4,8,9 \
  --server-cpu 2 --client-cpus 5,7 --workers 1 \
  --front-port 8604 --origin-port 8704 \
  --body-size 1048576 --concurrency 128 --warmup 3 \
  --keepalive-header implicit --proxy-profile native-streaming \
  --native-nginx-buffering off --native-origin-reuse on \
  --scenarios proxy-keepalive
```

The comparison supports `--baseline-rut /path/to/rut --engines
uring,baseline-uring,nginx`, and `--engines epoll,uring,nginx` using one candidate
binary. For the plaintext mixed case, add `--mixed-small-bytes 4096
--small-connections 32 --mixed-client-cpus 7,5`; 128 total connections then split
into 96 large and 32 small. Mixed aggregate percentiles are the large client's
percentiles; use the separate `large_client` / `small_client` rows for latency.
The scanner fixes eight body buffers for buffering-on configurations and
disables temporary-file writes, without enabling a proxy cache. It writes each
effective nginx configuration before startup and validates every result.

Official configuration reference:
[nginx proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffering).
