# http-short-coalesced-close-20261010

Single frontend CPU2, separate clients5/7, four pinned reuseport origins3/4/8/9. Frontends serial. Pure1KiB plaintext short connections. Proxy experiments use explicit request_policy ID1 and require actual upstream reuse across downstream closes. No response-size prediction. Local response is memory body in Rut versus cached static file/sendfile in nginx and is a diagnostic separation, not an identical filesystem test.

| Configuration | Engine | Samples | Median RPS | Median p99 ms | Valid | Timeouts |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| epoll | epoll | 3 | 25090 | 11.509 | 3/3 | 0 |
| nginx | nginx | 3 | 27263 | 8.167 | 3/3 | 0 |
| off | uring | 3 | 18638 | 15.240 | 3/3 | 0 |
| on | uring | 3 | 21912 | 12.415 | 3/3 | 0 |

Full raw evidence/configs/frozen binaries: `/home/hurricane/private/code/rut-performance-checkpoints/http-short-coalesced-close-20261010`.
Raw summary SHA256: `0d101fac74a8be5bd0e2a7b5e1e0bbdc7f6fae9adb00389f476e839efd375d63`.

No merge or default promotion. Study source/head/binary hashes and runner preserve precise configuration. The synchronous-request experiment was archived on study/http-sync-request-20261010 and removed from the active implementation after throughput and tail regressed. Exact scan controls show no consistent large improvement. At1024 concurrency nginx has75 timeouts, zero warmup errors: INVALID. Its8192 worker_connections limit does not by itself explain these timeouts; listener backlog and connection burst pressure remain unconfirmed possibilities. These are screening measurements rather than fully reproduced official cross-machine tests.

## Mechanism and validation

Candidate9728207f; `RUT_STUDY_HTTP_COALESCE_CLOSE=on`, defaultoff. An explicit request-policy rewrite permits origin persistence with downstream close. The original response path serializes a new header, sends it, then sends the already-received body after header completion. The study appends only an exactly complete Content-Length body already in the current buffer to the existing response-header slice, if capacity permits, and uses the existing one-shot proxy completion callback. It does not wait for bytes or change upstream persistence/framing.

Admission requires the existing narrow plaintext bodyless GET/ID1/neutral response-policy domain,200/HTTP1.1 response, forced-close header rewrite, exact complete body and enough existing capacity; throttled traffic is excluded. Incomplete, surplus, larger-than-capacity, TLS, upgraded and other policy traffic retain their existing paths. Raw upstream bytes remain untouched; upstream_send_len records the full consumed raw response so the ordinary surplus/reuse fence still applies. Header/body memory remains connection-owned until the existing send/close completion ledger drains.

Three1KiB repetitions: off18,638 RPS/p9915.240ms; on21,912/p9912.415ms; epoll25,090/p9911.509ms; nginx27,263/p998.167ms. About17.6% throughput gain and18.5% lower p99; only0.80× nginx, not the1.5× goal.4KiB single control is separate evidence and gives only7.8% throughput gain without a measured p99 gain.

Regression tests check incomplete body, surplus body, throttle, insufficient capacity, exact coalesced bytes, preserved raw upstream bytes and completion accounting. Real benchmark preflights also exercise response framing, downstream closure, upstream origin-ID reuse and slow-read behavior. Native io_uring/CLI tests and46 tool tests pass; test_network/test_splice were rebuilt against the current headers and all four related CTests passed. Changed-file clang-format22 and diff check pass. Full sanitizer, GCC, macOS and remote CI not run.

Remaining gap: the coalesced io_uring path remains below matched epoll/nginx. Local-memory response screening alone cannot prove accept/close are cost-free or eliminate client/kernel bottlenecks, but it disproves an unconditional approximately18k io_uring short-connection ceiling. Synchronous upstream request send did not improve this proxy case. Concurrency screening128→512 did not increase io_uring throughput; at1024 nginx was invalid and must not be used as a performance denominator. No eBPF/perf attribution was collected in this round, so Nagle/ACK behavior and per-stage kernel cost have not been established.
