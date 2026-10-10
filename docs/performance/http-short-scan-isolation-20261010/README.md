# http-short-scan-isolation-20261010

Single frontend CPU2, separate clients5/7, four pinned reuseport origins3/4/8/9. Frontends serial. Pure1KiB plaintext short connections. Proxy experiments use explicit request_policy ID1 and require actual upstream reuse across downstream closes. No response-size prediction. Local response is memory body in Rut versus cached static file/sendfile in nginx and is a diagnostic separation, not an identical filesystem test.

| Configuration | Engine | Samples | Median RPS | Median p99 ms | Valid | Timeouts |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| both | uring | 3 | 18056 | 15.951 | 3/3 | 0 |
| boundary | uring | 3 | 18939 | 15.468 | 3/3 | 0 |
| none | uring | 3 | 18407 | 14.688 | 3/3 | 0 |
| terminal | uring | 3 | 18919 | 15.194 | 3/3 | 0 |

Full raw evidence/configs/frozen binaries: `/home/hurricane/private/code/rut-performance-checkpoints/http-short-scan-isolation-20261010`.
Raw summary SHA256: `9a9dc49ea0da5cc5efc979b0a34d7223e1eedcfdfe5acbdc03d54d0d492d9120`.

No merge or default promotion. Study source/head/binary hashes and runner preserve precise configuration. The synchronous-request experiment was archived on study/http-sync-request-20261010 and removed from the active implementation after throughput and tail regressed. Exact scan controls show no consistent large improvement. At1024 concurrency nginx has75 timeouts, zero warmup errors: INVALID. Its8192 worker_connections limit does not by itself explain these timeouts; listener backlog and connection burst pressure remain unconfirmed possibilities. These are screening measurements rather than fully reproduced official cross-machine tests.
