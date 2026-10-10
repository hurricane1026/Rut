# http-short-concurrency-screen-20261010

Single frontend CPU2, separate clients5/7, four pinned reuseport origins3/4/8/9. Frontends serial. Pure1KiB plaintext short connections. Proxy experiments use explicit request_policy ID1 and require actual upstream reuse across downstream closes. No response-size prediction. Local response is memory body in Rut versus cached static file/sendfile in nginx and is a diagnostic separation, not an identical filesystem test.

| Configuration | Engine | Samples | Median RPS | Median p99 ms | Valid | Timeouts |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| c1024 | epoll | 1 | 27741 | 39.307 | 1/1 | 0 |
| c1024 | nginx | 1 | 29709 | 818.249 | 0/1 | 75 |
| c1024 | uring | 1 | 17262 | 129.397 | 1/1 | 0 |
| c128 | epoll | 1 | 26371 | 10.286 | 1/1 | 0 |
| c128 | nginx | 1 | 26227 | 10.746 | 1/1 | 0 |
| c128 | uring | 1 | 18371 | 15.257 | 1/1 | 0 |
| c512 | epoll | 1 | 26265 | 26.322 | 1/1 | 0 |
| c512 | nginx | 1 | 26409 | 62.105 | 1/1 | 0 |
| c512 | uring | 1 | 17192 | 69.009 | 1/1 | 0 |

Full raw evidence/configs/frozen binaries: `/home/hurricane/private/code/rut-performance-checkpoints/http-short-concurrency-screen-20261010`.
Raw summary SHA256: `54bd2306223c9b09656d89a793ff6df18e1c3b9e9b57d6bfaad1cffdc71b85ce`.

No merge or default promotion. Study source/head/binary hashes and runner preserve precise configuration. The synchronous-request experiment was archived on study/http-sync-request-20261010 and removed from the active implementation after throughput and tail regressed. Exact scan controls show no consistent large improvement. At1024 concurrency nginx has75 timeouts, zero warmup errors: INVALID. Its8192 worker_connections limit does not by itself explain these timeouts; listener backlog and connection burst pressure remain unconfirmed possibilities. These are screening measurements rather than fully reproduced official cross-machine tests.
