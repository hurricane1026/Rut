# http-short-local-response-v2-20261010

Single frontend CPU2, separate clients5/7, four pinned reuseport origins3/4/8/9. Frontends serial. Pure1KiB plaintext short connections. Proxy experiments use explicit request_policy ID1 and require actual upstream reuse across downstream closes. No response-size prediction. Local response is memory body in Rut versus cached static file/sendfile in nginx and is a diagnostic separation, not an identical filesystem test.

| Configuration | Engine | Samples | Median RPS | Median p99 ms | Valid | Timeouts |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1k-local | epoll | 3 | 45275 | 2.469 | 3/3 | 0 |
| 1k-local | nginx | 3 | 30632 | 7.912 | 3/3 | 0 |
| 1k-local | uring | 3 | 45299 | 2.479 | 3/3 | 0 |

Full raw evidence/configs/frozen binaries: `/home/hurricane/private/code/rut-performance-checkpoints/http-short-local-response-v2-20261010`.
Raw summary SHA256: `ab103146282f5fbcd90c575a45d7021843e5f65af362acc826fd4c58122846cd`.

No merge or default promotion. Study source/head/binary hashes and runner preserve precise configuration. The synchronous-request experiment was archived on study/http-sync-request-20261010 and removed from the active implementation after throughput and tail regressed. Exact scan controls show no consistent large improvement. At1024 concurrency nginx has75 timeouts, zero warmup errors: INVALID. Its8192 worker_connections limit does not by itself explain these timeouts; listener backlog and connection burst pressure remain unconfirmed possibilities. These are screening measurements rather than fully reproduced official cross-machine tests.
