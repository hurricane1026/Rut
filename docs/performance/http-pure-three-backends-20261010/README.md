# http-pure-three-backends-20261010

Local single-core plaintext native proxy. Four explicitly pinned reuseport origin workers. 128 downstream connections; 8 seconds after 2-second warmup, three rotated repeats. All frontends serial. These are screening measurements, not the nginx published 180-second cross-machine methodology. No default changes.

Transparent Rut forwards downstream Connection: close upstream; nginx strips it and reuses origin sockets. Short-connection results therefore include a persistence-policy difference and are not isolated backend comparisons. Exact preflight origin IDs are archived in raw logs.

| Campaign | Mode | Engine | Median RPS | Median p99 ms | Valid rows | Timeouts |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| 100k | close | epoll | 8205 | 16.074 | 3/3 | 0 |
| 100k | close | nginx | 11112 | 12.265 | 3/3 | 0 |
| 100k | close | uring | 10523 | 22.260 | 3/3 | 0 |
| 100k | keepalive | epoll | 20362 | 6.789 | 3/3 | 0 |
| 100k | keepalive | nginx | 12510 | 10.879 | 3/3 | 0 |
| 100k | keepalive | uring | 35154 | 904.650 | 0/3 | 339 |
| 10k | close | epoll | 12796 | 10.367 | 3/3 | 0 |
| 10k | close | nginx | 29530 | 4.804 | 3/3 | 0 |
| 10k | close | uring | 14357 | 15.777 | 3/3 | 0 |
| 10k | keepalive | epoll | 58907 | 2.399 | 3/3 | 0 |
| 10k | keepalive | nginx | 52619 | 2.671 | 3/3 | 0 |
| 10k | keepalive | uring | 82939 | 1.749 | 3/3 | 0 |
| 1k | close | epoll | 13139 | 10.132 | 3/3 | 0 |
| 1k | close | nginx | 27351 | 8.842 | 3/3 | 0 |
| 1k | close | uring | 14824 | 16.381 | 3/3 | 0 |
| 1k | keepalive | epoll | 68701 | 2.023 | 3/3 | 0 |
| 1k | keepalive | nginx | 62163 | 2.263 | 3/3 | 0 |
| 1k | keepalive | uring | 109960 | 1.297 | 3/3 | 0 |
| 1m | close | epoll | 3014 | 44.318 | 3/3 | 0 |
| 1m | close | nginx | 1737 | 75.829 | 3/3 | 0 |
| 1m | close | uring | 3880 | 48.163 | 3/3 | 0 |
| 1m | keepalive | epoll | 4265 | 32.490 | 3/3 | 0 |
| 1m | keepalive | nginx | 1554 | 104.719 | 3/3 | 0 |
| 1m | keepalive | uring | 7131 | 19.270 | 3/3 | 0 |
| 1m-nginx-tuned | close | nginx | 3674 | 38.810 | 3/3 | 0 |
| 1m-nginx-tuned | keepalive | nginx | 3955 | 37.365 | 3/3 | 0 |

100KiB io_uring persistent rows are INVALID and must not be used to claim throughput superiority. All three default-control repeats also time out: neither ring nor larger segments alone explain the failure. No root cause established yet.

Full logs/configs/frozen binaries: `/home/hurricane/private/code/rut-performance-checkpoints/http-pure-three-backends-20261010`.
Raw summary SHA256: `b100af94c252f72dcff61ad61e77a48341491568e8e910176d98fc5278b11a72`.

For isolation, default = current profile/128KiB/ring off/byte gate off; chunk256 = 256KiB/ring off/byte gate off; ring256 = 256KiB/ring on/byte gate off. The runner is authoritative for per-cell overrides. All controls preserve current CQ wait and turn budgets.
