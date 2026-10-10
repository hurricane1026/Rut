# Mixed proxy load at planned 5,000 API RPS

Same serial, single frontend core and four pinned reuseport origins as the 1,000 RPS study. 96 bulk 1MiB connections, 32 small 4KiB connections; three rotated 12-second repeats after 3-second warmup. All transport/warmup errors zero. Study knobs remain opt-in. nginx cannot deliver the planned API load; byte throughput ratios therefore do not represent matched completed workloads.

| Configuration | Median GiB/s | API service p99 ms | Planned delivery fraction |
| --- | ---: | ---: | ---: |
| current256 | 5.938 | 1.099 | 0.99995 |
| latency256 | 5.664 | 1.179 | 0.99998 |
| nginx | 3.696 | 27.282 | 0.26422 |

Raw records and frozen binaries: `/home/hurricane/private/code/rut-performance-checkpoints/http-mixed-paced5000-policies-20261010`.
Raw summary SHA256: `3ec8acc3c7aaf0eb1906020ca8f65d648f63c0ebbb3465ce1843b8910bed565c`.

Service latency starts at request transmission. Planned latency additionally includes scheduling/queued arrivals. One outstanding request per API connection; unissued plans are recorded. This local study does not establish an advantage across every workload.
