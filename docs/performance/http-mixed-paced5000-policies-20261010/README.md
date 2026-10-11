# Mixed proxy load at planned 5,000 API RPS

Same serial, single frontend core and four pinned reuseport origins as the 1,000 RPS study. 96 bulk 1MiB connections, 32 small 4KiB connections; three rotated 12-second repeats after 3-second warmup. Study knobs remain opt-in. Validity requires exact planned, issued, completed, unissued, and unfinished request counts, finite client metrics, and zero measurement/warmup errors. Only two of nine cells meet those conditions; nginx has no complete cell, so no three-repeat medians or cross-configuration comparison are reported.

| Configuration | Complete observations | GiB/s | API service p99 ms |
| --- | ---: | ---: | ---: |
| current256 | 1 of 3 | 6.186 | 2.414 |
| latency256 | 1 of 3 | 5.664 | 1.065 |
| nginx | 0 of 3 | — | — |

Raw records and frozen binaries: `/home/hurricane/private/code/rut-performance-checkpoints/http-mixed-paced5000-policies-20261010`.
Raw summary SHA256: `ba0d49b1064e0f372cc9008b00649672ea3861ad229e2e2029902148d77c966e`.

Service latency starts at request transmission. Planned latency additionally includes scheduling/queued arrivals. One outstanding request per API connection; unissued plans are recorded. This local study does not establish an advantage across every workload.
