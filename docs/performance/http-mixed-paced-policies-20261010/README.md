# http-mixed-paced-policies-20261010

Local Linux single frontend core study, four nginx origin workers. Frontends run serially. Runtime candidates remain opt-in; no default promotion.

Full raw logs, effective configurations and frozen binaries: `/home/hurricane/private/code/rut-performance-checkpoints/http-mixed-paced-policies-20261010`.
Raw summary SHA256: `2228b63928b002605e5e0a1ff1848ad133f4bd31866551d8838f41436aaa2151`.

Compact results retain errors and delivered request fractions. Saturated closed-loop mixed tests complete different proportions of small and large requests, so aggregate byte throughput alone is not a matched-workload comparison. Planned-rate tests report scheduling-inclusive latency separately from send-to-completion service latency. They use one outstanding request per small connection and expose unissued plans.

Only origin-pinned and paced studies explicitly pin independent reuseport origin workers. Results do not establish a universal 1.5× nginx advantage across workloads.

Three rotated repeats, 96 persistent 1MiB bulk connections plus 32 persistent 4KiB API connections at a planned total 1,000 RPS. 12 seconds measurement after 3 seconds warmup. Server CPU2, origins3/4/8/9, bulk clients5/7, API client6.

| Configuration | Median GiB/s | Ratio to nginx | Median API service p99 ms |
| --- | ---: | ---: | ---: |
| current, 256KiB | 6.640 | 1.81 | 2.953 |
| latency, 256KiB | 6.187 | 1.69 | 1.389 |
| balanced, 256KiB | 6.690 | 1.82 | 2.598 |
| throughput, 256KiB | 6.760 | 1.84 | 3.026 |
| nginx | 3.672 | 1.00 | 26.500 |

All latency-profile repeats exceed 1.5× their same-rotation nginx result. All transport and warmup error counters are zero. Throughput profile rotation2 delivers 11,999/12,000 planned API requests; every other cell delivers all 12,000. These medians are local evidence, not confidence intervals. Service p99 starts at request transmission; planned-arrival p99 additionally includes client scheduling/queued arrival delay.
