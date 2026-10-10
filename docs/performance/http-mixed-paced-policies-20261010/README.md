# http-mixed-paced-policies-20261010

Local Linux single frontend core study, four nginx origin workers. Frontends run serially. Runtime candidates remain opt-in; no default promotion.

Full raw logs, effective configurations and frozen binaries: `/home/hurricane/private/code/rut-performance-checkpoints/http-mixed-paced-policies-20261010`.
Raw summary SHA256: `e5ec5ed7a5aa0eeaa785dc25b5a7b32ecb4fb44130408e354bb7131056320bd2`.

Compact results retain errors and delivered request fractions. Saturated closed-loop mixed tests complete different proportions of small and large requests, so aggregate byte throughput alone is not a matched-workload comparison. Planned-rate tests report scheduling-inclusive latency separately from send-to-completion service latency. They use one outstanding request per small connection and expose unissued plans.

Only origin-pinned and paced studies explicitly pin independent reuseport origin workers. Results do not establish a universal 1.5× nginx advantage across workloads.

Three rotated repeats, 96 persistent 1MiB bulk connections plus 32 persistent 4KiB API connections at a planned total 1,000 RPS. 12 seconds measurement after 3 seconds warmup. Server CPU2, origins3/4/8/9, bulk clients5/7, API client6.

| Configuration | Median GiB/s | Ratio to nginx | Median API service p99 ms |
| --- | ---: | ---: | ---: |
| current, 256KiB | 6.640 | 1.81 | 2.953 |
| latency, 256KiB | 6.187 | 1.69 | 1.389 |
| balanced, 256KiB | 6.690 | 1.82 | 2.598 |
| throughput, 256KiB | 6.854 | 1.87 | 3.233 |
| nginx | 3.672 | 1.00 | 26.500 |

All medians and paired ratios exclude cells whose frozen raw planned, issued, completed, unissued, or unfinished counts are incomplete. Fourteen of fifteen cells have zero measurement/warmup errors, finite client metrics, and exact completion; throughput profile rotation2 delivered 11,999/12,000 and is marked invalid. All latency-profile repeats exceed 1.5× their same-rotation nginx result. These medians are local evidence, not confidence intervals. Service p99 starts at request transmission; planned-arrival p99 additionally includes client scheduling/queued arrival delay.
