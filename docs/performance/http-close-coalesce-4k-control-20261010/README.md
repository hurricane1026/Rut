# 4KiB complete close-response coalescing control

Single serial12-second sample after2-second warmup for each engine/configuration; same128 downstream connections, pinned frontend/origin/client cores as the1KiB confirmation. Existing explicit request_policy ID1; actual origin reuse and correct downstream close proved in preflight. All three rows and warmups have zero errors.

| Config | RPS | p99 ms |
| --- | ---: | ---: |
| io_uring off | 18,437 | 14.812 |
| io_uring on | 19,879 | 14.928 |
| nginx | 27,622 | 8.258 |

About7.8% throughput improvement, no tail improvement demonstrated. One sample is only a control, not a repeat-confirmed gain or general workload proof.

Full raw logs/configs/frozen binaries: /home/hurricane/private/code/rut-performance-checkpoints/http-close-coalesce-4k-control-20261010
Raw summary SHA256: `c1c52e798d9bba5f52628670f5de64b2cbc0ea85a1f0cca9dd928e6c25038d20`.
